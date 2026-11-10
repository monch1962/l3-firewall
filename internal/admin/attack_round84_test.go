// Red-team security hardening Round 84 — control-plane DNS rebinding.
//
// The admin API is reachable by design on a routable address
// (`--admin-listen` defaults to ":8082", and the README's own
// `docker run -p 8082:8082` publishes it), and it is UNAUTHENTICATED by
// default (`--admin-token` defaults to ""). It also sets no Host/Origin
// check at all.
//
// That combination is the classic DNS-rebinding exposure: a malicious web
// page served from `evil.example` re-resolves its own hostname to the
// firewall's address, so the victim's browser issues SAME-ORIGIN requests
// to `http://evil.example:8082/...`. `X-Frame-Options: DENY` stops framing
// but not `fetch()`; `Same-Origin-Policy` does not apply because, after the
// rebind, the origin and target are the same host:port. The page can then
// read `/admin/stats`, `/admin/blocks` and `/admin/block-stats` (internal
// IPs, ports, block reasons — network reconnaissance from an ordinary
// workstation) and POST `/admin/policy/reload`.
//
// The request's Host header still carries the ATTACKER's hostname
// (`evil.example`) — the browser never rewrites it — so a transport-layer
// Host allowlist defeats the attack while leaving every legitimate access
// path intact: IP-literal hosts (`127.0.0.1:8082`, a container/pod IP),
// `localhost`, and any operator-configured DNS name.
//
// R84 FIX: StartServer and StartServerTLS install a Host guard. IP literals,
// `localhost`/`*.localhost`, the host part of the listen address and any
// `--admin-allowed-hosts` entry are accepted; anything else is refused with
// 403 before the route runs. Handler() is unchanged, so embedding callers
// see their existing behaviour.
package admin

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// startGuardedAdminServer starts a plain admin server on loopback with the
// given extra allowed hosts and returns it with its address.
func startGuardedAdminServer(t *testing.T, allowed ...string) (*API, *http.Server, string) {
	t.Helper()
	// StartServer keeps Addr as given (it does not reflect the bound
	// address back), so reserve a loopback port first — same pattern as
	// startPlainAdminServer (R56).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	api := newTestAPI(t)
	if len(allowed) > 0 {
		api = api.WithAllowedHosts(allowed...)
	}
	srv := api.StartServer(addr)
	if srv == nil {
		t.Fatal("StartServer returned nil")
	}
	t.Cleanup(func() { srv.Close() })
	waitForListener(t, addr)
	return api, srv, addr
}

// doWithHost issues a request with an explicit Host header (what a
// DNS-rebound browser sends) and returns the status code.
func doWithHost(t *testing.T, client *http.Client, url, host, method string, body io.Reader) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Host = host
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request to %s with Host %q failed: %v", url, host, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, string(b)
}

// ── R84.1: a rebound DNS hostname must not read admin state ──────────────
// The attacker page's origin is its own hostname; after rebinding, the
// Host header is still that hostname. Every read endpoint is
// unauthenticated by default, so without a Host check the response is
// readable cross-origin-rebound.
func TestAttack_DNSRebindingReadBlocked(t *testing.T) {
	_, _, addr := startGuardedAdminServer(t)
	client := &http.Client{Timeout: 3 * time.Second}

	for _, path := range []string{"/admin/health", "/admin/stats", "/admin/blocks", "/admin/block-stats", "/admin/policy/versions"} {
		hostile := "evil.example:" + portOf(t, addr)
		code, body := doWithHost(t, client, "http://"+addr+path, hostile, http.MethodGet, nil)
		if code != http.StatusForbidden {
			t.Errorf("GET %s with rebound Host %q returned %d, want 403: a malicious page can read the admin API cross-origin (body=%q)",
				path, hostile, code, truncate(body))
			continue
		}
		if strings.Contains(body, `"status":"ok"`) || strings.Contains(body, "packets_processed") {
			t.Errorf("GET %s with rebound Host %q returned 403 but leaked the admin document: %q", path, hostile, truncate(body))
		}
	}
}

// ── R84.2: a rebound hostname must not trigger the write endpoint ────────
// Auth is DISABLED by default (no token configured), so pre-fix the write
// route ran for any caller. A rebound page could therefore POST reloads.
func TestAttack_DNSRebindingWriteBlocked(t *testing.T) {
	_, _, addr := startGuardedAdminServer(t)
	client := &http.Client{Timeout: 3 * time.Second}

	hostile := "evil.example:" + portOf(t, addr)
	code, body := doWithHost(t, client, "http://"+addr+"/admin/policy/reload", hostile, http.MethodPost, nil)
	if code != http.StatusForbidden {
		t.Errorf("POST /admin/policy/reload with rebound Host %q returned %d, want 403 (body=%q)", hostile, code, truncate(body))
	}
}

// ── R84.3: legitimate access paths must keep working ─────────────────────
// The guard must not break the documented ways to reach the admin API:
// an IP literal (container/pod IP or 127.0.0.1), localhost, or the IPv6
// loopback literal.
func TestAttack_LegitimateHostsStillAllowed(t *testing.T) {
	_, _, addr := startGuardedAdminServer(t)
	client := &http.Client{Timeout: 3 * time.Second}
	port := portOf(t, addr)

	for _, host := range []string{
		addr, // 127.0.0.1:port — the resolved listener address
		"127.0.0.1:" + port,
		"localhost:" + port,
		"LOCALHOST:" + port, // case-insensitive
		"[::1]:" + port,     // IPv6 loopback literal
	} {
		code, body := doWithHost(t, client, "http://"+addr+"/admin/health", host, http.MethodGet, nil)
		if code != http.StatusOK {
			t.Errorf("GET /admin/health with legitimate Host %q returned %d, want 200 (body=%q)", host, code, truncate(body))
		}
	}
}

// ── R84.4: hostname-confusion shapes must all be refused ─────────────────
// A naive suffix/prefix check is bypassable; these are the shapes that
// defeat one. Each must be rejected.
func TestAttack_HostAllowlistBypassShapesRejected(t *testing.T) {
	_, _, addr := startGuardedAdminServer(t)
	client := &http.Client{Timeout: 3 * time.Second}
	port := portOf(t, addr)

	hostile := []string{
		"evil.example:" + port,
		"evil.example.:" + port,          // trailing-dot FQDN
		"localhost.attacker.com:" + port, // not a .localhost suffix
		"evil.localhost.attacker.com:" + port,
		"127.0.0.1.evil.example:" + port, // looks like an IP prefix, is a name
		"localhost-attacker:" + port,     // no separator
		"evil-example:" + port,           // userinfo-ish confusion
		"admin.internal.evil.example:" + port,
	}
	for _, host := range hostile {
		code, body := doWithHost(t, client, "http://"+addr+"/admin/health", host, http.MethodGet, nil)
		if code != http.StatusForbidden {
			t.Errorf("GET /admin/health with hostile Host %q returned %d, want 403 (body=%q)", host, code, truncate(body))
		}
	}
}

// ── R84.5: an operator-configured DNS name is honoured ───────────────────
func TestAttack_AllowlistedReverseProxyHostAllowed(t *testing.T) {
	_, _, addr := startGuardedAdminServer(t, "admin.internal")
	client := &http.Client{Timeout: 3 * time.Second}

	for _, host := range []string{
		"admin.internal:" + portOf(t, addr),
		"ADMIN.INTERNAL:" + portOf(t, addr),  // case-insensitive
		"admin.internal.:" + portOf(t, addr), // trailing dot
	} {
		code, body := doWithHost(t, client, "http://"+addr+"/admin/health", host, http.MethodGet, nil)
		if code != http.StatusOK {
			t.Errorf("GET /admin/health with allowlisted Host %q returned %d, want 200 (body=%q)", host, code, truncate(body))
		}
	}
	// The allowlist is exact-match: a lookalike must still fail.
	code, _ := doWithHost(t, client, "http://"+addr+"/admin/health", "admin.internal.evil.example:"+portOf(t, addr), http.MethodGet, nil)
	if code != http.StatusForbidden {
		t.Errorf("lookalike of an allowlisted host returned %d, want 403", code)
	}
}

// ── R84.6: the TLS server installs the same guard ────────────────────────
func TestAttack_TLSServerAlsoGuardsHost(t *testing.T) {
	api := newTestAPI(t)
	srv, addr, err := api.StartServerTLS("127.0.0.1:0", "testdata/server.crt", "testdata/server.key")
	if err != nil {
		t.Fatalf("StartServerTLS: %v", err)
	}
	defer srv.Close()

	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	defer client.CloseIdleConnections()

	hostile := "evil.example:" + portOf(t, addr)
	code, body := doWithHost(t, client, "https://"+addr+"/admin/health", hostile, http.MethodGet, nil)
	if code != http.StatusForbidden {
		t.Errorf("TLS GET /admin/health with rebound Host %q returned %d, want 403 (body=%q)", hostile, code, truncate(body))
	}

	// Legitimate IP-literal access over TLS still works.
	code, body = doWithHost(t, client, "https://"+addr+"/admin/health", addr, http.MethodGet, nil)
	if code != http.StatusOK {
		t.Errorf("TLS GET /admin/health with Host %q returned %d, want 200 (body=%q)", addr, code, truncate(body))
	}
}

// ── R84.7: Host-predicate parsing-confusion shapes ───────────────────────
// A direct client can send Host values a browser never would. These must
// all be rejected by the predicate itself, independent of the transport.
func TestAttack_HostPredicateRejectsParsingConfusion(t *testing.T) {
	api := newTestAPI(t).WithAllowedHosts("admin.internal")

	bad := []string{
		"admin.internal:8082@evil.example", // SplitHostPort would yield admin.internal
		"admin.internal@evil.example",
		"admin.internal/evil.example",
		"admin.internal?x=1",
		"admin.internal#frag",
		"admin.internal:80:90",            // too many colons
		"admin\u200b.internal",            // zero-width space
		"admin\u2010internal",             // hyphen homoglyph (U+2010)
		"admin.internal\x00.evil.example", // NUL
		"",                                // no Host at all (HTTP/1.0)
	}
	for _, h := range bad {
		if api.hostAllowed(h, nil) {
			t.Errorf("hostAllowed(%q) = true; a parsing-confusion/no-Host value must be refused", h)
		}
	}

	good := []string{
		"admin.internal", "admin.internal:8082", "ADMIN.INTERNAL.", "Admin.Internal:443",
		"127.0.0.1:8082", "[::1]:8082", "localhost:8082", "app.localhost:8082",
	}
	for _, h := range good {
		if !api.hostAllowed(h, nil) {
			t.Errorf("hostAllowed(%q) = false; a legitimate IP/localhost/allowlisted host must be accepted", h)
		}
	}
}

// ── helpers ──────────────────────────────────────────────────────────────

func portOf(t *testing.T, addr string) string {
	t.Helper()
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		t.Fatalf("address %q has no port", addr)
	}
	return addr[i+1:]
}

func truncate(s string) string {
	if len(s) > 160 {
		return s[:160] + "…"
	}
	return s
}
