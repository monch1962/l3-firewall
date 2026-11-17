// Red-team security hardening Round 87 — the admin control plane's transport.
//
// The admin API is a CONTROL PLANE: POST /admin/policy/reload replaces the
// policy the firewall enforces. Before R87 the shipped binary had no way to
// serve it over TLS at all — internal/admin has had StartServerTLS since R56
// and the R83 round made it fail closed, but cmd/server declared no
// --admin-tls-cert/--admin-tls-key flag, so the function was unreachable from
// the binary and every deployment served the control plane as plain HTTP. The
// README has carried that as a documented finding since R84 with the note that
// it is "now a safe two-flag addition because StartServerTLS fails closed".
// This round closes it.
//
// Impact of the pre-R87 state: `Authorization: Bearer <--admin-token>` and the
// whole policy document travel in cleartext. A passive on-path observer
// (shared switch, mirror port, wifi, a compromised router) recovers the token
// and then has full control-plane write access from anywhere the listener is
// reachable; an active MITM can rewrite the response to any admin read. The
// R84 Host allowlist does not help — it is a DNS-rebinding guard, not
// encryption — and neither does `--admin-allowed-hosts`.
package main

import (
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/monch1962/l3-firewall/internal/admin"
	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/engine"
	"github.com/monch1962/l3-firewall/internal/ratelimit"
)

// ── R87.1: the binary must be able to serve the admin API over TLS ───────
// A control plane that cannot be encrypted is not a configuration choice, it
// is a missing capability: the operator's bearer token has no safe transport.
func TestAttack_BinaryCanServeAdminAPIOverTLS(t *testing.T) {
	src, err := os.ReadFile(mainSourcePath)
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	code := string(src)

	for _, flagDecl := range []string{`flag.String("admin-tls-cert"`, `flag.String("admin-tls-key"`} {
		if !strings.Contains(code, flagDecl) {
			t.Errorf("main.go does not declare %s — the admin API has no TLS transport, so --admin-token and the policy document cross the network in cleartext (R87)", flagDecl)
		}
	}
	if !strings.Contains(code, "StartServerTLS(") {
		t.Error("main.go never calls StartServerTLS: internal/admin has the fail-closed TLS constructor but the shipped binary cannot reach it (R87)")
	}
	// The TLS path must pass the flag VALUES, not literals: a StartServerTLS
	// call with hardcoded/empty paths would be the R40.4 silently-dropped
	// control again.
	if !strings.Contains(code, "resolveAdminTLS(") {
		t.Error("main.go does not validate the admin TLS flag pair through resolveAdminTLS — one-of-two flags must be a startup error, never a silent plaintext downgrade (R87)")
	}
}

// ── R87.1b: a half-configured TLS pair must fail closed ──────────────────
// StartServerTLS's empty-empty fallback (pinned by R83) means a deployment
// whose secret mount silently produced an empty --admin-tls-cert= would serve
// PLAINTEXT while the operator believes TLS is on. The binary must therefore
// treat "exactly one of cert/key set" as a startup error, and must treat
// "neither set" as an explicit, operator-visible plaintext mode rather than an
// accident.
func TestAttack_AdminTLSHalfPairIsFatal(t *testing.T) {
	cases := []struct {
		name    string
		cert    string
		key     string
		wantTLS bool
		wantErr bool
	}{
		{"both empty — plaintext mode", "", "", false, false},
		{"both set — TLS mode", "/etc/tls/tls.crt", "/etc/tls/tls.key", true, false},
		{"cert without key — must refuse", "/etc/tls/tls.crt", "", false, true},
		{"key without cert — must refuse", "", "/etc/tls/tls.key", false, true},
		{"whitespace-only cert with key — must refuse", "   ", "/etc/tls/tls.key", false, true},
		{"cert with whitespace-only key — must refuse", "/etc/tls/tls.crt", "\t", false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cert, key, useTLS, err := resolveAdminTLS(c.cert, c.key)
			if (err != nil) != c.wantErr {
				t.Fatalf("resolveAdminTLS(%q,%q) err = %v, wantErr %v", c.cert, c.key, err, c.wantErr)
			}
			if c.wantErr {
				if cert != "" || key != "" {
					t.Errorf("refused pair still returned paths (cert=%q key=%q)", cert, key)
				}
				if !strings.Contains(err.Error(), "refusing") && !strings.Contains(err.Error(), "both") {
					t.Errorf("error does not explain the refusal: %v", err)
				}
				return
			}
			if useTLS != c.wantTLS {
				t.Errorf("useTLS = %v, want %v", useTLS, c.wantTLS)
			}
			if useTLS && (cert == "" || key == "") {
				t.Errorf("TLS mode returned an empty path (cert=%q key=%q)", cert, key)
			}
		})
	}
}

// ── R87.2d: the binary must not log raw credential URLs ──────────────────
// The alerting finding (R87.2) is fixed in internal/alert, but the binary's
// own startup lines printed the same secrets. A fix in the package that is
// bypassed by the entrypoint's own logging is the R40.4 dropped-control class,
// so the wiring is pinned here.
func TestAttack_StartupLogsDoNotPrintRawCredentialURLs(t *testing.T) {
	src, err := os.ReadFile(mainSourcePath)
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	code := string(src)

	for _, raw := range []string{"*alertWebhookURL", "*threatIntelURL"} {
		if strings.Contains(code, `"webhook", `+raw+`)`) || strings.Contains(code, `"urls", `+raw+`)`) {
			t.Errorf("main.go logs %s verbatim: a webhook/feed URL is a bearer credential and must go through redact.URL (R87)", raw)
		}
	}
	if !strings.Contains(code, "redact.URL(*alertWebhookURL)") {
		t.Error("main.go does not redact the alert webhook URL at startup (R87)")
	}
	if !strings.Contains(code, "redact.URLs(*threatIntelURL)") {
		t.Error("main.go does not redact the threat-intel feed URLs at startup (R87)")
	}
	if !strings.Contains(code, "redact.ScrubIn(") {
		t.Error("main.go does not scrub the URL out of error text — net/http repeats the request URL inside err.Error(), so the credential leaks through the error attribute (R87)")
	}
}

// ── R87.1d: the wired path really serves an encrypted control plane ──────
// Source pinning proves the flags exist; this proves the CONSTRUCTOR CHAIN the
// binary now uses actually terminates TLS. It exercises resolveAdminTLS →
// StartServerTLS exactly as main() does, against the admin package's test
// certificate, and asserts the negative too: a plaintext request to that
// listener must not receive an HTTP response.
func TestAttack_AdminTLSPathServesEncryptedControlPlane(t *testing.T) {
	// R91: the TLS key-material reader now rejects ".." components on the RAW
	// path, exactly like every other credential reader (readPolicyFile,
	// geoip.NewReader, persist.LoadState, audit.openAuditFile) — the guard has
	// to see the raw string the kernel will resolve, and filepath.Dir/Clean
	// would consume the component first. So the fixture path is resolved here
	// rather than spelled with "..".
	certPath, err := filepath.Abs("../../internal/admin/testdata/server.crt")
	if err != nil {
		t.Fatalf("resolving fixture path: %v", err)
	}
	keyPath, err := filepath.Abs("../../internal/admin/testdata/server.key")
	if err != nil {
		t.Fatalf("resolving fixture path: %v", err)
	}
	cert, key, useTLS, err := resolveAdminTLS(certPath, keyPath)
	if err != nil || !useTLS {
		t.Fatalf("resolveAdminTLS refused a valid pair: useTLS=%v err=%v", useTLS, err)
	}

	api := admin.New(nil,
		engine.New(nil, conntrack.NewTable(conntrack.Config{}), ratelimit.NewLimiter(0, 0),
			false, false, nil, nil, nil, nil, nil, "", nil),
		"r87-test", "", "")
	srv, addr, err := api.StartServerTLS("127.0.0.1:0", cert, key)
	if err != nil {
		t.Fatalf("StartServerTLS: %v", err)
	}
	defer srv.Close()

	// TLS client that trusts the self-signed test certificate.
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // test cert
	}
	resp, err := client.Get("https://" + addr + "/admin/health")
	if err != nil {
		t.Fatalf("HTTPS request to the wired listener failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("HTTPS /admin/health returned %d, want 200", resp.StatusCode)
	}

	// Same address, plaintext must not be served (no silent downgrade).
	plain := &http.Client{Timeout: 3 * time.Second}
	if pResp, pErr := plain.Get("http://" + addr + "/admin/health"); pErr == nil {
		_ = pResp.Body.Close()
		if pResp.StatusCode == http.StatusOK {
			t.Error("the TLS listener answered a PLAINTEXT request with 200 — the control plane is readable in cleartext (R87)")
		}
	}
}

// ── R87.1c: a token over plaintext must be visible in the log ────────────
// Plaintext mode stays supported (many deployments front the admin API with a
// TLS-terminating proxy or an unix-socket-only sidecar), but it must be LOUD
// when a bearer token is configured, because that is the case where the
// credential actually escapes. A silent plaintext listener plus a token is the
// R40.4 "control that is not what the deployment says it is" class.
func TestAttack_PlaintextTokenDeploymentIsLoudNotSilent(t *testing.T) {
	src, err := os.ReadFile(mainSourcePath)
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	code := string(src)

	// The warning must name the condition (cleartext token) and the fix
	// (the TLS flags), otherwise an operator cannot act on it.
	lower := strings.ToLower(code)
	if !strings.Contains(lower, "cleartext") {
		t.Error("main.go has no cleartext warning: a --admin-token deployment over plain HTTP logs nothing about the exposed credential (R87)")
	}
	if !strings.Contains(code, "admin-tls-cert") || !strings.Contains(code, "admin-tls-key") {
		t.Error("the plaintext warning does not point at the TLS flags, so it is not actionable (R87)")
	}
}
