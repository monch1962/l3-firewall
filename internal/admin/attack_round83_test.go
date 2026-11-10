// Red-team security hardening Round 83 — admin TLS transport downgrade.
//
// `StartServerTLS` is the only TLS entry point of the control plane. When the
// caller supplies a certificate pair, the operator has explicitly asked for an
// encrypted admin API. The pre-R83 code treated a certificate that FAILED TO
// LOAD exactly like "TLS was never requested": it logged one line and fell
// through to `StartServer`, which serves the SAME routes (including the
// full-write `POST /admin/policy/reload`) over cleartext on the caller's
// address — and returned a NIL error, so the caller has no signal at all.
//
// Threat: the standing R42/R45/R62/R70 threat model is an attacker with write
// access to a configured path. A planted/removed/expired certificate turns the
// next start into a silent cleartext admin API on every interface:
//
//   - a passive observer on the network captures the bearer token, which is
//     full write access (replay it as POST /admin/policy/reload: policy
//     control of the running firewall), and
//   - a MITM can inject/alter responses on top of the same channel.
//
// A supervisor (systemd, compose, k8s) cannot detect the downgrade because the
// error is nil and the only signal is a log line. A transport control that a
// misconfiguration silently removes is not a control — the fail-open doctrine
// already applied to undecidable OPA input (R78) and uninspectable packets
// (R40.3/R49).
//
// R83 FIX: when cert AND key paths are both supplied, a load failure is an
// ERROR and NO listener is started. The empty-paths case ("TLS not requested")
// keeps its documented plain-HTTP fallback.
package admin

import (
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ── R83.1: missing cert/key pair must fail, not downgrade ───────────────
// TLS was explicitly requested; an unloadable pair must surface as an error
// and must not leave a plaintext listener behind.
func TestAttack_TLSConfigFailureMustNotDowngradeToPlaintext(t *testing.T) {
	api := newTestAPI(t)

	srv, addr, err := api.StartServerTLS("127.0.0.1:0",
		filepath.Join("testdata", "missing.crt"),
		filepath.Join("testdata", "missing.key"))
	if err == nil {
		if srv != nil {
			srv.Close()
		}
		t.Fatalf("StartServerTLS() with an unloadable cert/key pair returned err=nil (addr=%q): "+
			"TLS was configured but the admin API silently comes up in CLEARTEXT and the caller cannot detect it", addr)
	}
	if srv != nil {
		srv.Close()
		t.Error("StartServerTLS() returned a running server alongside an error: no listener may be started on a TLS configuration failure")
	}
}

// ── R83.2: present-but-corrupt key material must fail, not downgrade ────
// The realistic failure after a botched rotation: both files exist (so a
// naive "does the file exist" check passes) but they do not form a pair.
func TestAttack_TLSCorruptKeyMaterialMustNotDowngrade(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	// Copy the real certificate but pair it with a file that is NOT a key.
	certBytes, err := os.ReadFile(filepath.Join("testdata", "server.crt"))
	if err != nil {
		t.Fatalf("reading test cert: %v", err)
	}
	if err := os.WriteFile(certPath, certBytes, 0o600); err != nil {
		t.Fatalf("writing cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}

	api := newTestAPI(t)
	srv, addr, err := api.StartServerTLS("127.0.0.1:0", certPath, keyPath)
	if err == nil {
		if srv != nil {
			srv.Close()
		}
		t.Fatalf("StartServerTLS() with a mismatched cert/key pair returned err=nil (addr=%q): cleartext downgrade", addr)
	}
	if srv != nil {
		srv.Close()
		t.Error("StartServerTLS() returned a server despite unloadable key material")
	}
}

// ── R83.3: a successfully configured TLS pair still serves TLS ──────────
// Regression guard: the fix must not break the working path.
func TestAttack_TLSHealthyPairStillServesTLS(t *testing.T) {
	api := newTestAPI(t)
	srv, addr, err := api.StartServerTLS("127.0.0.1:0",
		filepath.Join("testdata", "server.crt"),
		filepath.Join("testdata", "server.key"))
	if err != nil {
		t.Fatalf("StartServerTLS() with a valid pair: %v", err)
	}
	defer srv.Close()
	if addr == "" {
		t.Fatal("StartServerTLS returned an empty address")
	}

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test cert
	}}
	defer client.CloseIdleConnections()
	resp, err := client.Get("https://" + addr + "/admin/health")
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	// A cleartext request to a TLS listener must not be served the admin
	// document: Go's http server answers a plaintext request on a TLS
	// listener with 400 ("Client sent an HTTP request to an HTTPS server"),
	// which proves the listener is genuinely speaking TLS rather than
	// accidentally serving plaintext.
	plain := &http.Client{Timeout: 2 * time.Second}
	if presp, perr := plain.Get("http://" + addr + "/admin/health"); perr == nil {
		presp.Body.Close()
		if presp.StatusCode == http.StatusOK {
			t.Errorf("cleartext GET against a TLS listener returned 200: admin API is serving plaintext")
		}
	}
}

// ── R83.4: "TLS not requested" (empty paths) keeps its plain fallback ───
// Documented behaviour, pinned so the R83 fix does not over-reach: an empty
// pair means the operator did not ask for TLS at all.
func TestAttack_TLSNotRequestedFallsBackExplicitly(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	api := newTestAPI(t)
	srv, gotAddr, err := api.StartServerTLS(addr, "", "")
	if err != nil {
		t.Fatalf("StartServerTLS(\"\", \"\") must keep the documented plain fallback, got error: %v", err)
	}
	if srv == nil {
		t.Fatal("StartServerTLS returned nil server")
	}
	defer srv.Close()
	waitForListener(t, gotAddr)

	resp, err := http.Get("http://" + gotAddr + "/admin/health")
	if err != nil {
		t.Fatalf("plain HTTP request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}
