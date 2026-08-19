package admin

// ── R56: admin plain-mode server must refuse TLS ──────────────────
// Pre-R56, tls_test.go asserted `srv.TLSConfig == nil` after starting a
// plain server. That field is written asynchronously by net/http's
// internal HTTP/2 auto-configuration — Go 1.25's Server.Serve calls
// setupHTTP2_Serve, which runs http2.ConfigureServer (x/net v0.53.0
// server.go:267: `if s.TLSConfig == nil { s.TLSConfig = new(tls.Config) }`)
// — so the assertion raced the server goroutine and flakily failed
// `go test -race` with a DATA RACE and a spurious "TLSConfig not nil"
// failure (observed 2026-08-20 on the 8-package race run; the race
// window is narrow, so isolated runs pass and the R48–R55 "race clean
// on admin" claims were timing luck).
//
// The real security property — a plain-mode admin server must not serve
// TLS — is asserted behaviorally here: a TLS handshake to the plain
// server must FAIL. (The internal TLSConfig write is net/http's own
// documented behavior — Go's comment cites Issue 15908 — and never
// changes what the plain listener serves; the pre-R56 read of the field
// was testing stdlib internals, not firewall behavior.)

import (
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"
)

// startPlainAdminServer starts the admin API in plain mode on a reserved
// loopback port and returns the server plus its real address.
// (StartServer's returned *http.Server keeps Addr=":0" — the bound
// address is not reflected back — so the port is reserved first.)
func startPlainAdminServer(t *testing.T) (*http.Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	srv := newTestAPI(t).StartServer(addr)
	if srv == nil {
		t.Fatal("StartServer returned nil")
	}
	waitForListener(t, addr)
	return srv, addr
}

// waitForListener blocks until the given address accepts TCP connections.
// StartServer (and StartServerTLS's empty-cert fallback) start the
// listener inside the server goroutine and return before it binds, so
// callers must wait before issuing requests — a direct request can be
// refused if it lands before net.Listen runs.
func waitForListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start listening at %s within 3s: %v", addr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAttack_AdminPlainServerRefusesTLSHandshake(t *testing.T) {
	srv, addr := startPlainAdminServer(t)
	defer srv.Close()

	// Sanity: plain HTTP works over the returned address.
	resp, err := http.Get("http://" + addr + "/admin/health")
	if err != nil {
		t.Fatalf("plain HTTP request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	// The security property: a plain server must refuse TLS. net/http's
	// HTTP/2 auto-config may internally set srv.TLSConfig (the pre-R56
	// test's racy read), but the LISTENER is plain — a TLS ClientHello
	// must never complete a handshake.
	d := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err == nil {
		conn.Close()
		t.Error("plain-mode admin server completed a TLS handshake — unexpectedly serving TLS")
	}
}
