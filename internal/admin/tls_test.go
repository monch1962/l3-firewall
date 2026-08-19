package admin

import (
	"crypto/tls"
	"net"
	"net/http"
	"testing"
)

func TestStartServerTLS(t *testing.T) {
	api := newTestAPI(t)
	srv, addr, err := api.StartServerTLS(":0", "testdata/server.crt", "testdata/server.key")
	if err != nil {
		t.Fatalf("StartServerTLS: %v", err)
	}
	defer srv.Close()

	if addr == "" || addr == ":0" {
		t.Fatalf("expected real listening address, got %q", addr)
	}
	// TLS is handled at the listener level when using StartServerTLS.
	// Verify by making a TLS connection.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get("https://" + addr + "/admin/health")
	if err != nil {
		t.Fatalf("TLS connection failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestStartServerPlain(t *testing.T) {
	// NOTE (R56): pre-R56 this asserted `srv.TLSConfig == nil`. That field
	// is written asynchronously by net/http's internal HTTP/2
	// auto-configuration (http2.ConfigureServer — `if s.TLSConfig == nil {
	// s.TLSConfig = new(tls.Config)}`, x/net v0.53.0 server.go:267 — runs
	// from Server.Serve on every server, plain or TLS), so the read raced
	// the server goroutine and flakily failed `go test -race` with a DATA
	// RACE plus a spurious "TLSConfig not nil" failure. The property is
	// verified behaviorally instead: plain HTTP must work, and
	// TestAttack_AdminPlainServerRefusesTLSHandshake asserts the
	// TLS-refusal side (the field itself is stdlib-internal, not firewall
	// behavior).
	srv, addr := startPlainAdminServer(t)
	defer srv.Close()

	resp, err := http.Get("http://" + addr + "/admin/health")
	if err != nil {
		t.Fatalf("plain HTTP request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestStartServerTLSWithEmptyPaths(t *testing.T) {
	// StartServerTLS with empty cert paths falls back to plain HTTP.
	// The fallback branch returns srv.Addr (the requested address), so
	// reserve a real port to verify plain HTTP end-to-end (same R56
	// race note as TestStartServerPlain — no TLSConfig field reads).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	api := newTestAPI(t)
	srv, gotAddr, err := api.StartServerTLS(addr, "", "")
	if err != nil {
		t.Fatalf("StartServerTLS: %v", err)
	}
	defer srv.Close()
	if gotAddr == "" {
		t.Fatal("expected non-empty address")
	}
	// The fallback branch starts the listener inside the server goroutine
	// (StartServer → ListenAndServe), so wait for it to bind.
	waitForListener(t, gotAddr)

	// The fallback must serve plain HTTP (not TLS).
	resp, err := http.Get("http://" + gotAddr + "/admin/health")
	if err != nil {
		t.Fatalf("plain HTTP request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (empty-cert fallback must serve plain HTTP)", resp.StatusCode)
	}
}

func TestHealthEndpointOverTLS(t *testing.T) {
	api := newTestAPI(t)
	srv, addr, err := api.StartServerTLS(":0", "testdata/server.crt", "testdata/server.key")
	if err != nil {
		t.Fatalf("StartServerTLS: %v", err)
	}
	defer srv.Close()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get("https://" + addr + "/admin/health")
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}
