// Red-team security hardening Round 44 — metrics HTTP server timeout parity.
//
// The admin server (internal/admin newServer) sets all four timeouts
// (ReadHeaderTimeout, ReadTimeout, WriteTimeout, IdleTimeout), but the metrics
// server constructed inline in main() only sets ReadHeaderTimeout and
// IdleTimeout. Missing ReadTimeout leaves the request-body phase unbounded and
// missing WriteTimeout lets a slow-reading scrape client hold a connection
// (and its goroutine) open with no deadline — the monitoring endpoint is the
// only listener with a weaker posture than admin (R9 missing-timeout class).
//
// R44 FIX: extract newMetricsServer(addr) helper mirroring admin's newServer
// with all four timeouts, wired into main().
package main

import (
	"testing"
	"time"
)

// ── R44.5: metrics server must carry the same timeout posture as admin ─
// All four timeouts must be set; a zero ReadTimeout/WriteTimeout opens the
// metrics endpoint to slow-client connection hold.
func TestAttack_MetricsServerTimeoutParity(t *testing.T) {
	srv := newMetricsServer("127.0.0.1:0")
	if srv == nil {
		t.Fatal("newMetricsServer returned nil")
	}
	if srv.ReadHeaderTimeout <= 0 {
		t.Error("metrics server missing ReadHeaderTimeout (slow-header window)")
	}
	if srv.ReadTimeout <= 0 {
		t.Error("metrics server missing ReadTimeout (unbounded request-body phase)")
	}
	if srv.WriteTimeout <= 0 {
		t.Error("metrics server missing WriteTimeout (slow-reader connection hold)")
	}
	if srv.IdleTimeout <= 0 {
		t.Error("metrics server missing IdleTimeout (idle keep-alive hold)")
	}
	// Parity with the admin server posture (internal/admin newServer).
	if srv.ReadTimeout < 5*time.Second {
		t.Errorf("metrics server ReadTimeout %v is weaker than the 10s admin posture", srv.ReadTimeout)
	}
}
