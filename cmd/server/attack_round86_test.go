// Red-team security hardening Round 86 — detection-plane transport.
//
// /metrics is the SECOND HTTP transport this binary serves, on its own
// listener (--metrics-listen), with no authentication. Round 84 installed an
// R84 DNS-rebinding Host guard on the admin transport only; the metrics
// transport never got it — the R85 propagation class (a guard installed on
// one transport does not protect the other one) applied to HTTP surfaces
// rather than file paths.
//
// Today the gap leaks nothing because the endpoint publishes no samples (the
// R86.1 finding fixed alongside this one). The moment the counters carry real
// data — protocol/decision counts, bounded reason labels — a page on
// attacker.example that rebinds to the firewall could read them same-origin
// from a victim's browser: a positive signal that the host is an l3-firewall
// and which policies are firing. The guard must therefore land WITH the
// data, not after it.
package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// ── R86.9: the metrics listener refuses an unrecognised Host ────────────
// DNS rebinding needs the browser to send the ATTACKER's hostname in Host;
// the browser never rewrites it, so a transport-layer allowlist breaks the
// attack without touching legitimate scrapes (IP literals, localhost, or an
// operator-supplied name via --admin-allowed-hosts).
func TestAttack_MetricsListenerRefusesHostileHost(t *testing.T) {
	h := metricsHandler(nil, ":9100")

	// Hostile: a rebindable public hostname.
	req := httptest.NewRequest(http.MethodGet, "http://evil.example:9100/metrics", nil)
	req.Host = "evil.example:9100"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("Host: evil.example/metrics returned %d, want 403 — the metrics transport is reachable by DNS rebinding", w.Code)
	}
	if strings.Contains(w.Body.String(), "l3_firewall_") {
		t.Errorf("refused scrape still leaked the metrics document: %q", w.Body.String())
	}

	// Legitimate: localhost and an IP literal must keep working.
	for _, host := range []string{"localhost:9100", "127.0.0.1:9100"} {
		req := httptest.NewRequest(http.MethodGet, "http://"+host+"/metrics", nil)
		req.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Host: %s/metrics returned %d, want 200 (legitimate scrape broken)", host, w.Code)
		}
	}
}

// ── R86.10: the shipped binary actually wires the guard and the sink ─────
// A guard that exists in a package but is never installed on the listener
// (or a metrics instance that is initialised but never handed to the engine)
// is the R40.4 silently-dropped-control class. main() is not executable in a
// unit test, so the wiring is pinned by source property — the same technique
// R83/R84 used for the entrypoint/flag wiring.
func TestAttack_MainWiresMetricsIntoSinkAndGuard(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	code := string(src)

	if !strings.Contains(code, "WithMetrics(") {
		t.Error("main.go never hands the metrics instance to the engine: the decision counters stay dead (R86.1)")
	}
	if !strings.Contains(code, "metricsHandler(") {
		t.Error("main.go does not build the metrics listener through metricsHandler(): the R84 Host guard is not installed on the metrics transport")
	}
	if strings.Contains(code, "metricsMux := http.NewServeMux()") {
		t.Error("main.go still builds the raw metrics mux inline — the host guard must wrap it")
	}
	// The guard must be the shared admin predicate, not a copy.
	if !strings.Contains(code, "admin.NewHostGuard(") {
		t.Error("metrics transport guard is not the shared admin.NewHostGuard — a second copy of the predicate will drift (R85: centralise, do not patch twice)")
	}
}
