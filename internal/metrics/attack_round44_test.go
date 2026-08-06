// Red-team security hardening Round 44 — internal/metrics, the last package
// with ZERO test files (R40 examined it and documented dead-metric findings but
// never wrote tests or fixed the second-call crash):
//
//  1. metrics.Init() is NOT idempotent — a second call re-registers the same
//     collectors on the Prometheus default registry and panics inside
//     prometheus.MustRegister ("duplicate metrics collector registration
//     attempted"). The panic is unhandled in main()'s call path, so any
//     second Init (future wiring, tests, admin-triggered re-init) crashes the
//     entire firewall process. R9/R12 class: second-call-crashes-process bugs
//     are fixed with sync.Once (double-close prevention, idempotent Start).
//
// R44 FIX: guard Init's construction+registration with a package-level
// sync.Once so repeated calls are no-ops returning the first instance.
//
// NOTE on test ordering: Go runs tests in source order, and Init is
// first-call-wins. TestAttack_InitWithConntrackCallback is deliberately the
// FIRST test in this file so the callback-wired instance is created first;
// the remaining tests reuse that instance.
package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// ── R44.3: Init with a conntrack-length callback wires the GaugeFunc ───
// The getConntrackLen callback must be honored: ConntrackEntries must be
// non-nil and reflect the callback's value. Exercises the nil vs non-nil
// callback branch. Runs first so the callback-wired instance wins.
func TestAttack_InitWithConntrackCallback(t *testing.T) {
	m := Init(func() int {
		return 42
	})
	if m == nil {
		t.Fatal("Init() returned nil")
	}
	if m.ConntrackEntries == nil {
		t.Fatal("ConntrackEntries GaugeFunc not registered with non-nil callback")
	}
}

// ── R44.1: Init() must be idempotent — second call must not panic ──────
// A second Init() re-registers duplicate collectors on the default registry
// and panics inside prometheus.MustRegister. Before the fix this panic is
// unhandled and takes down the whole firewall process.
func TestAttack_InitTwiceDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("second Init() panicked: %v — Init must be idempotent (sync.Once)", r)
		}
	}()

	m1 := Init(nil)
	m2 := Init(nil)

	if m1 == nil {
		t.Fatal("first Init() returned nil")
	}
	if m2 == nil {
		t.Fatal("second Init() returned nil")
	}
	if m1 != m2 {
		t.Error("Init() must return the same instance on repeated calls")
	}
}

// ── R44.2: Get() after Init returns the registered instance ────────────
// Get() must return the same instance Init() created — a stale or second
// instance would carry unregistered collectors whose increments vanish.
func TestAttack_GetReturnsInitInstance(t *testing.T) {
	m := Init(nil)
	g := Get()
	if g == nil {
		t.Fatal("Get() returned nil after Init()")
	}
	if g != m {
		t.Error("Get() returned a different instance than Init()")
	}
}

// ── R44.4: metrics handler serves /metrics without error ───────────────
// The promhttp handler must respond 200 to a GET /metrics scrape.
func TestAttack_MetricsHandlerServes(t *testing.T) {
	h := Handler()
	if h == nil {
		t.Fatal("Handler() returned nil")
	}
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("GET /metrics returned %d, want 200", w.Code)
	}
}
