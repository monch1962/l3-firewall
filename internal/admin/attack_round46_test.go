package admin

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// ── R46.1: admin policyVersions concurrent append/read data race ────────────
// handlePolicyReload appends to a.policyVersions with NO lock while
// handlePolicyVersions reads the slice with NO lock. Two concurrent
// requests (or one reload + one read) race on the slice header: the
// append may reallocate the backing array mid-read, producing torn data,
// a garbage response, or a panic inside the handler. With default config
// (no --admin-token/--admin-read-token) the admin API is unauthenticated,
// so any network peer can POST /admin/policy/reload while another GETs
// /admin/policy/versions — a remotely triggerable data race (R42
// documented this race as a finding but never fixed it).
func TestAttack_PolicyVersionsConcurrentReloadRace(t *testing.T) {
	api := newTestAPI(t)
	handler := api.Handler()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				req := httptest.NewRequest(http.MethodPost, "/admin/policy/reload", nil)
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				req := httptest.NewRequest(http.MethodGet, "/admin/policy/versions", nil)
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusOK {
					t.Errorf("versions status = %d, want 200", w.Code)
				}
			}
		}()
	}
	wg.Wait()
}

// ── R46.1b: bounded policyVersions history (append-only slice cap) ─────────
// The reload handler keeps only the last 100 entries; a flood of reload
// requests must not grow the slice unboundedly.
func TestAttack_PolicyVersionsBoundedHistory(t *testing.T) {
	api := newTestAPI(t)
	handler := api.Handler()

	for i := 0; i < 500; i++ {
		req := httptest.NewRequest(http.MethodPost, "/admin/policy/reload", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
	if len(api.policyVersions) > 100 {
		t.Errorf("policyVersions grew to %d entries, want cap 100", len(api.policyVersions))
	}
}
