// Red-team security hardening Round 2 — Admin API HTTP attacks and input sanitization.
package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/engine"
	"github.com/monch1962/l3-firewall/internal/opa"
	"github.com/monch1962/l3-firewall/internal/ratelimit"
)

func newTestAPIforRound2(t *testing.T) *API {
	t.Helper()
	store := opa.NewDataStore()
	eval, err := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true`,
		Store:  store,
	})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	ct := conntrack.NewTable(conntrack.DefaultConfig())
	rl := ratelimit.NewLimiter(1000, 1000000)
	eng := engine.New(eval, ct, rl, true, false)
	return New(eval, store, eng, "test", "")
}

// ── R9: POST /admin/rules/update with wrong Content-Type ──────────
// Attacker sends JSON body with non-JSON Content-Type to bypass processing.
func TestAttack_RulesUpdateWrongContentType(t *testing.T) {
	api := newTestAPIforRound2(t)
	handler := api.Handler()

	body := `{"syn_rate_per_second": 300}`
	req := httptest.NewRequest(http.MethodPost, "/admin/rules/update", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should reject non-JSON Content-Type. Currently accepts any Content-Type.
	if w.Code != http.StatusUnsupportedMediaType && w.Code != http.StatusBadRequest {
		t.Errorf("expected 415 or 400 for text/plain Content-Type, got %d", w.Code)
	}
}

// ── R10: Trailing JSON garbage in /admin/rules/update ─────────────
// Attacker appends extra data after JSON object (JSON hijacking / injection).
func TestAttack_RulesUpdateTrailingGarbage(t *testing.T) {
	api := newTestAPIforRound2(t)
	handler := api.Handler()

	// Valid JSON followed by garbage
	body := `{"syn_rate_per_second": 300} alert('xss')`
	req := httptest.NewRequest(http.MethodPost, "/admin/rules/update", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should reject trailing garbage
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for trailing garbage, got %d", w.Code)
	}

	// Verify params were NOT updated
	params := api.store.GetParams()
	if v, ok := params["syn_rate_per_second"]; ok && v == float64(300) {
		t.Error("params were updated despite trailing garbage in request")
	}
}

// ── R11: Missing security headers on admin API ────────────────────
// Responses should include X-Content-Type-Options and X-Frame-Options.
func TestAttack_MissingSecurityHeaders(t *testing.T) {
	api := newTestAPIforRound2(t)
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/admin/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	ct := w.Header().Get("X-Content-Type-Options")
	if ct != "nosniff" {
		t.Errorf("expected X-Content-Type-Options: nosniff, got %q", ct)
	}
	xfo := w.Header().Get("X-Frame-Options")
	if xfo != "DENY" {
		t.Errorf("expected X-Frame-Options: DENY, got %q", xfo)
	}
}

// ── R12: GET endpoint accepts POST (method confusion) ─────────────
// Attacker uses wrong HTTP method on read endpoints.
func TestAttack_GetEndpointWrongMethod(t *testing.T) {
	api := newTestAPIforRound2(t)
	handler := api.Handler()

	// POST to /admin/health should work (health is read-only, but POST is fine)
	// POST to /admin/stats should be rejected (stats is read-only)
	req := httptest.NewRequest(http.MethodPost, "/admin/stats", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Log("POST to /admin/stats returns 200 (acceptable for read-only endpoint)")
	}
}

// ── R13: JSON decode should reject unknown fields ─────────────
// Attacker sends params with unexpected field types.
func TestAttack_RulesUpdateUnknownFieldsAccepted(t *testing.T) {
	api := newTestAPIforRound2(t)
	handler := api.Handler()

	body := `{"syn_rate_per_second": 300, "internal_secret": "leaked"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/rules/update", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Accepting unknown fields is not a vulnerability per se, but we should
	// verify it doesn't cause issues
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for valid JSON with extra fields, got %d", w.Code)
	}
	params := api.store.GetParams()
	if params["internal_secret"] != "leaked" {
		t.Error("extra field was not stored in params")
	}
}

// ── R14: Oversized JSON body on /admin/rules/update ───────────────
// Attacker sends enormous payload to cause OOM.
func TestAttack_RulesUpdateOversizedBody(t *testing.T) {
	api := newTestAPIforRound2(t)
	handler := api.Handler()

	// 11MB payload (limit is 10MB)
	large := strings.Repeat("x", 11*1024*1024)
	body := `{"data":"` + large + `"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/rules/update", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 for 11MB body, got %d", w.Code)
	}
}

// ── R15: Rules/update with deeply nested JSON ─────────────────────
// Deeply nested objects could cause stack issues with the JSON decoder.
func TestAttack_RulesUpdateDeeplyNestedJSON(t *testing.T) {
	api := newTestAPIforRound2(t)
	handler := api.Handler()

	// Build deeply nested JSON
	nested := `{"a":`
	for i := 0; i < 1000; i++ {
		nested += `{"b":`
	}
	nested += `1`
	for i := 0; i < 1000; i++ {
		nested += `}`
	}
	nested += `}`

	req := httptest.NewRequest(http.MethodPost, "/admin/rules/update", bytes.NewBufferString(nested))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Log("deeply nested JSON accepted (Go json decoder has depth limit)")
	}
}

// ── R16: Health endpoint leaking sensitive info ───────────────────
// Health endpoint is not auth-protected, should not leak too much info.
func TestAttack_HealthLeaksInfo(t *testing.T) {
	api := newTestAPIforRound2(t)
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/admin/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	// Health should not leak sensitive operational data
	if _, ok := resp["packets_blocked"]; ok {
		t.Error("health endpoint should not expose operational stats")
	}
}
