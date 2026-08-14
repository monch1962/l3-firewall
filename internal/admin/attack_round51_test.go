package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/engine"
	"github.com/monch1962/l3-firewall/internal/opa"
	"github.com/monch1962/l3-firewall/internal/ratelimit"
)

// ── R51.1: read-token-only configuration bypasses auth entirely ──────────
//
// When the operator configures ONLY --admin-read-token (no --admin-token),
// the intended posture is read-only access protected by that token. Two
// holes make the configuration non-functional:
//
//  1. tokenMatches(given, "") returns TRUE for any non-empty given value
//     (its "expected == '' means auth disabled" convention). requireReadAuth
//     calls tokenMatches(given, a.token) unconditionally, so with a.token ==
//     "" the FIRST clause short-circuits: ANY junk bearer token passes the
//     read check — the read token protects nothing.
//  2. requireWriteAuth early-returns `next` when a.token == "" — write
//     endpoints are completely unauthenticated. A config with only a read
//     token therefore leaves /admin/policy/reload wide open.
//
// The admin API binds :8082 by default, so any network peer can trigger
// this. R46 hardened the policyVersions slice and R50 the engine stats on
// the same unauthenticated-admin-API threat model, but neither round
// examined the partial-token configuration.

func newReadTokenOnlyAPI(t *testing.T) *API {
	t.Helper()
	eval, err := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true`,
	})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	ct := conntrack.NewTable(conntrack.DefaultConfig())
	rl := ratelimit.NewLimiter(1000, 1000000)
	eng := engine.New(eval, ct, rl, true, false, nil, nil, nil, nil, nil, "", nil)
	// token = "" (no admin token), readToken = secret
	return New(eval, eng, "test", "", "read-only-secret")
}

func TestAttack_ReadTokenOnly_AnyTokenPassesReadAuth(t *testing.T) {
	api := newReadTokenOnlyAPI(t)
	handler := api.Handler()

	// An attacker who does NOT know the read token presents a junk bearer
	// token. With a.token == "", tokenMatches(given, "") returns true and
	// the request sails through to the handler.
	req := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
	req.Header.Set("Authorization", "Bearer attacker-garbage")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for unknown token on read endpoint (read-token-only config), got %d", w.Code)
	}
}

func TestAttack_ReadTokenOnly_WriteEndpointUnprotected(t *testing.T) {
	api := newReadTokenOnlyAPI(t)
	handler := api.Handler()

	// No Authorization header at all — requireWriteAuth sees a.token == ""
	// and returns the handler unwrapped. Unauthenticated → 401; any
	// credentialed-but-insufficient → 403. Either proves the endpoint is
	// no longer open.
	req := httptest.NewRequest(http.MethodPost, "/admin/policy/reload", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
		t.Errorf("expected 401/403 for unauthenticated write (read-token-only config), got %d", w.Code)
	}
}

func TestAttack_ReadTokenOnly_ReadTokenDeniedOnWriteEndpoint(t *testing.T) {
	api := newReadTokenOnlyAPI(t)
	handler := api.Handler()

	// The read token must NOT grant write access.
	req := httptest.NewRequest(http.MethodPost, "/admin/policy/reload", nil)
	req.Header.Set("Authorization", "Bearer read-only-secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for read token on write endpoint (read-token-only config), got %d", w.Code)
	}
}

func TestAttack_ReadTokenOnly_ReadTokenStillWorksOnReadEndpoint(t *testing.T) {
	// Positive regression: the legitimate read token must keep working on
	// read endpoints after the fix.
	api := newReadTokenOnlyAPI(t)
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
	req.Header.Set("Authorization", "Bearer read-only-secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for correct read token on read endpoint, got %d", w.Code)
	}
}
