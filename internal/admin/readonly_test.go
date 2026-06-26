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

func TestReadOnlyTokenAllowedOnReadEndpoint(t *testing.T) {
	eval, _ := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true`,
	})
	ct := conntrack.NewTable(conntrack.DefaultConfig())
	rl := ratelimit.NewLimiter(1000, 1000000)
	eng := engine.New(eval, ct, rl, true, false, nil, nil, nil, nil, nil)
	api := New(eval, eng, "test", "admin-secret", "read-only-secret")
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
	req.Header.Set("Authorization", "Bearer read-only-secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for read-only token on stats, got %d", w.Code)
	}
}

func TestReadOnlyTokenBlockedOnWriteEndpoint(t *testing.T) {
	eval, _ := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true`,
	})
	ct := conntrack.NewTable(conntrack.DefaultConfig())
	rl := ratelimit.NewLimiter(1000, 1000000)
	eng := engine.New(eval, ct, rl, true, false, nil, nil, nil, nil, nil)
	api := New(eval, eng, "test", "admin-secret", "read-only-secret")
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodPost, "/admin/policy/reload", nil)
	req.Header.Set("Authorization", "Bearer read-only-secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for read-only token on policy/reload, got %d", w.Code)
	}
}

func TestAdminTokenAccessesBoth(t *testing.T) {
	eval, _ := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true`,
	})
	ct := conntrack.NewTable(conntrack.DefaultConfig())
	rl := ratelimit.NewLimiter(1000, 1000000)
	eng := engine.New(eval, ct, rl, true, false, nil, nil, nil, nil, nil)
	api := New(eval, eng, "test", "admin-secret", "read-only-secret")
	handler := api.Handler()

	// Read endpoint
	req := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for admin token on stats, got %d", w.Code)
	}

	// Write endpoint
	req2 := httptest.NewRequest(http.MethodPost, "/admin/policy/reload", nil)
	req2.Header.Set("Authorization", "Bearer admin-secret")
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200 for admin token on reload, got %d", w2.Code)
	}
}

func TestReadOnlyTokenWithEmptyReadToken(t *testing.T) {
	// When readToken is empty, requireReadAuth falls back to requireAuth behavior
	eval, _ := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true`,
	})
	ct := conntrack.NewTable(conntrack.DefaultConfig())
	rl := ratelimit.NewLimiter(1000, 1000000)
	eng := engine.New(eval, ct, rl, true, false, nil, nil, nil, nil, nil)
	api := New(eval, eng, "test", "admin-secret", "")
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for admin token on stats, got %d", w.Code)
	}
}
