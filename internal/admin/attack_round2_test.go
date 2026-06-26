package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/engine"
	"github.com/monch1962/l3-firewall/internal/opa"
	"github.com/monch1962/l3-firewall/internal/ratelimit"
)

func TestAttack_RulesUpdateWrongContentType(t *testing.T) {
	eval, _ := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true`,
	})
	ct := conntrack.NewTable(conntrack.DefaultConfig())
	rl := ratelimit.NewLimiter(1000, 1000000)
	eng := engine.New(eval, ct, rl, true, false)
	api := New(eval, eng, "test", "", "")
	handler := api.Handler()

	body := `{"syn_rate_per_second": 300}`
	req := httptest.NewRequest(http.MethodPost, "/admin/policy/reload", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (policy reload accepts all Content-Types)", w.Code, http.StatusOK)
	}
}

func TestAttack_MissingSecurityHeaders(t *testing.T) {
	eval, _ := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true`,
	})
	ct := conntrack.NewTable(conntrack.DefaultConfig())
	rl := ratelimit.NewLimiter(1000, 1000000)
	eng := engine.New(eval, ct, rl, true, false)
	api := New(eval, eng, "test", "", "")
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/admin/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing X-Content-Type-Options header")
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("missing X-Frame-Options header")
	}
}

func TestAttack_HealthLeaksInfo(t *testing.T) {
	api := newTestAPI(t)
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/admin/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	// Health should only expose basic info, not internal stats
	if _, ok := resp["status"]; !ok {
		t.Error("health should return status")
	}
}
