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

func newTestAPI(t *testing.T) *API {
	t.Helper()
	eval, err := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true`,
	})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	ct := conntrack.NewTable(conntrack.DefaultConfig())
	rl := ratelimit.NewLimiter(1000, 1000000)
	eng := engine.New(eval, ct, rl, true, false, nil)
	return New(eval, eng, "test", "", "")
}

func TestHealthEndpoint(t *testing.T) {
	api := newTestAPI(t)
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/admin/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("status = %v, want ok", resp["status"])
	}
	if _, ok := resp["engine_running"]; !ok {
		t.Error("response missing engine_running")
	}
}

func TestStatsEndpoint(t *testing.T) {
	api := newTestAPI(t)
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := resp["packets_processed"]; !ok {
		t.Error("response missing packets_processed")
	}
}

func TestBlocksEndpoint(t *testing.T) {
	eng := engine.New(nil, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(1000, 1000000), true, false, nil)
	api := New(nil, eng, "test", "", "")
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/admin/blocks", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var blocks []interface{}
	if err := json.NewDecoder(w.Body).Decode(&blocks); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if blocks == nil {
		t.Error("expected empty array, got nil")
	}
}

func TestPolicyReload(t *testing.T) {
	eval, _ := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true`,
	})
	ct := conntrack.NewTable(conntrack.DefaultConfig())
	rl := ratelimit.NewLimiter(1000, 1000000)
	eng := engine.New(eval, ct, rl, true, false, nil)
	api := New(eval, eng, "test", "", "")
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodPost, "/admin/policy/reload", bytes.NewBufferString(`{}`))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestPolicyReloadWrongMethod(t *testing.T) {
	api := newTestAPI(t)
	handler := api.Handler()

	req := httptest.NewRequest(http.MethodGet, "/admin/policy/reload", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestAuthRequired(t *testing.T) {
	eval, _ := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true`,
	})
	ct := conntrack.NewTable(conntrack.DefaultConfig())
	rl := ratelimit.NewLimiter(1000, 1000000)
	eng := engine.New(eval, ct, rl, true, false, nil)
	api := New(eval, eng, "test", "my-secret-token", "")
	handler := api.Handler()

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{"no auth", "", http.StatusUnauthorized},
		{"wrong token", "Bearer wrong-token", http.StatusForbidden},
		{"valid token", "Bearer my-secret-token", http.StatusOK},
		{"token without bearer", "my-secret-token", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/admin/blocks", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}
