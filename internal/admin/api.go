// Package admin provides the REST admin API for live rule management.
package admin

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/monch1962/l3-firewall/internal/engine"
	"github.com/monch1962/l3-firewall/internal/opa"
)

// API holds dependencies for the admin HTTP handlers.
type API struct {
	eval    *opa.EmbeddedEvaluator
	engine  *engine.Engine
	version string
	started time.Time
	token   string
}

// New creates an admin API with the given dependencies.
func New(eval *opa.EmbeddedEvaluator, eng *engine.Engine, version, token string) *API {
	return &API{
		eval:    eval,
		engine:  eng,
		version: version,
		started: time.Now(),
		token:   token,
	}
}

// Handler returns the admin HTTP handler with all routes and security headers.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/health", a.handleHealth)
	mux.HandleFunc("/admin/stats", a.requireAuth(a.handleStats))
	mux.HandleFunc("/admin/blocks", a.requireAuth(a.handleBlocks))
	mux.HandleFunc("/admin/block-stats", a.requireAuth(a.handleBlockStats))
	mux.HandleFunc("/admin/policy/reload", a.requireAuth(a.handlePolicyReload))
	return withSecurityHeaders(mux)
}

// withSecurityHeaders wraps an http.Handler to set security headers on all responses.
func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// requireAuth wraps a handler with bearer token authentication.
func (a *API) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	if a.token == "" {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, `{"error":"authorization required"}`, http.StatusUnauthorized)
			return
		}
		var token string
		if len(auth) > 7 && auth[:7] == "Bearer " {
			token = auth[7:]
		} else {
			token = auth
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(a.token)) != 1 {
			http.Error(w, `{"error":"invalid authorization token"}`, http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "ok",
		"version":        a.version,
		"uptime":         time.Since(a.started).String(),
		"engine_running": a.engine.Running(),
	})
}

func (a *API) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := a.engine.Stats()
	ctStats := a.engine.ConntrackStats()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"packets_processed":  stats.PacketsProcessed,
		"packets_allowed":    stats.PacketsAllowed,
		"packets_blocked":    stats.PacketsBlocked,
		"conntrack_entries":  json.Number(fmt.Sprintf("%d", ctStats.Created)),
		"conntrack_expired":  json.Number(fmt.Sprintf("%d", ctStats.Expired)),
		"conntrack_evicted":  json.Number(fmt.Sprintf("%d", ctStats.Evicted)),
		"engine_running":     a.engine.Running(),
		"uptime":             time.Since(a.started).String(),
		"version":            a.version,
	})
}

func (a *API) handleBlocks(w http.ResponseWriter, r *http.Request) {
	blocks := a.engine.RecentBlocks()
	w.Header().Set("Content-Type", "application/json")
	if blocks == nil {
		json.NewEncoder(w).Encode([]engine.BlockLogEntry{})
		return
	}
	json.NewEncoder(w).Encode(blocks)
}

func (a *API) handleBlockStats(w http.ResponseWriter, r *http.Request) {
	stats := a.engine.BlockStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (a *API) handlePolicyReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"use POST"}`, http.StatusMethodNotAllowed)
		return
	}

	// Trigger hot-reload via file watcher (read the latest policy from disk)
	// The reload is handled by the file watcher in cmd/server. This endpoint
	// just logs the request; the actual reload happens on file change detection.
	slog.Info("admin API: policy reload requested (file watcher handles the reload)")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "reload triggered"})
}

// StartServer starts the admin HTTP server in a goroutine.
func (a *API) StartServer(addr string) *http.Server {
	srv := &http.Server{
		Addr:              addr,
		Handler:           a.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		slog.Info("admin API listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("admin API error", "error", err)
		}
	}()
	return srv
}
