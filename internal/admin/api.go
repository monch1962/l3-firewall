package admin

import (
	"crypto/subtle"
	"crypto/tls"
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
	eval      *opa.EmbeddedEvaluator
	engine    *engine.Engine
	version   string
	started   time.Time
	token     string
	readToken string // read-only token; optional
}

// New creates an admin API with the given dependencies.
// token is the full-access admin token. readToken is an optional read-only token.
// If both are empty, auth is disabled.
func New(eval *opa.EmbeddedEvaluator, eng *engine.Engine, version, token, readToken string) *API {
	return &API{
		eval:      eval,
		engine:    eng,
		version:   version,
		started:   time.Now(),
		token:     token,
		readToken: readToken,
	}
}

// Handler returns the admin HTTP handler with all routes and security headers.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	// Read-only endpoints (accessible with readToken or full token)
	mux.HandleFunc("/admin/health", a.handleHealth)
	mux.HandleFunc("/admin/stats", a.requireReadAuth(a.handleStats))
	mux.HandleFunc("/admin/blocks", a.requireReadAuth(a.handleBlocks))
	mux.HandleFunc("/admin/block-stats", a.requireReadAuth(a.handleBlockStats))
	// Write endpoints (require full token)
	mux.HandleFunc("/admin/policy/reload", a.requireWriteAuth(a.handlePolicyReload))
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

// extractToken reads the bearer token from the Authorization header.
func extractToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return auth
}

// tokenMatches does a constant-time comparison of two tokens.
func tokenMatches(given, expected string) bool {
	if expected == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(given), []byte(expected)) == 1
}

// requireReadAuth accepts the read-only token OR the full admin token.
func (a *API) requireReadAuth(next http.HandlerFunc) http.HandlerFunc {
	if a.token == "" && a.readToken == "" {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		given := extractToken(r)
		if given == "" {
			http.Error(w, `{"error":"authorization required"}`, http.StatusUnauthorized)
			return
		}
		if tokenMatches(given, a.token) || (a.readToken != "" && tokenMatches(given, a.readToken)) {
			next(w, r)
			return
		}
		http.Error(w, `{"error":"invalid authorization token"}`, http.StatusForbidden)
	}
}

// requireWriteAuth only accepts the full admin token.
func (a *API) requireWriteAuth(next http.HandlerFunc) http.HandlerFunc {
	if a.token == "" {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		given := extractToken(r)
		if given == "" {
			http.Error(w, `{"error":"authorization required"}`, http.StatusUnauthorized)
			return
		}
		if tokenMatches(given, a.token) {
			next(w, r)
			return
		}
		if a.readToken != "" && tokenMatches(given, a.readToken) {
			http.Error(w, `{"error":"read-only token cannot modify resources"}`, http.StatusForbidden)
			return
		}
		http.Error(w, `{"error":"invalid authorization token"}`, http.StatusForbidden)
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
	slog.Info("admin API: policy reload requested (file watcher handles the reload)")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "reload triggered"})
}

// StartServer starts the admin HTTP server in a goroutine (plain HTTP).
func (a *API) StartServer(addr string) *http.Server {
	srv := newServer(addr, a.Handler())
	go func() {
		slog.Info("admin API listening", "addr", addr, "tls", false)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("admin API error", "error", err)
		}
	}()
	return srv
}

// StartServerTLS starts the admin HTTP server with TLS in a goroutine.
// If certFile or keyFile is empty, falls back to plain HTTP.
func (a *API) StartServerTLS(addr, certFile, keyFile string) (*http.Server, string, error) {
	if certFile == "" || keyFile == "" {
		srv := a.StartServer(addr)
		return srv, srv.Addr, nil
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		slog.Error("admin API: failed to load TLS cert", "error", err)
		srv := a.StartServer(addr)
		return srv, srv.Addr, nil
	}
	listener, err := tls.Listen("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		return nil, "", fmt.Errorf("TLS listen: %w", err)
	}
	srv := newServer("", a.Handler())
	go func() {
		slog.Info("admin API listening", "addr", listener.Addr().String(), "tls", true)
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			slog.Error("admin API error", "error", err)
		}
	}()
	return srv, listener.Addr().String(), nil
}

// newServer creates an *http.Server with sensible timeouts.
func newServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
}
