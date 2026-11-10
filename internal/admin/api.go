package admin

import (
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
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

	// Rule version history (guarded: reload appends while /admin/policy/versions
	// reads — a bare slice is a data race (R46), remotely triggerable since the
	// admin API is unauthenticated when no tokens are configured).
	versionsMu     sync.RWMutex
	policyVersions []PolicyVersion

	// allowedHosts is the operator-configured DNS-name allowlist for the
	// transport-layer Host guard (R84). IP literals and localhost are
	// always accepted; this list adds named hosts (reverse proxy / service
	// DNS). Set via WithAllowedHosts before serving.
	allowedHosts []string
}

// PolicyVersion records a policy reload event.
type PolicyVersion struct {
	Timestamp   time.Time `json:"timestamp"`
	Version     string    `json:"version"`
	Description string    `json:"description,omitempty"`
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

// WithAllowedHosts adds DNS names that the transport-layer Host guard
// accepts in addition to IP literals and localhost (R84). Entries are
// matched case-insensitively on the hostname with any :port and a trailing
// dot removed, so "Admin.Internal:8082" and "admin.internal." both match a
// request whose Host is "admin.internal:8082". Chainable for use from main.
func (a *API) WithAllowedHosts(hosts ...string) *API {
	for _, h := range hosts {
		if h = strings.TrimSpace(h); h != "" {
			a.allowedHosts = append(a.allowedHosts, h)
		}
	}
	return a
}

// Handler returns the admin HTTP handler with all routes and security headers.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	// Read-only endpoints (accessible with readToken or full token)
	mux.HandleFunc("/admin/health", a.handleHealth)
	mux.HandleFunc("/admin/stats", a.requireReadAuth(a.handleStats))
	mux.HandleFunc("/admin/blocks", a.requireReadAuth(a.handleBlocks))
	mux.HandleFunc("/admin/block-stats", a.requireReadAuth(a.handleBlockStats))
	mux.HandleFunc("/admin/policy/versions", a.requireReadAuth(a.handlePolicyVersions))
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

// normalizeHost reduces a Host header value or allowlist entry to a
// comparable lower-case hostname: the :port is removed, IPv6 brackets are
// stripped, and a trailing FQDN dot is removed. "Admin.Internal.:8082"
// normalises to "admin.internal".
func normalizeHost(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	h = strings.TrimSuffix(h, ".")
	return strings.ToLower(h)
}

// isWildcardListenHost reports whether a listen address binds every
// interface (so it contributes no useful hostname to the allowlist).
func isWildcardListenHost(addr string) bool {
	switch normalizeHost(addr) {
	case "", "0.0.0.0", "::":
		return true
	}
	return false
}

// hostAllowed is the R84 DNS-rebinding predicate. A Host header is accepted
// when it is an IP literal (127.0.0.1, a pod/container IP, ::1), localhost
// or any *.localhost name (RFC 6761 — never publicly resolvable, so unusable
// for rebinding), a configured --admin-allowed-hosts entry, or the host part
// of the listen address. Every other value is an attacker-controlled
// hostname and is refused. A request with no Host at all (HTTP/1.0) is
// refused: the admin API is HTTP/1.1-only in practice and a missing Host is
// exactly the ambiguity the guard exists to remove.
func (a *API) hostAllowed(host string, extra []string) bool {
	// Reject Host values carrying characters that are never legal in a Host
	// header (userinfo '@', path/query/fragment delimiters, whitespace,
	// control bytes). Without this, a crafted value like
	// "admin.internal:8082@evil.example" would be splittable by
	// net.SplitHostPort into the allowlisted "admin.internal" — a parsing
	// confusion a browser would not produce but a direct client can.
	if strings.ContainsAny(host, "@/\\?# 	\r\n") {
		return false
	}
	h := normalizeHost(host)
	if h == "" {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	// Only [a-z0-9.-] can remain for a DNS name; anything else (stray
	// colons, brackets, unicode, percent-escapes) is not a hostname.
	for _, r := range h {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
			continue
		}
		return false
	}
	for _, candidate := range a.allowedHosts {
		if normalizeHost(candidate) == h {
			return true
		}
	}
	for _, candidate := range extra {
		if normalizeHost(candidate) == h {
			return true
		}
	}
	return false
}

// hostGuard installs the R84 Host allowlist on the transport. It is applied
// by StartServer and StartServerTLS — the only ways this binary serves the
// API — and NOT by Handler(), so embedding callers that mount Handler() on
// their own listener keep their previous behaviour and must add an equivalent
// check themselves (documented contract).
//
// Rationale: without a Host check, an unauthenticated (default) admin API on
// a routable address is exploitable by DNS rebinding — a page on
// attacker.example re-resolves to the firewall, the browser then makes
// SAME-ORIGIN requests (X-Frame-Options does not apply to fetch; CORS does
// not apply to same-origin), and the attacker reads /admin/stats,
// /admin/blocks and posts /admin/policy/reload. The browser never rewrites
// the Host header, so rejecting unrecognised hosts breaks the attack without
// touching legitimate IP/localhost/reverse-proxy access.
func (a *API) hostGuard(next http.Handler, listenAddr string) http.Handler {
	var extra []string
	if !isWildcardListenHost(listenAddr) {
		extra = append(extra, listenAddr)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.hostAllowed(r.Host, extra) {
			next.ServeHTTP(w, r)
			return
		}
		slog.Warn("admin API: refused request with an unrecognised Host header (possible DNS rebinding)",
			"host", r.Host, "remote", r.RemoteAddr)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("{\"error\":\"unrecognised Host header\"}\n"))
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
// An empty expected value never matches: an unconfigured credential must
// not authenticate anyone. The "no auth configured" case is handled by the
// require*Auth wrappers returning the handler unwrapped when ALL tokens are
// empty — before R51, tokenMatches(given, "") returned true, so a config
// with ONLY --admin-read-token let any junk bearer token pass every read
// endpoint (and requireWriteAuth left writes fully open).
func tokenMatches(given, expected string) bool {
	if expected == "" {
		return false
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
	// Auth is disabled only when NO credentials are configured at all.
	// With only a read token set, write endpoints must NOT be left open:
	// the operator configured auth and the read-only token cannot modify
	// resources (R51 — previously a.token == "" short-circuited straight
	// to the handler, silently dropping the write control).
	if a.token == "" && a.readToken == "" {
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
		"packets_processed": stats.PacketsProcessed,
		"packets_allowed":   stats.PacketsAllowed,
		"packets_blocked":   stats.PacketsBlocked,
		"conntrack_entries": json.Number(fmt.Sprintf("%d", ctStats.Created)),
		"conntrack_expired": json.Number(fmt.Sprintf("%d", ctStats.Expired)),
		"conntrack_evicted": json.Number(fmt.Sprintf("%d", ctStats.Evicted)),
		"engine_running":    a.engine.Running(),
		"uptime":            time.Since(a.started).String(),
		"version":           a.version,
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

	// Record the version entry. Guarded by versionsMu: the append and the
	// 100-entry reslice race with concurrent readers of /admin/policy/versions
	// (R46 — the bare slice was a data race on the slice header).
	a.versionsMu.Lock()
	a.policyVersions = append(a.policyVersions, PolicyVersion{
		Timestamp:   time.Now(),
		Version:     a.version,
		Description: "policy reload triggered via admin API",
	})
	// Keep only last 100 entries
	if len(a.policyVersions) > 100 {
		a.policyVersions = a.policyVersions[len(a.policyVersions)-100:]
	}
	a.versionsMu.Unlock()

	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "reload triggered"})
}

// handlePolicyVersions returns the policy reload history.
func (a *API) handlePolicyVersions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	a.versionsMu.RLock()
	defer a.versionsMu.RUnlock()
	if a.policyVersions == nil {
		json.NewEncoder(w).Encode([]PolicyVersion{})
		return
	}
	json.NewEncoder(w).Encode(a.policyVersions)
}

// StartServer starts the admin HTTP server in a goroutine (plain HTTP).
func (a *API) StartServer(addr string) *http.Server {
	srv := newServer(addr, a.hostGuard(a.Handler(), addr))
	go func() {
		slog.Info("admin API listening", "addr", addr, "tls", false)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("admin API error", "error", err)
		}
	}()
	return srv
}

// StartServerTLS starts the admin HTTP server with TLS in a goroutine.
//
// TLS configuration is a CONTROL, so a configuration failure must not remove
// it silently (R83). Pre-R83 every failure — a missing/expired certificate, a
// botched rotation, or a certificate planted/removed by an attacker with write
// access to the configured path (the standing R42/R45/R62/R70 model) — fell
// through to StartServer and served the SAME routes, including the full-write
// POST /admin/policy/reload, in CLEARTEXT on the caller's address, returning a
// nil error. A supervisor cannot detect that downgrade (one log line, no
// error), a passive observer captures the bearer token — which is full write
// access to the running firewall's policy — and a MITM can inject a reload
// response on the same channel. The pre-R83 fallback is exactly the R78/R40.3
// fail-open doctrine inverted: instead of blocking when a decision cannot be
// made, it downgraded when a protection could not be established.
//
// The empty-paths case is unchanged and deliberate: no certificate means the
// operator did not request TLS, so plain HTTP is the documented behaviour. A
// PARTIAL pair (one path set) is a misconfiguration and is rejected.
func (a *API) StartServerTLS(addr, certFile, keyFile string) (*http.Server, string, error) {
	if certFile == "" && keyFile == "" {
		srv := a.StartServer(addr)
		return srv, srv.Addr, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, "", fmt.Errorf("admin TLS: both a certificate and a key are required (cert=%q key=%q) — refusing to start an unencrypted admin API", certFile, keyFile)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		slog.Error("admin API: TLS key material could not be loaded — refusing to start (no plaintext fallback)",
			"cert", certFile, "key", keyFile, "error", err)
		return nil, "", fmt.Errorf("admin TLS: loading key pair: %w", err)
	}
	listener, err := tls.Listen("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		return nil, "", fmt.Errorf("TLS listen: %w", err)
	}
	srv := newServer("", a.hostGuard(a.Handler(), addr))
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
