// Package alert provides webhook-based alerting for firewall events.
//
// Alerts are fired asynchronously (non-blocking HTTP POST) with a configurable
// cooldown per alert type to prevent notification storms.
package alert

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/monch1962/l3-firewall/internal/netguard"
	"github.com/monch1962/l3-firewall/internal/redact"
)

// AlertType identifies the category of an alert event.
type AlertType int

const (
	AlertBlockRate AlertType = iota // Block rate threshold exceeded
	AlertPortScan                   // Port scan detected
	AlertConnLimit                  // Connection limit per source IP
	AlertOPAError                   // OPA evaluation error
	AlertRateLimit                  // Sustained rate limit trigger
)

// String returns the human-readable name of an alert type.
func (at AlertType) String() string {
	switch at {
	case AlertBlockRate:
		return "block_rate"
	case AlertPortScan:
		return "port_scan"
	case AlertConnLimit:
		return "connection_limit"
	case AlertOPAError:
		return "opa_error"
	case AlertRateLimit:
		return "rate_limit"
	default:
		return "unknown"
	}
}

// AlertEvent represents a single alert notification.
type AlertEvent struct {
	Type      AlertType `json:"-"`                // alert category
	Message   string    `json:"message"`          // human-readable description
	Source    string    `json:"source,omitempty"` // component that generated the alert
	Timestamp time.Time `json:"timestamp"`        // when the event occurred
}

// Config controls the alert router behaviour.
type Config struct {
	WebhookURL string        // URL to POST webhook payloads to (empty = disabled)
	Cooldown   time.Duration // minimum interval between same-type alerts
}

// warnPlaintextWebhook logs loudly when alerts will carry a bearer credential
// over plain HTTP to a host that is not loopback (R88.3).
//
// The webhook URL IS the credential — Slack/Discord/Teams put the secret in the
// path — so every POST hands it to anyone on the path. This is not fatal
// (a TLS-terminating sidecar or a pod-local collector is a legitimate
// deployment), but it must not be SILENT: an operator who configured
// `http://` for an internal collector and one who believes their `https://`
// proxy handles it look identical in the logs otherwise.
//
// Loopback (127.0.0.0/8, ::1, localhost) is exempt: those bytes never leave the
// host, so there is nothing on the wire to observe. Warning there would train
// the operator to ignore this warning.
func warnPlaintextWebhook(raw string) {
	if raw == "" {
		return
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || !strings.EqualFold(u.Scheme, "http") {
		return
	}
	if isLocalWebhookHost(u.Hostname()) {
		return
	}
	slog.Warn("alert: webhook URL is plain HTTP — the webhook URL IS the bearer credential "+
		"(the secret is in the path), so every alert transmits it in cleartext where an on-path "+
		"observer can recover it and forge messages into the incident channel; use an https:// "+
		"webhook URL, or terminate TLS in front of the collector (a loopback/pod-local "+
		"http collector is exempt)", "host", u.Hostname())
}

// isLocalWebhookHost reports whether host cannot put bytes on a network.
// The predicate lives in internal/netguard because the etcd policy channel
// asks the same question (R97) and two copies of a guard drift (R85).
func isLocalWebhookHost(host string) bool {
	return netguard.IsLoopbackHost(host)
}

// Router manages alert dispatch with per-type cooldown suppression.
type Router struct {
	mu       sync.Mutex
	cfg      Config
	client   *http.Client
	lastSent map[AlertType]time.Time // last send time per alert type
}

// NewRouter creates an alert router. Default cooldown is 30 seconds.
func NewRouter(cfg Config) *Router {
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 30 * time.Second
	}
	warnPlaintextWebhook(cfg.WebhookURL)
	return &Router{
		cfg: cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
			// Do not follow redirects to prevent SSRF: a compromised or
			// malicious webhook endpoint could 302/307 the alert POST
			// (containing src IPs and messages) to an internal service
			// (cloud metadata endpoints, etcd, admin API). Webhook
			// endpoints should serve directly; redirects serve no
			// legitimate purpose and turn the firewall into an SSRF
			// proxy that leaks alert payloads to internal targets.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		lastSent: make(map[AlertType]time.Time),
	}
}

// Send dispatches an alert asynchronously. If WebhookURL is empty, the event
// is silently dropped. Alerts of the same type within the cooldown period are
// suppressed. Safe for concurrent use and nil receivers.
func (r *Router) Send(e AlertEvent) {
	if r == nil || r.cfg.WebhookURL == "" {
		return
	}

	r.mu.Lock()
	last, exists := r.lastSent[e.Type]
	now := time.Now()
	if exists && now.Sub(last) < r.cfg.Cooldown {
		r.mu.Unlock()
		return
	}
	r.lastSent[e.Type] = now
	r.mu.Unlock()

	// Fire asynchronously — never block the hot path
	go r.fire(e)
}

// fire sends the alert payload as JSON via HTTP POST.
func (r *Router) fire(e AlertEvent) {
	payload := map[string]interface{}{
		"type":       e.Type.String(),
		"message":    e.Message,
		"source":     e.Source,
		"timestamp":  e.Timestamp.UTC().Format(time.RFC3339),
		"event_type": "l3_firewall_alert",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		slog.Error("alert: failed to marshal payload", "error", err)
		return
	}

	resp, err := r.client.Post(r.cfg.WebhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		// R87: the URL is a bearer credential (Slack/Discord put the secret in
		// the path) and net/http echoes it into err.Error(), so BOTH the url
		// attribute and the error text must be redacted before they reach the
		// log stream. Docker's log driver and any SIEM that ingests it have a
		// wider readership than the process environment.
		slog.Warn("alert: webhook request failed",
			"url", redact.URL(r.cfg.WebhookURL),
			"error", redact.ScrubIn(err.Error(), r.cfg.WebhookURL))
		return
	}
	defer resp.Body.Close()
	// Drain a bounded amount so the connection can be reused; the body of an
	// alert webhook carries no information the firewall needs.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))

	if resp.StatusCode >= 400 {
		slog.Warn("alert: webhook returned error",
			"url", redact.URL(r.cfg.WebhookURL), "status", resp.StatusCode)
	}
}
