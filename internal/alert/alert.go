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
	"sync"
	"time"

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
