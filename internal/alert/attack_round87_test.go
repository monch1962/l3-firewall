// Red-team security hardening Round 87 — the alerting plane's credential.
//
// A webhook URL is a BEARER CREDENTIAL. Slack, Discord, Teams and Mattermost
// all put the secret in the URL path (https://hooks.slack.com/services/T…/
// B…/XXXXXXXX); possession of the URL is sufficient to post into the channel —
// no header, no signature. R87 found that l3-firewall wrote that URL verbatim
// to its log stream in two places:
//
//   - on every failed delivery (connection refused, DNS failure, timeout) and
//     on every HTTP >= 400 response, from Router.fire; and
//   - at startup, on the "alerts enabled" line.
//
// Docker captures container stdout into the local log driver or a hosted log
// service, so the secret leaves the process and lands somewhere with a wider
// readership than the process environment (support bundles, SIEM, a shared log
// index). An attacker who can read the log can then post arbitrary messages
// into the operator's incident channel — and forge the alert format the
// operator trusts for "the firewall saw something", including messages that
// claim an all-clear.
//
// The measurement below is the important part: the pre-fix line leaked the URL
// TWICE, because net/http embeds the request URL in its error string
// (`Post "http://…/SECRET": dial tcp …`). Redacting only the structured "url"
// attribute is therefore not enough — the error text must be scrubbed too.
package alert

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// httptestStatusServer starts a server that answers every request with the
// given status, so the >= 400 branch of Router.fire can be exercised.
func httptestStatusServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
}

// captureHandler is a slog.Handler that records every message and attribute
// value so a test can assert what actually reached the log stream.
type captureHandler struct {
	mu      sync.Mutex
	lines   []string
	records chan string
}

func newCaptureHandler() *captureHandler {
	return &captureHandler{records: make(chan string, 16)}
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		b.WriteString(" ")
		b.WriteString(a.Key)
		b.WriteString("=")
		b.WriteString(a.Value.String())
		return true
	})
	line := b.String()
	h.mu.Lock()
	h.lines = append(h.lines, line)
	h.mu.Unlock()
	select {
	case h.records <- line:
	default:
	}
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

func (h *captureHandler) all() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.lines...)
}

// ── R87.2: a failing webhook delivery must not log the credential ────────
// Attacker model: anyone who can read the firewall's log stream (container log
// driver, SIEM, support bundle) — or who can make the delivery fail and then
// read the operator's log — obtains a URL that posts into the incident channel.
func TestAttack_FailedWebhookDoesNotLogCredential(t *testing.T) {
	const secret = "T000/B000/SUPERSECRETTOKEN"

	h := newCaptureHandler()
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(prev) })

	// 127.0.0.1:1 refuses instantly: the failure path under test.
	r := NewRouter(Config{WebhookURL: "http://127.0.0.1:1/hooks/" + secret})
	r.Send(AlertEvent{Type: AlertBlockRate, Message: "block rate exceeded", Timestamp: time.Now()})

	deadline := time.After(5 * time.Second)
	for {
		select {
		case line := <-h.records:
			if !strings.Contains(line, "webhook") && !strings.Contains(line, "alert") {
				continue
			}
			if strings.Contains(line, "SUPERSECRETTOKEN") || strings.Contains(line, secret) {
				t.Fatalf("log line leaked the webhook credential: %q", line)
			}
			// Non-vacuous: the line must still identify the endpoint, so an
			// operator can act on it. Dropping the field entirely would be a
			// different (silent) regression.
			if !strings.Contains(line, "127.0.0.1") {
				t.Errorf("log line no longer identifies the failing endpoint: %q", line)
			}
			return
		case <-deadline:
			t.Fatalf("no delivery-failure log line captured; lines=%q", h.all())
		}
	}
}

// ── R87.2b: an HTTP >= 400 response must not log the credential either ───
// The status-code branch logs the URL without an error string, so a fix that
// only scrubbed the transport error would leave this one leaking.
func TestAttack_WebhookErrorStatusDoesNotLogCredential(t *testing.T) {
	const secret = "SVC000/B000/SUPERSECRETTOKEN"

	h := newCaptureHandler()
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(prev) })

	srv := httptestStatusServer(t, 500)
	defer srv.Close()

	r := NewRouter(Config{WebhookURL: srv.URL + "/hooks/" + secret})
	r.Send(AlertEvent{Type: AlertPortScan, Message: "port scan", Timestamp: time.Now()})

	deadline := time.After(5 * time.Second)
	for {
		select {
		case line := <-h.records:
			if !strings.Contains(line, "webhook") {
				continue
			}
			if strings.Contains(line, "SUPERSECRETTOKEN") {
				t.Fatalf("status-error log line leaked the webhook credential: %q", line)
			}
			if !strings.Contains(line, "status") {
				t.Errorf("status-error line lost the status field: %q", line)
			}
			return
		case <-deadline:
			t.Fatalf("no status-error log line captured; lines=%q", h.all())
		}
	}
}
