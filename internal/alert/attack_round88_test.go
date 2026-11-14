// Red-team security hardening Round 88 — the alerting credential crosses the
// network in cleartext.
//
// R87 classified the webhook URL as a BEARER CREDENTIAL: the secret lives in
// the path (https://hooks.slack.com/services/T…/B…/XXXXXXXX) and possession is
// enough to post into the operator's incident channel. R87 then stopped the
// firewall from writing it to logs and gave the admin control plane a TLS
// transport.
//
// What was left open is the OUTBOUND leg. NewRouter accepts any URL with any
// scheme; when the scheme is plain `http` the credential is transmitted in
// cleartext on every single alert — same exposure class as R87.1, opposite
// direction. An on-path observer (shared switch, mirror port, wifi, a
// compromised router, a sidecar's own namespace) recovers the URL and can then
// forge messages into the channel the operator trusts for "the firewall saw
// something", including an all-clear.
//
// Not a startup failure: many deployments POST to a collector inside the pod
// or the same host, where plain HTTP never touches a wire. The defect is the
// SILENCE — the operator cannot distinguish "TLS terminated by my proxy" from
// "the secret is on the wire".
package alert

import (
	"log/slog"
	"strings"
	"testing"
)

// round88WarnSink records slog records and exposes a substring counter.
type round88WarnSink struct {
	*captureHandler // reuse the R87 recorder (message + key=value attributes)
}

func newRound88WarnSink() *round88WarnSink {
	return &round88WarnSink{captureHandler: newCaptureHandler()}
}

func (s *round88WarnSink) count(substr string) int {
	n := 0
	for _, l := range s.all() {
		if strings.Contains(l, substr) {
			n++
		}
	}
	return n
}

// ── R88.3: a plaintext webhook transport must not be silent ──────────────
func TestAttack_PlaintextWebhookTransportIsSilent(t *testing.T) {
	const secret = "T000/B000/SUPERSECRETTOKEN"

	sink := newRound88WarnSink()
	prev := slog.Default()
	slog.SetDefault(slog.New(sink))
	t.Cleanup(func() { slog.SetDefault(prev) })

	_ = NewRouter(Config{WebhookURL: "http://collector.example.com/hooks/" + secret})

	if sink.count("cleartext") == 0 && sink.count("PLAIN") == 0 && sink.count("plain HTTP") == 0 {
		t.Fatalf("NewRouter accepted a plain-HTTP webhook on a routable host with no warning; "+
			"the bearer credential in the URL path travels readable on every alert. Logged: %v", sink.all())
	}
	// The warning must be actionable and must not itself leak the credential.
	for _, line := range sink.all() {
		if strings.Contains(line, secret) {
			t.Errorf("the cleartext warning leaks the webhook credential: %q", line)
		}
	}
	if sink.count("--alert-webhook-url") == 0 && sink.count("https") == 0 {
		t.Errorf("the cleartext warning does not tell the operator what to change: %v", sink.all())
	}
}

// ── R88.3b: legitimate plaintext deployments stay quiet ──────────────────
// Silence here is the point of the exception: a loopback/Pod-local collector
// never puts the credential on a wire, and an https webhook is already
// encrypted. Warning on those would train the operator to ignore the warning.
func TestAttack_PlaintextWarningSparesLoopbackAndTLS(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
	}{
		{"loopback ipv4", "http://127.0.0.1:8088/hooks/T000/B000/TOKEN"},
		{"localhost name", "http://localhost:8088/hooks/T000/B000/TOKEN"},
		{"ipv6 loopback", "http://[::1]:8088/hooks/T000/B000/TOKEN"},
		{"https webhook", "https://hooks.slack.com/services/T000/B000/TOKEN"},
		{"empty (disabled)", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := newRound88WarnSink()
			prev := slog.Default()
			slog.SetDefault(slog.New(sink))
			defer slog.SetDefault(prev)

			_ = NewRouter(Config{WebhookURL: tc.url})
			if n := sink.count("cleartext") + sink.count("plain HTTP") + sink.count("PLAIN"); n > 0 {
				t.Errorf("spurious cleartext warning for %q: %v", tc.url, sink.all())
			}
		})
	}
}
