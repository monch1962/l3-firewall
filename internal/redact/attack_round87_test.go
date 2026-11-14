// Red-team security hardening Round 87 — URL redaction for log lines.
//
// Several operator-supplied URLs are bearer credentials:
//
//	--alert-webhook-url   https://hooks.slack.com/services/T…/B…/SECRET
//	--threat-intel-url    https://otx.alienvault.com/api/...?auth_key=SECRET
//
// Both were written verbatim to the log stream (startup lines and every failed
// delivery), so the credential landed in Docker/SIEM log storage where a
// different and larger set of readers can reach it. This package is the single
// place that turns a credential-bearing URL into a log-safe one — centralised
// rather than patched at each call site, because the R85 lesson is that a
// guard copied into two consumers drifts.
package redact

import (
	"strings"
	"testing"
)

// ── R87.2a: the redaction rule ───────────────────────────────────────────
// Keep scheme://host (that is what an operator needs to identify the endpoint),
// drop userinfo and the whole path/query/fragment (that is where every provider
// puts the credential). Input that does not parse as an absolute URL cannot be
// partially trusted, so it collapses to a bare marker — echoing an unparseable
// string risks echoing the secret itself.
func TestAttack_RedactedURLCannotCarryCredential(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "slack-style secret path",
			in:   "https://hooks.slack.com/services/T000/B000/SUPERSECRETTOKEN",
			want: "https://hooks.slack.com/…",
		},
		{
			name: "discord-style secret path",
			in:   "https://discord.com/api/webhooks/123456789/SUPERSECRETTOKEN",
			want: "https://discord.com/…",
		},
		{
			name: "userinfo credential",
			in:   "https://user:SUPERSECRETTOKEN@alerts.internal/hook",
			want: "https://alerts.internal/…",
		},
		{
			name: "query-string token",
			in:   "https://otx.alienvault.com/api/v1/indicators/export?auth_key=SUPERSECRETTOKEN",
			want: "https://otx.alienvault.com/…",
		},
		{
			name: "non-default port kept",
			in:   "http://127.0.0.1:9119/hooks/SUPERSECRETTOKEN",
			want: "http://127.0.0.1:9119/…",
		},
		{
			name: "host with no path stays",
			in:   "https://alerts.internal",
			want: "https://alerts.internal",
		},
		{
			name: "unparseable input must not echo the raw string",
			in:   "::not a url::/SUPERSECRETTOKEN",
			want: "…",
		},
		{
			name: "relative path is not an absolute URL",
			in:   "/hooks/SUPERSECRETTOKEN",
			want: "…",
		},
		{
			name: "empty stays empty",
			in:   "",
			want: "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := URL(c.in)
			if got != c.want {
				t.Errorf("URL(%q) = %q, want %q", c.in, got, c.want)
			}
			if strings.Contains(got, "SUPERSECRETTOKEN") {
				t.Errorf("URL(%q) = %q still contains the credential", c.in, got)
			}
		})
	}
}

// ── R87.2b: scrubbing a message that embeds the raw URL ──────────────────
// net/http folds the request URL into its error string, so a caller that logs
// err.Error() re-leaks what URL() just redacted. ScrubIn is the companion that
// rewrites every occurrence inside free text.
func TestAttack_MessageTextCannotReleakTheURL(t *testing.T) {
	const raw = "http://127.0.0.1:1/hooks/T000/B000/SUPERSECRETTOKEN"
	msg := `Post "` + raw + `": dial tcp 127.0.0.1:1: connect: connection refused`

	got := ScrubIn(msg, raw)
	if strings.Contains(got, "SUPERSECRETTOKEN") {
		t.Fatalf("ScrubIn left the credential in the message: %q", got)
	}
	if !strings.Contains(got, "127.0.0.1") {
		t.Errorf("ScrubIn destroyed the endpoint identifier: %q", got)
	}
	if !strings.Contains(got, "connection refused") {
		t.Errorf("ScrubIn destroyed the diagnostic: %q", got)
	}
	// A message that does not contain the URL is returned unchanged.
	plain := "dial tcp: i/o timeout"
	if out := ScrubIn(plain, raw); out != plain {
		t.Errorf("ScrubIn(%q) = %q, want unchanged", plain, out)
	}
	// An empty raw URL must not panic or mangle the message (strings.ReplaceAll
	// with an empty old value would insert the replacement between runes).
	if out := ScrubIn(plain, ""); out != plain {
		t.Errorf("ScrubIn with an empty URL = %q, want unchanged", out)
	}
}

// ── R87.2c: a comma-separated feed list keeps its cardinality ────────────
// --threat-intel-url takes a comma-separated list. Redacting the list as one
// URL would parse the second entry as part of the first URL's path and lose
// it, so an operator could no longer see HOW MANY feeds are configured — the
// difference between an empty list and a silently truncated one.
func TestAttack_URLListKeepsEveryFeedVisible(t *testing.T) {
	in := "https://a.example/feed?auth_key=SUPERSECRETTOKEN, https://b.example/feed?auth_key=SUPERSECRETTOKEN,"
	got := URLs(in)
	want := "https://a.example/…, https://b.example/…"
	if got != want {
		t.Errorf("URLs(%q) = %q, want %q", in, got, want)
	}
	if strings.Contains(got, "SUPERSECRETTOKEN") {
		t.Errorf("URLs(%q) leaked a credential: %q", in, got)
	}
	if e := URLs(""); e != "" {
		t.Errorf("URLs(\"\") = %q, want empty", e)
	}
}
