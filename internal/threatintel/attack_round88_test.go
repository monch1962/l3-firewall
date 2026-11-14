// Red-team security hardening Round 88 — the refresher path re-leaks the feed
// credential that R87 redacted at startup.
//
// R87 established the classification: a threat-intel feed URL is a BEARER
// CREDENTIAL — most commercial and community feeds authenticate with a query
// string (`?auth_key=…`, `?api_key=…`) and possession of the URL is enough to
// pull the feed. R87 therefore redacted the STARTUP lines in cmd/server.
//
// But the startup fetch is the least-exercised path. The long-running one is
// Blocklist.StartRefresher: a goroutine that re-fetches every configured feed
// on an interval (30 minutes in the shipped binary) and logs, for the life of
// the process,
//
//	threat intel refreshed   url=<RAW FEED URL> entries=N
//	threat intel refresh failed  url=<RAW FEED URL> error=<err>
//
// and the error text itself embeds the URL twice — FetchFromURL wraps it
// ("fetching blocklist %s: %w", "blocklist %s returned status %d") and
// net/http repeats it inside its own *url.Error. So the credential reaches the
// log stream on every tick, in both the success and failure branches, and an
// operator who fixes only the one-shot startup line believes the leak is
// closed.
//
// This is the R85 fix-propagation lesson applied to logging: the guard was
// installed at one consumer (cmd/server) while the producer (internal/
// threatintel) kept printing the same secret from its own goroutine.
package threatintel

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

// round88Sink records every record written through slog's default logger, as
// "message key=value key=value…", so a test can assert on what actually
// reached the log stream.
type round88Sink struct {
	mu    sync.Mutex
	lines []string
}

func (s *round88Sink) Enabled(context.Context, slog.Level) bool { return true }

func (s *round88Sink) Handle(_ context.Context, r slog.Record) error {
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
	s.mu.Lock()
	s.lines = append(s.lines, line)
	s.mu.Unlock()
	return nil
}

func (s *round88Sink) WithAttrs([]slog.Attr) slog.Handler { return s }
func (s *round88Sink) WithGroup(string) slog.Handler      { return s }

func (s *round88Sink) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.lines...)
}

func (s *round88Sink) count(substr string) int {
	n := 0
	for _, l := range s.snapshot() {
		if strings.Contains(l, substr) {
			n++
		}
	}
	return n
}

// ── R88.1: the refresher must not log the feed credential ────────────────
// Attacker model: anyone who can read the firewall's log stream (container log
// driver, hosted log service, SIEM index, support bundle), or who can simply
// wait for the next refresh tick, obtains a URL that pulls the operator's paid
// or private threat feed — and, on feeds that are writable, can poison it.
func TestAttack_RefresherLogsFeedURLCredential(t *testing.T) {
	const secret = "ROUND88REFRESHSECRET"

	okFeed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("10.0.0.1\n"))
	}))
	defer okFeed.Close()

	// The failure branch is the worse one: the error text embeds the URL.
	badFeed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer badFeed.Close()

	okURL := okFeed.URL + "/feed?auth_key=" + secret
	badURL := badFeed.URL + "/feed?auth_key=" + secret

	sink := &round88Sink{}
	prev := slog.Default()
	slog.SetDefault(slog.New(sink))
	t.Cleanup(func() { slog.SetDefault(prev) })

	bl := NewBlocklist()
	stop := bl.StartRefresher([]string{okURL, badURL}, 100*time.Millisecond)
	defer close(stop)

	// Wait until BOTH branches have logged, so the assertion below cannot pass
	// vacuously on a ticker that never fired.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if sink.count("threat intel refreshed") > 0 && sink.count("threat intel refresh failed") > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if sink.count("threat intel refreshed") == 0 {
		t.Fatal("refresher never logged a successful refresh — test would be vacuous")
	}
	if sink.count("threat intel refresh failed") == 0 {
		t.Fatal("refresher never logged a failed refresh — test would be vacuous")
	}

	for _, line := range sink.snapshot() {
		if strings.Contains(line, secret) {
			t.Errorf("refresher log line leaks the feed credential: %q", line)
		}
	}

	// Positive property: the operator must still be able to tell WHICH feed
	// failed and that entries were loaded — redaction must not erase the
	// diagnostic.
	var sawHost, sawCount bool
	for _, line := range sink.snapshot() {
		if strings.Contains(line, "threat intel refreshed") {
			sawHost = sawHost || strings.Contains(line, strings.TrimPrefix(okFeed.URL, "http://"))
			sawCount = sawCount || strings.Contains(line, "entries=1")
		}
	}
	if !sawHost {
		t.Error("redacted refresh line no longer identifies the feed endpoint (scheme+host must survive)")
	}
	if !sawCount {
		t.Error("redacted refresh line lost the entries count — an operator cannot tell the feed is still delivering threats")
	}
}
