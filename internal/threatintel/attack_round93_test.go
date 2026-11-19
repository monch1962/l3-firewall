package threatintel

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ── R93.2: a whitespace-padded feed URL silently kills the refresh loop ────
//
// --threat-intel-url is a comma-separated list, and the natural spelling is
// "--threat-intel-url https://a/feed, https://b/feed". cmd/server trimmed each
// entry for the STARTUP fetch only, then handed the RAW split slice to
// StartRefresher. net/http cannot parse a URL with a leading space
// ("first path segment in URL cannot contain colon"), so every periodic
// refresh of every entry after the first failed forever: the startup log said
// "threat intel enabled", the blocklist loaded once, and no new intelligence
// was ever picked up again — the R40.4 silently-degraded-control class on the
// deny plane, with the failure only visible as one redacted warning per
// 30-minute cycle.
//
// The fix normalises at the source: the refresh path must accept the same
// strings the startup path accepts.
func TestAttack_RefresherUntrimmedURLStillRefreshes(t *testing.T) {
	feed := "203.0.113.7\n198.51.100.0/24\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, feed)
	}))
	defer srv.Close()

	bl := NewBlocklist()
	// Exactly what `strings.Split("https://a, https://b", ",")` yields for the
	// second entry — trailing newline included, as a templated flag value can.
	stop := bl.StartRefresher([]string{" " + srv.URL + "/feed\n"}, 100*time.Millisecond)
	if stop != nil {
		defer close(stop)
	}

	deadline := time.Now().Add(2 * time.Second)
	for bl.Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if bl.Len() == 0 {
		t.Fatal("refresher never loaded the feed: a whitespace-padded URL makes every refresh fail, so the deny plane never sees new threat intelligence")
	}
	if !bl.Contains("203.0.113.7") {
		t.Error("feed entry 203.0.113.7 not present after refresh")
	}
}

// A list whose entries are all blank must not spawn a goroutine that fails a
// doomed HTTP parse every interval for the life of the process (and must not
// be reported as an active refresher).
func TestAttack_AllBlankFeedListSpawnsNoRefresher(t *testing.T) {
	bl := NewBlocklist()
	stop := bl.StartRefresher([]string{"", "   ", "\t"}, 100*time.Millisecond)
	if stop != nil {
		close(stop)
		t.Error("StartRefresher returned a live stop channel for an all-blank URL list — a permanent failing fetch loop was started")
	}
}

// The single-URL entry point must tolerate the same padding: it is the
// function that turns a string into an HTTP request, so it is the last place
// the class can be closed for every caller.
func TestAttack_FetchFromURLTrimsWhitespace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "203.0.113.9\n")
	}))
	defer srv.Close()

	bl := NewBlocklist()
	n, err := bl.FetchFromURL("\t " + srv.URL + " \n")
	if err != nil {
		t.Fatalf("FetchFromURL with padded URL: %v", err)
	}
	if n != 1 || !bl.Contains("203.0.113.9") {
		t.Errorf("padding prevented the fetch: n=%d len=%d", n, bl.Len())
	}
}

// The flag-string parser is the one place the comma list is split, so the
// startup loop and the refresher cannot disagree about what the entries are.
func TestAttack_ParseURLListNormalisesEntries(t *testing.T) {
	got := ParseURLList(" https://a.example/feed , https://b.example/feed\n, ,")
	want := []string{"https://a.example/feed", "https://b.example/feed"}
	if len(got) != len(want) {
		t.Fatalf("ParseURLList = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}
	if l := ParseURLList("   "); l != nil {
		t.Errorf("ParseURLList(blank) = %q, want nil", l)
	}
}
