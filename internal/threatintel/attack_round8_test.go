package threatintel

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── R8.18: No response body size limit in FetchFromURL ────────────────
// A malicious feed server sends a large response body. FetchFromURL
// reads it all into memory via parseReader without any io.LimitReader.
// The fix wraps resp.Body with io.LimitReader to cap memory usage.
func TestAttack_FetchFromURLNoBodySizeLimit(t *testing.T) {
	// Serve a large response (about 100MB)
	largeBody := strings.Repeat("10.0.0.1\n", 10*1024*1024) // ~100MB
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(largeBody))
	}))
	defer server.Close()

	bl := NewBlocklist()
	done := make(chan struct{})
	var fetchCount int
	var fetchErr error
	go func() {
		fetchCount, fetchErr = bl.FetchFromURL(server.URL)
		close(done)
	}()

	select {
	case <-done:
		if fetchErr != nil {
			t.Logf("FetchFromURL correctly rejected large response: %v", fetchErr)
			return
		}
		// LimitReader stops at maxFeedResponseSize, so we expect bounded entries
		if fetchCount >= 10*1024*1024 {
			t.Errorf("FetchFromURL loaded all %d entries from ~100MB response — no size limit enforced", fetchCount)
		} else {
			t.Logf("FetchFromURL loaded %d entries (limited by size cap) — body size limit enforced", fetchCount)
		}
	case <-time.After(10 * time.Second):
		t.Error("FetchFromURL hung on large response — needs io.LimitReader")
	}
}

// ── R8.19: Blocklist memory growth across refreshes ───────────────────
// Each refresh cycle calls FetchFromURL which adds entries via Add().
// Old entries are never removed. Over many refresh cycles, the blocklist
// grows monotonically until maxBlocklistEntries is reached.
func TestAttack_RefreshMemoryGrowth(t *testing.T) {
	bl := NewBlocklist()

	const cycles = 10
	const entriesPerCycle = 10000

	for cycle := 0; cycle < cycles; cycle++ {
		for i := 0; i < entriesPerCycle; i++ {
			ip := "10.0." + itoa(cycle) + "." + itoa(i)
			bl.Add(ip)
		}
	}

	count := bl.Len()
	t.Logf("Blocklist has %d entries after %d cycles (no auto-pruning — grows monotonically)", count, cycles)

	// Add another cycle — should be capped by maxBlocklistEntries
	for i := 0; i < 20000; i++ {
		bl.Add("192.168." + itoa(i/256) + "." + itoa(i%256))
	}
	finalCount := bl.Len()
	t.Logf("Blocklist has %d entries after exceeding maxBlocklistEntries cap", finalCount)
	if finalCount > maxBlocklistEntries+100 {
		t.Errorf("Blocklist grew to %d — exceeds maxBlocklistEntries cap (%d)", finalCount, maxBlocklistEntries)
	}
}

// ── R8.20: Remove from empty blocklist ────────────────────────────────
// Calling Remove on an empty blocklist should not crash.
func TestAttack_RemoveFromEmptyBlocklist(t *testing.T) {
	bl := NewBlocklist()

	recovered := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				recovered = true
			}
		}()
		bl.Remove("10.0.0.1")
		bl.Remove("192.168.0.0/16")
		bl.Remove("")
	}()

	if recovered {
		t.Error("Remove from empty blocklist panicked")
	}
}

// ── R8.21: Add with excessive duplicates ──────────────────────────────
// Adding the same entry many times should not cause map growth (map keys
// are unique, so this is safe by design).
func TestAttack_AddDuplicateExcessive(t *testing.T) {
	bl := NewBlocklist()

	for i := 0; i < 100000; i++ {
		bl.Add("10.0.0.1")
	}

	if bl.Len() != 1 {
		t.Errorf("expected 1 unique entry after 100K duplicate adds, got %d", bl.Len())
	}
}

// ── R8.22: Concurrent FetchFromURL and Contains ───────────────────────
// Fetching from URL while checking Contains should not race (mutex safe).
func TestAttack_ConcurrentFetchAndCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 1000; i++ {
			w.Write([]byte("10.0.0." + itoa(i) + "\n"))
		}
	}))
	defer server.Close()

	bl := NewBlocklist()
	bl.Add("10.0.0.1")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := bl.FetchFromURL(server.URL)
		if err != nil {
			t.Errorf("FetchFromURL: %v", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			bl.Contains("10.0.0.1")
			bl.Contains("192.168.0.1")
		}
	}()

	wg.Wait()
}

// ── R8.23: StartRefresher with single-entry URL race ──────────────────
// Fast refresh cycle on a single-entry URL should not cause issues.
func TestAttack_FastRefreshCycle(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("10.0.0.1\n"))
	}))
	defer server.Close()

	bl := NewBlocklist()
	stopCh := bl.StartRefresher([]string{server.URL}, 10*time.Millisecond)

	time.Sleep(100 * time.Millisecond)
	close(stopCh)

	count := bl.Len()
	t.Logf("Blocklist has %d entries after fast refresh cycles", count)
}

// ── R8.24: Add with URL-encoded IPv4 notation ─────────────────────────
// Some threat feeds use URL-encoded or oddly formatted IPs.
func TestAttack_AddURLEncodedIP(t *testing.T) {
	bl := NewBlocklist()

	// URL-encoded IP (should not parse as valid)
	bl.Add("10%2E0%2E0%2E1")
	// Octal notation
	bl.Add("012.0.0.1")
	// Leading zeros
	bl.Add("010.000.000.001")

	if bl.Contains("10.0.0.1") {
		t.Log("URL-encoded or octal IPs should not resolve to 10.0.0.1")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}
	result := ""
	for n > 0 {
		result = digits[n%10] + result
		n /= 10
	}
	return result
}
