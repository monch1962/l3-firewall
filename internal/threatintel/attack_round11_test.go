package threatintel

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// ── R11.3: SSRF via FetchFromURL redirect to internal service ─────
// Go's http.Client follows HTTP redirects by default (up to 10).
// A malicious blocklist feed could redirect to an internal service
// (e.g., cloud metadata endpoint, etcd API), potentially leaking data
// or causing unintended side effects from GET requests.
func TestAttack_FetchFromURLSSRFViaRedirect(t *testing.T) {
	// Simulate a malicious feed that redirects to a sensitive internal URL
	caught := false
	internalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If the client follows the redirect to this internal endpoint,
		// it proves SSRF is possible
		caught = true
		w.Write([]byte("10.0.0.1\n"))
	}))
	defer internalServer.Close()

	maliciousFeed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Redirect to an "internal" server
		w.Header().Set("Location", internalServer.URL)
		w.WriteHeader(http.StatusFound) // 302
	}))
	defer maliciousFeed.Close()

	bl := NewBlocklist()
	_, err := bl.FetchFromURL(maliciousFeed.URL)

	if err != nil {
		t.Logf("FetchFromURL rejected redirect: %v — SSRF blocked", err)
	} else if caught {
		t.Errorf("FetchFromURL followed redirect to %q — SSRF vulnerability! "+
			"Should block redirects to non-feed URLs or disable following redirects",
			internalServer.URL)
	} else {
		t.Log("FetchFromURL did not follow the redirect (internal server not reached)")
	}
}

// ── R11.4: Add silently fails after cap is reached ─────────────────
// Once maxBlocklistEntries is reached, Add() silently drops entries.
// The count returned from FetchFromURL is misleading — it reports
// entries parsed from the feed, not entries actually added.
func TestAttack_AddSilentlyFailsAfterCap(t *testing.T) {
	bl := NewBlocklist()

	// Fill to just below the cap with unique entries
	for i := 0; i < maxBlocklistEntries; i++ {
		a := i / 65536
		b := (i / 256) % 256
		c := i % 256
		bl.Add("10." + itoa(a) + "." + itoa(b) + "." + itoa(c))
	}

	if bl.Len() != maxBlocklistEntries {
		t.Fatalf("expected %d entries at cap, got %d", maxBlocklistEntries, bl.Len())
	}

	// Adding beyond the cap silently drops entries
	bl.Add("192.168.1.1")
	if bl.Contains("192.168.1.1") {
		t.Error("192.168.1.1 was added despite cap being full")
	} else {
		t.Logf("Add beyond cap silently dropped entry 192.168.1.1 (len=%d)", bl.Len())
	}

	// Also test with CIDR
	bl.Add("10.0.0.0/8")
	if bl.Len() > maxBlocklistEntries {
		t.Errorf("CIDR added beyond cap — len=%d exceeds max=%d", bl.Len(), maxBlocklistEntries)
	}
	t.Logf("Add beyond cap: len=%d, max=%d — entries silently dropped", bl.Len(), maxBlocklistEntries)
}

// ── R11.5: Remove with IP that has multiple CIDR matches ────────────
// R11 documented that duplicate identical CIDRs could exist in the nets
// slice (added from two feed sources) and Remove took out only the first.
// R45 eliminated the precondition: Add() now dedups CIDRs on canonical
// form, so duplicates can never accumulate — this test asserts the fixed
// invariant (one entry, fully removable) instead of the old behavior.
func TestAttack_RemoveDuplicateCIDRs(t *testing.T) {
	bl := NewBlocklist()

	// Add the same CIDR twice (e.g., from two different feed sources) —
	// R45 dedup collapses this to a single entry
	bl.Add("10.0.0.0/8")
	bl.Add("10.0.0.0/8")

	if bl.Len() != 1 {
		t.Fatalf("expected 1 entry (CIDR duplicates deduped), got %d", bl.Len())
	}

	// Remove removes the single entry entirely
	bl.Remove("10.0.0.0/8")

	if bl.Len() != 0 {
		t.Errorf("expected 0 entries after removing the deduped CIDR, got %d", bl.Len())
	}

	// Contains must no longer match — the network is fully gone
	if bl.Contains("10.0.0.1") {
		t.Error("Contains('10.0.0.1') should be false after removal")
	}
}

// ── R11.6: FetchFromURL with empty response body ───────────────────
// An empty blocklist feed (no entries, just empty response) should not
// cause errors or add entries.
func TestAttack_FetchFromURLEmptyResponse(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantErr  bool
		wantNew  int
	}{
		{"empty body", "", false, 0},
		{"whitespace only", "\n\n\n", false, 0},
		{"comments only", "# comment\n# another\n", false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tt.body))
			}))
			defer server.Close()

			bl := NewBlocklist()
			count, err := bl.FetchFromURL(server.URL)

			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if count != tt.wantNew {
				t.Errorf("got %d new entries, want %d", count, tt.wantNew)
			}
		})
	}
}
