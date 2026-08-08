package threatintel

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ── R45.1: CIDR duplicate accumulation across refreshes ──────────────
// Add() dedups exact IPs via map keys but appends CIDRs to the nets
// slice with no dedup. StartRefresher re-fetches the same feed every
// interval; a feed whose CIDR list is stable re-adds every CIDR each
// cycle, growing the nets slice monotonically until maxBlocklistEntries
// is hit. After that the cap is full of DUPLICATES and newly discovered
// malicious IPs from the feed are silently dropped — the blocklist stops
// updating (security control bypass). Contains() also does an O(n) scan
// over nets per packet, so 500k duplicate CIDRs mean every hot-path
// packet check scans 500k entries (CPU amplification).
func TestAttack_CIDRDuplicatesAccumulateAcrossRefreshes(t *testing.T) {
	bl := NewBlocklist()

	// Feed with a stable CIDR list (10 networks)
	const feedCIDRs = 10
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < feedCIDRs; i++ {
			fmt.Fprintf(w, "10.%d.0.0/16\n", i)
		}
	}))
	defer server.Close()

	// Simulate 3 refresh cycles of the same feed (StartRefresher calls
	// FetchFromURL repeatedly; entries are never cleared between cycles)
	for cycle := 0; cycle < 3; cycle++ {
		if _, err := bl.FetchFromURL(server.URL); err != nil {
			t.Fatalf("cycle %d: FetchFromURL: %v", cycle, err)
		}
	}

	if got := bl.Len(); got != feedCIDRs {
		t.Errorf("after 3 refreshes of a %d-CIDR feed, expected %d unique entries, got %d (duplicates accumulated)",
			feedCIDRs, feedCIDRs, got)
	}
}

// ── R45.2: CIDR duplicates must not exhaust the cap ───────────────────
// The cap check (len(ips)+len(nets) >= maxBlocklistEntries) must count
// UNIQUE entries. Pre-fix, duplicate CIDRs appended to the nets slice
// filled the cap with one network repeated maxBlocklistEntries times and
// every subsequent legitimate entry (a newly discovered malicious IP) was
// silently dropped by Add(). With R45 dedup, the same CIDR added
// maxBlocklistEntries times occupies exactly one slot.
func TestAttack_CIDRDuplicatesExhaustCapBlockingNewThreats(t *testing.T) {
	bl := NewBlocklist()

	// Add the same CIDR up to the cap limit — dedup must keep it to 1
	for i := 0; i < maxBlocklistEntries; i++ {
		bl.Add("10.0.0.0/8")
	}

	if bl.Len() != 1 {
		t.Fatalf("expected 1 unique entry after %d duplicate adds, got %d",
			maxBlocklistEntries, bl.Len())
	}

	// A NEW threat IP must still be addable — the cap represents unique
	// entries, not duplicates
	bl.Add("192.168.1.1")
	if !bl.Contains("192.168.1.1") {
		t.Errorf("new threat 192.168.1.1 dropped: cap exhausted by %d duplicates of a single CIDR",
			maxBlocklistEntries)
	}
}

// ── R45.3: Distinct CIDRs must still dedup by canonical form ─────────
// Regression guard: dedup must not break distinct networks, and must
// normalize equivalent spellings of the same CIDR (verified with go run:
// "10.0.0.0/08" and "::ffff:10.0.0.0/104" both canonicalize to
// "10.0.0.0/8" via ParseCIDR, while "010.0.0.0/8" is rejected by the
// parser and never added).
func TestAttack_CIDRDedupPreservesDistinctNetworks(t *testing.T) {
	bl := NewBlocklist()
	bl.Add("10.0.0.0/8")
	bl.Add("10.0.0.0/8")          // exact duplicate
	bl.Add("10.0.0.0/08")         // equivalent spelling — canonicalizes
	bl.Add("::ffff:10.0.0.0/104") // IPv4-mapped alias — canonicalizes
	bl.Add("192.168.0.0/16")

	if got := bl.Len(); got != 2 {
		t.Errorf("expected 2 distinct networks after duplicate/alias adds, got %d", got)
	}
	if !bl.Contains("10.1.2.3") {
		t.Error("Contains(10.1.2.3) should be true — network still present")
	}
	if !bl.Contains("192.168.5.5") {
		t.Error("Contains(192.168.5.5) should be true — network still present")
	}
}
