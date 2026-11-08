package threatintel

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ── R82.1: one feed line blackholes an entire address family ─────────
// net.ParseCIDR canonicalises an IPv4-mapped IPv6 network onto its 4-byte
// equivalent: "::ffff:0:0/96" — the spelling used by real blocklists to
// mean "the IPv4-mapped space" — becomes "0.0.0.0/0". Contains()
// normalises every IPv4 source with To4(), so IPNet.Contains compares the
// masked 4-byte tail and every IPv4 address matches: ONE line in a threat
// feed hard-blocks 100% of IPv4 traffic (the R79.1 whole-family
// false-block class, on the threat-intel plane). A whole-family entry is
// never threat intelligence and must be rejected, not stored.
func TestAttack_MappedSpaceEntryBlackholesAllIPv4(t *testing.T) {
	bl := NewBlocklist()
	bl.Add("::ffff:0:0/96")

	for _, ip := range []string{"8.8.8.8", "1.2.3.4", "203.0.113.9", "192.0.2.55"} {
		if bl.Contains(ip) {
			t.Errorf("Contains(%q) = true after adding the mapped-space entry ::ffff:0:0/96 — "+
				"a single feed line blackholed the entire IPv4 plane", ip)
		}
	}
	if got := bl.Len(); got != 0 {
		t.Errorf("Len() = %d after adding a whole-family entry, want 0 (entry must be rejected)", got)
	}
}

// ── R82.2: explicit whole-family entries are rejected too ────────────
// "0.0.0.0/0" and "::/0" assert "every address of a family is hostile".
// No threat-intel entry can mean that, and one such line silently turns
// the deny plane into deny-all. Visible-to-the-operator or not, the
// blocklist refuses the degenerate shape; a firewall-wide block belongs
// in the policy, where it is explicit and auditable.
func TestAttack_WholeFamilyEntryRejected(t *testing.T) {
	bl := NewBlocklist()
	bl.Add("0.0.0.0/0")
	bl.Add("::/0")

	if bl.Contains("8.8.8.8") {
		t.Error("Contains(8.8.8.8) = true after adding 0.0.0.0/0 — whole-family entry stored")
	}
	if bl.Contains("2001:db8::1") {
		t.Error("Contains(2001:db8::1) = true after adding ::/0 — whole-family entry stored")
	}
	if got := bl.Len(); got != 0 {
		t.Errorf("Len() = %d after two whole-family entries, want 0", got)
	}

	// Regression: a legitimate broad-but-bounded range is still accepted —
	// the guard rejects only the degenerate whole-family shape.
	bl.Add("128.0.0.0/1")
	if !bl.Contains("200.1.2.3") {
		t.Error("Contains(200.1.2.3) = false after adding 128.0.0.0/1 — real /1 range must still be stored")
	}
}

// ── R82.3: mapped entries that DO name IPv4 addresses still work ─────
// The guard must be surgical: ::ffff:a.b.c.d/(96+N) is the faithful mapped
// spelling of a.b.c.d/N and existing feeds/tests rely on it (R10, R45).
func TestAttack_MappedFormStillMapsFaithfully(t *testing.T) {
	bl := NewBlocklist()
	bl.Add("::ffff:10.0.0.0/120") // == 10.0.0.0/24
	if !bl.Contains("10.0.0.9") {
		t.Error("Contains(10.0.0.9) = false — ::ffff:10.0.0.0/120 must still block 10.0.0.0/24")
	}
	if bl.Contains("10.0.1.9") {
		t.Error("Contains(10.0.1.9) = true — ::ffff:10.0.0.0/120 must not widen past 10.0.0.0/24")
	}

	bl2 := NewBlocklist()
	bl2.Add("::ffff:10.0.0.0/104") // == 10.0.0.0/8
	if !bl2.Contains("10.200.1.1") {
		t.Error("Contains(10.200.1.1) = false — ::ffff:10.0.0.0/104 must still block 10.0.0.0/8")
	}
}

// ── R82.4: the poison line is reachable through the feed path ────────
// The threat model is a malicious/compromised feed server (R54/R58): one
// line in the response body. The poison entry must be dropped WITHOUT
// aborting the parse — the benign entries in the same response still load.
func TestAttack_FeedPathPoisonLineRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "# threat feed\n")
		fmt.Fprint(w, "::ffff:0:0/96\n") // poison: the whole IPv4 plane
		fmt.Fprint(w, "203.0.113.66\n")
		fmt.Fprint(w, "198.51.100.0/24\n")
	}))
	defer server.Close()

	bl := NewBlocklist()
	n, err := bl.FetchFromURL(server.URL)
	if err != nil {
		t.Fatalf("FetchFromURL: %v", err)
	}

	if bl.Contains("8.8.8.8") {
		t.Error("8.8.8.8 blocked after a feed served ::ffff:0:0/96 — one line blackholed all IPv4")
	}
	if !bl.Contains("203.0.113.66") {
		t.Error("203.0.113.66 not blocked — the poison line aborted the rest of the feed")
	}
	if !bl.Contains("198.51.100.7") {
		t.Error("198.51.100.7 not blocked — the poison line aborted the rest of the feed")
	}
	if n != 2 {
		t.Errorf("FetchFromURL counted %d entries, want 2 (the rejected poison line must not be counted)", n)
	}
}

// ── R82.5: cap exhaustion must be observable, not silent ─────────────
// R11.4 documented (t.Log) that Add drops every entry once
// maxBlocklistEntries is reached. Left unfixed, the deny plane silently
// stops consuming NEW threat intelligence forever — a compromised feed
// that fills the cap with junk permanently disables every later
// discovery, while FetchFromURL keeps reporting a healthy entry count
// (R40.4 "silently dropped control"). R82 makes Add report whether the
// entry was stored and logs the transition once, so the count is honest
// and the operator gets a signal.
func TestAttack_CapExhaustionIsObservable(t *testing.T) {
	bl := NewBlocklist()
	for i := 0; i < maxBlocklistEntries; i++ {
		bl.Add(fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256))
	}
	if got := bl.Len(); got != maxBlocklistEntries {
		t.Fatalf("expected %d entries at cap, got %d", maxBlocklistEntries, got)
	}

	if added := bl.Add("203.0.113.7"); added {
		t.Error("Add reported success at cap — the caller cannot detect that a new threat was dropped")
	}
	if bl.Contains("203.0.113.7") {
		t.Error("203.0.113.7 stored despite the cap")
	}

	// The feed path must report the truth: a refresh that adds nothing
	// reports 0, not the number of lines it parsed.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "203.0.113.7\n203.0.113.8\n")
	}))
	defer server.Close()
	n, err := bl.FetchFromURL(server.URL)
	if err != nil {
		t.Fatalf("FetchFromURL: %v", err)
	}
	if n != 0 {
		t.Errorf("FetchFromURL reported %d new entries at cap, want 0 (honest count)", n)
	}
}

// ── R82.6: dedup is not "added" ─────────────────────────────────────
// A re-fetch of an unchanged feed adds nothing; the count must say so.
func TestAttack_RefreshCountHonestForDuplicates(t *testing.T) {
	bl := NewBlocklist()
	if added := bl.Add("203.0.113.7"); !added {
		t.Error("Add reported a new entry as not added")
	}
	if added := bl.Add("203.0.113.7"); added {
		t.Error("Add reported a duplicate as added — the refresh count would overstate new intelligence")
	}
	if added := bl.Add("203.0.113.8"); !added {
		t.Error("Add reported a new entry as not added")
	}
}
