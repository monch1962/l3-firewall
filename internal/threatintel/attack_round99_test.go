// Red-team security hardening Round 99 — the deny plane's entry lifecycle.
//
// R98 taught Blocklist.Add to strip the Unicode FORMAT class (Cf: BOM, ZWSP,
// ZWNJ/ZWJ, bidi overrides) at the single ingest point, so an indicator hidden
// behind an invisible character is still stored. Add therefore accepts a
// spelling net.ParseIP would reject, and stores its canonical form:
//
//	Add("203.0.113.7\uFEFF")  →  stored as "203.0.113.7"
//
// Remove — the OTHER mutation of the same key space — was not given the same
// transform. It hands the raw string to net.ParseIP, which fails, so the entry
// survives. The result is an asymmetric key space: an entry ingested from a
// BOM/ZWSP-prefixed feed line (routine for feeds written by Windows tooling
// and some exporters, R98) can never be removed using the same spelling the
// feed supplied. R41 fixed exactly this asymmetry for IPv4-mapped forms
// ("Add/Contains are fixed but Remove is forgotten"); R98 re-introduced it for
// the Cf class, one round later, in the same package.
//
// Remove has no production caller today (the documented dead-API finding), so
// this is a correctness/future-proofing defect rather than a live bypass — but
// the project's own rule is that every method that parses an entry normalises
// it identically (R41), because the first caller to wire Remove inherits the
// bug silently.
package threatintel

import "testing"

// ── R99.5: Remove must accept the same spellings Add accepts ──────────────
func TestAttack_RemoveMustNormaliseLikeAdd(t *testing.T) {
	// Zero-width space, BOM, ZWNJ — three Cf characters a feed can carry.
	for _, cf := range []string{"\u200B", "\uFEFF", "\u200C"} {
		bl := NewBlocklist()
		// Add strips the Cf class (R98) — the entry is effectively present.
		if !bl.Add("203.0.113.7" + cf) {
			t.Fatalf("Add(%q) did not store the entry — R98's Cf strip is not in place", "203.0.113.7"+cf)
		}
		if !bl.Contains("203.0.113.7") {
			t.Fatalf("Contains() does not see the entry Add stored (cf=%q)", cf)
		}
		// Remove must undo the same spelling.
		bl.Remove("203.0.113.7" + cf)
		if bl.Len() != 0 {
			t.Errorf("Remove(%q) left %d entries: Add normalised the Cf character away but Remove did not, so an indicator ingested from a BOM/ZWSP-prefixed feed line can never be removed with the spelling the feed supplied (R41 Add/Remove consistency, applied to the R98 Cf class)",
				"203.0.113.7"+cf, bl.Len())
		}
	}

	// The same asymmetry on the CIDR branch.
	bl := NewBlocklist()
	if !bl.Add("198.51.100.0/24\u200B") {
		t.Fatal("Add of a Cf-suffixed CIDR was rejected — R98's Cf strip is not in place for CIDRs")
	}
	bl.Remove("198.51.100.0/24\u200B")
	if bl.Len() != 0 {
		t.Errorf("Remove of a Cf-suffixed CIDR left %d entries; the delete branch must share Add's normalisation", bl.Len())
	}
}
