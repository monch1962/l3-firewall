// Red-team security hardening Round 98 — threat-intel feed ingestion: a
// byte-order mark silently dropped the first indicator.
//
// parseReader trims each line with strings.TrimSpace, which removes Unicode
// White_Space but NOT U+FEFF (ZERO WIDTH NO-BREAK SPACE / BOM — it is listed
// under Cf, not Zs). A feed whose first line carries a UTF-8 BOM — routine for
// files produced by Windows tooling, some editors, and several
// threat-intel exporters — therefore yields the line "\ufeff203.0.113.7",
// which net.ParseIP rejects: the FIRST indicator of every refresh is dropped
// with no warning and the refresh still reports a healthy count. A
// compromised feed can use the same shape to hide one specific indicator per
// cycle while every other line loads (the R82.2 silently-dropped-control
// class on the deny plane).
package threatintel

import (
	"strings"
	"testing"
)

// ── R98.6: a BOM must not cost the first indicator ──────────────────────
func TestAttack_FeedBOMMustNotDropFirstEntry(t *testing.T) {
	feed := "\ufeff203.0.113.7\n198.51.100.9\n# comment\n192.0.2.5\n"
	bl := NewBlocklist()
	n, err := bl.parseReader(strings.NewReader(feed))
	if err != nil {
		t.Fatalf("parseReader: %v", err)
	}
	if n != 3 {
		t.Errorf("stored %d entries from a 3-entry feed — the BOM-prefixed first line was dropped silently", n)
	}
	if !bl.Contains("203.0.113.7") {
		t.Errorf("the first indicator (BOM-prefixed) is NOT blocked: the deny plane silently lost a real threat entry")
	}
	for _, ip := range []string{"198.51.100.9", "192.0.2.5"} {
		if !bl.Contains(ip) {
			t.Errorf("regression: %s from the same feed is not blocked", ip)
		}
	}
}

// A BOM can also appear mid-stream: replicas of one feed are routinely
// concatenated, and each copy starts with its own BOM.
func TestAttack_FeedMidStreamBOMStillParses(t *testing.T) {
	bl := NewBlocklist()
	n, err := bl.parseReader(strings.NewReader("203.0.113.7\n\ufeff198.51.100.9\n"))
	if err != nil {
		t.Fatalf("parseReader: %v", err)
	}
	if n != 2 || !bl.Contains("198.51.100.9") {
		t.Errorf("stored %d entries, Contains(198.51.100.9)=%v — a mid-stream BOM dropped the entry", n, bl.Contains("198.51.100.9"))
	}
}
