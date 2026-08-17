package threatintel

import (
	"strings"
	"testing"
)

// ── R54.2: overlong feed line must be skipped, not abort the parse ────
// parseReader uses bufio.Scanner with a 1MB token cap. A single feed line
// longer than 1MB makes scanner.Scan() return false with
// bufio.ErrTooLong, which aborts the ENTIRE parse: every entry after the
// pathological line is discarded and FetchFromURL returns an error. A
// malicious/compromised feed server (or a poisoned mirror of a legitimate
// feed — the operator-configurable URL is the trust boundary) needs only
// one 2MB line at the top of the response to permanently kill every
// refresh: new threats are silently never added until the feed changes.
// R8 capped the feed SIZE (50MB LimitReader) and R45 deduped repeated
// entries, but per-line robustness was never covered. An overlong line is
// not a plausible blocklist entry — skip it with a warning and keep
// parsing the rest.
func TestAttack_ParseReaderSkipsOverlongLine(t *testing.T) {
	bl := NewBlocklist()

	// 2MB single line — over the 1MB token cap.
	overlong := strings.Repeat("A", 2*1024*1024)
	input := overlong + "\n10.0.0.1\n10.0.0.2\n"

	count, err := bl.parseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("overlong line must be skipped, not abort the parse: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 valid entries after skipping the overlong line, got %d", count)
	}
	if !bl.Contains("10.0.0.1") || !bl.Contains("10.0.0.2") {
		t.Error("valid entries following the overlong line were not added")
	}
}

// ── R54.3: overlong line at EOF (no trailing newline) ──────────────────
// Same class with the pathological line as the LAST line of the feed:
// the drain path must handle a final line without a newline terminator.
func TestAttack_ParseReaderSkipsOverlongLineAtEOF(t *testing.T) {
	bl := NewBlocklist()

	overlong := strings.Repeat("B", 2*1024*1024)
	input := "10.0.0.9\n" + overlong // no trailing newline

	count, err := bl.parseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("overlong final line must be skipped, not abort the parse: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 valid entry before the overlong final line, got %d", count)
	}
	if !bl.Contains("10.0.0.9") {
		t.Error("valid entry before the overlong line was not added")
	}
}

// ── R54.4: normal multi-line feed still parses (regression) ────────────
func TestAttack_ParseReaderHealthyFeedRegression(t *testing.T) {
	bl := NewBlocklist()

	input := "# comment\n\n10.0.0.1\n10.0.0.0/24\n10.0.0.3\n"
	count, err := bl.parseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("healthy feed failed: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 entries from healthy feed, got %d", count)
	}
	if !bl.Contains("10.0.0.1") || !bl.Contains("10.0.0.3") || !bl.Contains("10.0.0.5") {
		t.Error("healthy feed entries not all added (10.0.0.5 tests the /24 network)")
	}
}
