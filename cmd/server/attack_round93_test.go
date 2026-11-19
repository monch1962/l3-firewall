package main

import (
	"os"
	"strings"
	"testing"

	"github.com/monch1962/l3-firewall/internal/threatintel"
)

// ── R93.2 (cmd/server wiring): one normalised list feeds both paths ────────
//
// The vulnerability was a WIRING divergence, not a bug in either half: the
// startup loop trimmed each entry of --threat-intel-url, and the raw split
// slice went to StartRefresher. With the natural spelling
// "--threat-intel-url https://a/feed, https://b/feed" the second entry keeps
// its leading space, so every periodic refresh failed forever while the
// startup log said "threat intel enabled" — the deny plane silently stopped
// consuming new intelligence.
//
// The fix makes main() parse the flag ONCE into a normalised list and hand the
// SAME slice to the startup fetch and to the refresher. The behaviour of the
// parser is covered in internal/threatintel; this test pins the wiring, which
// is the half that can silently regress.
func TestAttack_ThreatIntelURLListIsParsedOnceAndShared(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}
	body := string(src)

	// The flag value must be parsed by the shared helper...
	if !strings.Contains(body, "threatintel.ParseURLList(*threatIntelURL)") {
		t.Error("main.go does not parse --threat-intel-url with threatintel.ParseURLList: the startup fetch and the refresher can disagree about the entries again")
	}
	// ...and no longer split inline, which is the shape that produced the drift.
	if strings.Contains(body, "strings.Split(*threatIntelURL") {
		t.Error("main.go splits --threat-intel-url inline instead of using threatintel.ParseURLList — the raw entries would reach StartRefresher untrimmed")
	}
	// The same `urls` slice must drive both consumers.
	if !strings.Contains(body, "bl.StartRefresher(urls,") {
		t.Error("main.go does not pass the parsed url slice to StartRefresher")
	}

	// End-to-end shape of the value that list carries, including the padding
	// a templated flag expansion introduces.
	got := threatintel.ParseURLList(" https://a.example/feed ,https://b.example/feed\n")
	if len(got) != 2 {
		t.Fatalf("ParseURLList = %q, want 2 entries", got)
	}
	for _, u := range got {
		if strings.TrimSpace(u) != u {
			t.Errorf("parsed entry %q still carries padding — the refresher would fail on it", u)
		}
	}
}
