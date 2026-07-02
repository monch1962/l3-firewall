package l2filter

import (
	"strings"
	"sync"
	"testing"
)

// ── R9.5: Unicode whitespace bypasses MAC normalization ─────────────────
// normalizeMAC replaces only ASCII space (0x20), but not Unicode whitespace
// like NBSP (U+00A0), thin space (U+2009), ideographic space (U+3000), etc.
// An attacker can use these to bypass MAC filtering.
func TestAttack_UnicodeWhitespaceBypassInNormalizeMAC(t *testing.T) {
	// Set up a filter with a blocked MAC
	f := NewFilter(Config{
		BlockedMACs: []string{"aa:bb:cc:dd:ee:ff"},
	})

	// Without unicode whitespace, this MAC should be blocked
	if ok, _ := f.MACAllowed("aa:bb:cc:dd:ee:ff"); ok {
		t.Fatal("setup failed: blocked MAC was not blocked")
	}

	// Try various unicode whitespace characters that could bypass normalization
	unicodeWhitespaceInputs := []struct {
		name string
		mac  string
	}{
		{"NBSP (U+00A0)", "aa:bb:cc:dd:ee:\u00a0ff"},
		{"thin space (U+2009)", "aa:bb:cc:dd:ee:\u2009ff"},
		{"ideographic space (U+3000)", "aa:bb:cc:dd:ee:\u3000ff"},
		{"en quad (U+2000)", "aa:bb:cc:dd:ee:\u2000ff"},
		{"em quad (U+2001)", "aa:bb:cc:dd:ee:\u2001ff"},
		{"en space (U+2002)", "aa:bb:cc:dd:ee:\u2002ff"},
		{"em space (U+2003)", "aa:bb:cc:dd:ee:\u2003ff"},
		{"three-per-em (U+2004)", "aa:bb:cc:dd:ee:\u2004ff"},
		{"four-per-em (U+2005)", "aa:bb:cc:dd:ee:\u2005ff"},
		{"six-per-em (U+2006)", "aa:bb:cc:dd:ee:\u2006ff"},
		{"figure space (U+2007)", "aa:bb:cc:dd:ee:\u2007ff"},
		{"punctuation space (U+2008)", "aa:bb:cc:dd:ee:\u2008ff"},
		{"hair space (U+200A)", "aa:bb:cc:dd:ee:\u200Aff"},
		{"narrow NBSP (U+202F)", "aa:bb:cc:dd:ee:\u202fff"},
		{"medium math space (U+205F)", "aa:bb:cc:dd:ee:\u205fff"},
		{"ogham (U+1680)", "aa:bb:cc:dd:ee:\u1680ff"},
	}

	for _, tt := range unicodeWhitespaceInputs {
		t.Run(tt.name, func(t *testing.T) {
			norm := normalizeMAC(tt.mac)
			expected := "aabbccddeeff"
			if norm == expected {
				t.Logf("normalizeMAC(%q) = %q — correctly normalized to blocked form", tt.mac, norm)
			} else {
				t.Errorf("normalizeMAC(%q) = %q — unicode whitespace prevents normalization, bypassing blocklist", tt.mac, norm)
			}
		})
	}
}

// ── R9.6: normalizMAC with homoglyph characters ──────────────────────
// Unicode homoglyphs (characters that look like hex digits) could be used
// to impersonate a legitimate MAC address. For example, Greek ο (omicron)
// looks like 'o' or '0', and Cyrillic а (a) looks like Latin 'a'.
func TestAttack_MACHomoglyphCharacters(t *testing.T) {
	f := NewFilter(Config{
		AllowedMACs: []string{"aa:bb:cc:dd:ee:ff"},
	})

	homoglyphInputs := []struct {
		name string
		mac  string
	}{
		// Cyrillic а (U+0430) looks like Latin 'a'
		{"Cyrillic a instead of Latin a",
			"\u0430\u0430:bb:cc:dd:ee:ff"},
		// Greek ο (U+03BF) looks like 'o' or '0'
		{"Greek omicron instead of 'o'",
			"aa:bb:cc:dd:ee:f\u03bff"},
	}

	for _, tt := range homoglyphInputs {
		t.Run(tt.name, func(t *testing.T) {
			ok, reason := f.MACAllowed(tt.mac)
			if ok {
				t.Errorf("MAC %q with homoglyph characters was allowed — bypass: reason=%q", tt.mac, reason)
			} else {
				t.Logf("MAC %q correctly rejected: %s", tt.mac, reason)
			}
		})
	}
}

// ── R9.7: RecordDHCP with empty IP creates zero-length key ─────────────
// RecordDHCP stores IP→MAC bindings without validating that the IP is
// non-empty. An empty IP creates a zero-length key in arpTable.
func TestAttack_RecordDHCPWithEmptyIP(t *testing.T) {
	f := NewFilter(Config{EnableDHCPCheck: true})

	// Record DHCP with empty IP
	f.RecordDHCP("", "aa:bb:cc:dd:ee:ff")

	// The empty key should not cause issues when checked
	// CheckARP with empty IP returns early (norm == "" || ip == "")
	ok, reason := f.CheckARP("", "aa:bb:cc:dd:ee:ff")
	t.Logf("CheckARP('', 'aa:bb:cc:dd:ee:ff') = %v, reason=%q", ok, reason)
}

// ── R9.8: CheckARP with very long IP strings ──────────────────────────
// CheckARP accepts arbitrary-length IP strings with no validation before
// storing them in arpTable. An attacker sending a crafted ARP packet with
// a 10KB "IP" would waste memory.
func TestAttack_CheckARPWithLongIP(t *testing.T) {
	f := NewFilter(Config{EnableARPCheck: true})

	longIP := strings.Repeat("a", 10*1024) // 10KB "IP"
	longMAC := "aa:bb:cc:dd:ee:ff"

	// Record a very long IP
	f.CheckARP(longIP, longMAC)

	// Check arpTable for the long IP entry (learning mode)
	f.mu.RLock()
	_, exists := f.arpTable[longIP]
	f.mu.RUnlock()

	if exists {
		t.Logf("arpTable stored a %d-byte IP key — no length validation", len(longIP))
	} else {
		t.Log("long IP was rejected or not stored (has validation)")
	}
}

// ── R9.9: Concurrent CheckARP on same IP does not race ────────────────
// Multiple goroutines calling CheckARP with the same IP should not race
// on the arpTable map write. Uses existing mutex.
func TestAttack_ConcurrentCheckARPSameIP(t *testing.T) {
	f := NewFilter(Config{EnableARPCheck: true})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			// All goroutines write to the same key
			f.CheckARP("10.0.0.1", "aa:bb:cc:dd:ee:ff")
		}(i)
	}
	wg.Wait()
	t.Log("50 concurrent CheckARP on same IP completed without race")
}


