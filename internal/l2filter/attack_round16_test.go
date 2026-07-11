// Red-team security hardening Round 16 — Zero-width character bypass in normalizeMAC
//
// Attacks: Unicode format characters (zero-width space U+200B, zero-width
// non-joiner U+200C, etc.) are not classified as whitespace by Go's unicode
// package, so strings.Fields does not strip them during MAC normalization.
// An attacker can embed these characters in MAC addresses to bypass allowlist
// and blocklist filtering.
//
// FIX: Add a pre-normalization step that strips non-hex, non-separator
// characters from MAC addresses. Specifically, filter to keep only [0-9a-fA-F:-.]
// before normalization.
package l2filter

import (
	"testing"
)

// ── R16.1: Zero-width space (U+200B) bypasses MAC blocklist ────────
// An attacker sends a packet with source MAC "aa:bb:cc:dd:ee:\u200bff".
// normalizeMAC currently produces "aabbccddee\u200bff" which does NOT
// match "aabbccddeeff" stored from the blocked MAC "aa:bb:cc:dd:ee:ff".
// The attacker bypasses the blocklist.
func TestAttack_ZeroWidthSpaceBypassBlocklist(t *testing.T) {
	f := NewFilter(Config{
		BlockedMACs: []string{"aa:bb:cc:dd:ee:ff"},
	})

	// Baseline: blocked MAC must be blocked
	if ok, _ := f.MACAllowed("aa:bb:cc:dd:ee:ff"); ok {
		t.Fatal("baseline: blocked MAC was not blocked")
	}

	// Zero-width space (U+200B) inside the MAC — should also be blocked
	zwsp := "aa:bb:cc:dd:ee:\u200bff"
	norm := normalizeMAC(zwsp)
	expected := "aabbccddeeff"
	if norm == expected {
		t.Logf("normalizeMAC correctly normalizes U+200B to %q", norm)
	} else {
		t.Errorf("normalizeMAC(%q) = %q — U+200B zero-width space bypasses MAC normalization, expected %q",
			zwsp, norm, expected)
	}

	// MACAllowed should block this
	if ok, _ := f.MACAllowed(zwsp); ok {
		t.Errorf("MACAllowed(%q) bypassed blocklist — zero-width space evades filtering", zwsp)
	} else {
		t.Logf("MACAllowed correctly blocked zero-width space variant")
	}
}

// ── R16.2: Multiple zero-width format characters bypass blocklist ──
// Tests various Unicode format characters that are NOT whitespace but
// prevent proper MAC normalization.
func TestAttack_ZeroWidthFormatCharsBypassBlocklist(t *testing.T) {
	f := NewFilter(Config{
		BlockedMACs: []string{"aa:bb:cc:dd:ee:ff"},
	})

	// Baseline
	if ok, _ := f.MACAllowed("aa:bb:cc:dd:ee:ff"); ok {
		t.Fatal("baseline: blocked MAC was not blocked")
	}

	tests := []struct {
		name string
		mac  string // MAC with format character embedded
		char string // description of the format character
		code string // unicode code point
	}{
		{
			name: "zero-width space U+200B",
			mac:  "aa:bb:cc:dd:ee:\u200bff",
			char: "zero-width space",
			code: "U+200B",
		},
		{
			name: "zero-width non-joiner U+200C",
			mac:  "aa:bb:cc:dd:ee:\u200cff",
			char: "zero-width non-joiner",
			code: "U+200C",
		},
		{
			name: "zero-width joiner U+200D",
			mac:  "aa:bb:cc:dd:ee:\u200dff",
			char: "zero-width joiner",
			code: "U+200D",
		},
		{
			name: "BOM / ZWNBSP U+FEFF",
			mac:  "aa:bb:cc:dd:ee:\ufeffff",
			char: "BOM / zero-width no-break space",
			code: "U+FEFF",
		},
		{
			name: "soft hyphen U+00AD",
			mac:  "aa:bb:cc:dd:ee:\u00adff",
			char: "soft hyphen",
			code: "U+00AD",
		},
		{
			name: "mongolian vowel separator U+180E",
			mac:  "aa:bb:cc:dd:ee:\u180eff",
			char: "mongolian vowel separator",
			code: "U+180E",
		},
		{
			name: "arabic letter mark U+061C",
			mac:  "aa:bb:cc:dd:ee:\u061cff",
			char: "arabic letter mark",
			code: "U+061C",
		},
		{
			name: "word joiner U+2060",
			mac:  "aa:bb:cc:dd:ee:\u2060ff",
			char: "word joiner",
			code: "U+2060",
		},
		{
			name: "left-to-right mark U+200E",
			mac:  "aa:bb:cc:dd:ee:\u200eff",
			char: "left-to-right mark",
			code: "U+200E",
		},
		{
			name: "right-to-left mark U+200F",
			mac:  "aa:bb:cc:dd:ee:\u200fff",
			char: "right-to-left mark",
			code: "U+200F",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			norm := normalizeMAC(tt.mac)
			expected := "aabbccddeeff"
			if norm == expected {
				t.Logf("normalizeMAC(%q) = %q — %s (%s) correctly stripped", tt.mac, norm, tt.char, tt.code)
			} else {
				t.Errorf("normalizeMAC(%q) = %q — %s (%s) bypasses normalization, expected %q",
					tt.mac, norm, tt.char, tt.code, expected)
			}

			// MACAllowed should block this
			if ok, _ := f.MACAllowed(tt.mac); ok {
				t.Errorf("MACAllowed bypassed blocklist via %s (%s): %q", tt.char, tt.code, tt.mac)
			}
		})
	}
}

// ── R16.3: Zero-width chars also bypass allowlist ──────────────────
// Same attack applies to allowlist: embedding zero-width chars in a MAC
// that should be allowed results in it being denied (false positive).
func TestAttack_ZeroWidthBypassAllowlist(t *testing.T) {
	f := NewFilter(Config{
		AllowedMACs: []string{"aa:bb:cc:dd:ee:01"},
	})

	// Baseline: allowed MAC works
	if ok, _ := f.MACAllowed("aa:bb:cc:dd:ee:01"); !ok {
		t.Fatal("baseline: allowed MAC was not allowed")
	}

	// With zero-width space inserted — should also be allowed (same MAC chars)
	zwsp := "aa:bb:cc:dd:ee:\u200b01"
	norm := normalizeMAC(zwsp)
	expected := "aabbccddee01"
	if norm == expected {
		t.Logf("normalizeMAC(%q) = %q — zero-width space stripped, normalization correct", zwsp, norm)
	} else {
		t.Errorf("normalizeMAC(%q) = %q — zero-width space should be stripped, expected %q",
			zwsp, norm, expected)
	}

	if ok, reason := f.MACAllowed(zwsp); ok {
		t.Logf("MACAllowed correctly allowed zero-width space variant")
	} else {
		t.Errorf("MACAllowed(%q) denied — zero-width space prevents correct allowlist matching: %s", zwsp, reason)
	}
}

// ── R16.4: normalizeMAC with combined Unicode whitespace + format chars ─
// Both Unicode whitespace (NBSP, thin space) AND format characters
// should be stripped.
func TestAttack_NormalizeMACCombinedUnicode(t *testing.T) {
	expected := "aabbccddeeff"

	tests := []struct {
		name string
		mac  string
	}{
		{"NBSP + ZWS", "aa:bb:cc:dd:ee:\u00a0\u200bff"},
		{"thin space + ZWJ", "aa:bb:cc:dd:ee:\u2009\u200dff"},
		{"ZWS in middle", "aa:\u200bbb:cc:dd:ee:ff"},
		{"multiple ZWS", "aa:\u200bbb:\u200bcc:\u200bdd:\u200bee:\u200bff"},
		{"ZWS + NBSP + ZWS", "aa:\u200bbb:\u00a0cc:\u200bdd:ee:ff"},
		{"BOM at start", "\ufeffaa:bb:cc:dd:ee:ff"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			norm := normalizeMAC(tt.mac)
			if norm == expected {
				t.Logf("normalizeMAC(%q) = %q ✓", tt.mac, norm)
			} else {
				t.Errorf("normalizeMAC(%q) = %q — expected %q", tt.mac, norm, expected)
			}
		})
	}
}

// ── R16.5: normalizeMAC still handles normal inputs correctly ─────
// Regression: existing normalization patterns must not break.
func TestAttack_NormalizeMACRegression(t *testing.T) {
	tests := []struct {
		name string
		mac  string
		want string
	}{
		{"standard colon", "aa:bb:cc:dd:ee:ff", "aabbccddeeff"},
		{"uppercase", "AA:BB:CC:DD:EE:FF", "aabbccddeeff"},
		{"no separators", "aabbccddeeff", "aabbccddeeff"},
		{"dash notation", "aa-bb-cc-dd-ee-ff", "aabbccddeeff"},
		{"dot notation", "aabb.ccdd.eeff", "aabbccddeeff"},
		{"extra spaces", "  aa:bb:cc:dd:ee:ff  ", "aabbccddeeff"},
		{"mixed separators", "aa:bb-cc.dd:ee:ff", "aabbccddeeff"},
		{"NBSP separator", "aa:bb:cc:dd:ee:\u00a0ff", "aabbccddeeff"},
		{"thin space separator", "aa:bb:cc:dd:ee:\u2009ff", "aabbccddeeff"},
		{"ideographic space", "aa:bb:cc:dd:ee:\u3000ff", "aabbccddeeff"},
		{"empty string", "", ""},
		{"single char", "a", "a"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeMAC(tt.mac)
			if got != tt.want {
				t.Errorf("normalizeMAC(%q) = %q, want %q", tt.mac, got, tt.want)
			}
		})
	}
}
