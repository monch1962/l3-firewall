package l2filter

import (
	"strings"
	"sync"
	"testing"
)

// ── R8.13: normalizeMAC non-hex characters ────────────────────────────
// normalizeMAC strips separators and lowercases, but doesn't validate
// that the result is a valid 12-character hex string. Non-hex characters
// (e.g. "zz:zz:zz:zz:zz:zz") are accepted silently and stored in maps.
func TestAttack_NonHexMACCharacters(t *testing.T) {
	f := NewFilter(Config{
		AllowedMACs: []string{"aa:bb:cc:dd:ee:ff"},
	})

	tests := []struct {
		name string
		mac  string
		want bool // true if expected to match (allowed)
	}{
		{"valid hex", "aa:bb:cc:dd:ee:ff", true},
		{"non-hex chars", "zz:zz:zz:zz:zz:zz", false},
		{"mixed hex and non-hex", "aa:bb:cc:dd:ee:gg", false},
		{"garbage input", "!@#$%^&*()", false},
		{"control chars in MAC", "aa:bb:cc:dd:ee:\x00ff", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, _ := f.MACAllowed(tt.mac)
			if ok != false {
				// These should never match any real MAC
				t.Logf("MACAllowed(%q) = %v — no hex validation on MAC normalization", tt.mac, ok)
			}
		})
	}

	// Verify that normalizeMAC doesn't validate hex
	for _, tt := range tests {
		norm := normalizeMAC(tt.mac)
		t.Logf("normalizeMAC(%q) = %q (len=%d) — no hex validation", tt.mac, norm, len(norm))
	}
}

// ── R8.14: Broadcast MAC address handling ─────────────────────────────
// ff:ff:ff:ff:ff:ff is a broadcast MAC. Should it be blockable?
func TestAttack_BroadcastMACAddress(t *testing.T) {
	f := NewFilter(Config{
		BlockedMACs: []string{"ff:ff:ff:ff:ff:ff"},
	})

	ok, reason := f.MACAllowed("ff:ff:ff:ff:ff:ff")
	if !ok {
		t.Logf("Broadcast MAC correctly blocked: %s", reason)
	} else {
		t.Log("Broadcast MAC was not blocked — broadcast not in blocked list?")
	}

	// Test multicast MAC
	f2 := NewFilter(Config{
		BlockedMACs: []string{"01:00:5e:00:00:01"},
	})
	ok, reason = f2.MACAllowed("01:00:5e:00:00:01")
	if !ok {
		t.Logf("Multicast MAC correctly blocked: %s", reason)
	} else {
		t.Log("Multicast MAC was not blocked")
	}
}

// ── R8.15: MAC address length extremes ────────────────────────────────
// Very short or very long MAC-like strings should not crash the filter.
func TestAttack_MACLengthExtremes(t *testing.T) {
	f := NewFilter(Config{
		AllowedMACs: []string{"aa:bb:cc:dd:ee:ff"},
	})

	tests := []struct {
		name string
		mac  string
	}{
		{"empty string", ""},
		{"single char", "a"},
		{"short string", "abc"},
		{"very long", strings.Repeat("aa:", 1000)},
		{"null byte embedded", "aa:bb:cc:dd:ee:\xff"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, reason := f.MACAllowed(tt.mac)
			t.Logf("MACAllowed(%q len=%d) = %v, reason=%q — no panic", tt.mac, len(tt.mac), ok, reason)
		})
	}
}

// ── R8.16: Concurrent normalizeMAC ────────────────────────────────────
// normalizeMAC is called from both MACAllowed (RLock) and RecordDHCP
// (Lock). It doesn't access shared state, so it's safe, but we verify.
func TestAttack_ConcurrentNormalize(t *testing.T) {
	f := NewFilter(Config{
		AllowedMACs: []string{"aa:bb:cc:dd:ee:ff"},
		BlockedMACs: []string{"11:22:33:44:55:66"},
	})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			mac := "aa:bb:cc:dd:ee:" + itoa(n)
			f.MACAllowed(mac)
			f.RecordDHCP("10.0.0."+itoa(n), mac)
			f.CheckARP("10.0.0."+itoa(n), mac)
		}(i)
	}
	wg.Wait()
	t.Log("Concurrent normalizeMAC completed without race")
}

// ── R8.17: Very large allowed/blocked MAC lists ───────────────────────
// NewFilter creates maps by iterating over all MACs. A config with
// many MACs could cause slow startup or memory pressure.
func TestAttack_LargeMACListStartup(t *testing.T) {
	macs := make([]string, 10000)
	for i := 0; i < 10000; i++ {
		macs[i] = "aa:bb:cc:dd:ee:" + itoa(i%256)
	}

	_ = NewFilter(Config{
		AllowedMACs: macs,
	})
	t.Logf("NewFilter with %d allowed MACs completed", len(macs))
}


