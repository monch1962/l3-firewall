package l2filter

import (
	"testing"
)

// ── R6.5: ARP table unbounded growth ────────────────────────────────────
// Attacker sends ARP packets with many unique IPs to exhaust memory.
// The arpTable map has no capacity limit.
func TestAttack_ARPTableUnbounded(t *testing.T) {
	f := NewFilter(Config{})
	const entries = 10000

	for i := 0; i < entries; i++ {
		ip := "10.0.0." + itoa(i)
		mac := "aa:bb:cc:dd:ee:ff"
		f.CheckARP(ip, mac)
	}

	count := countARPTable(f)
	t.Logf("ARP table has %d entries after %d insertions", count, entries)

	if count != entries {
		t.Errorf("expected %d entries, got %d", entries, count)
	}
	// This test documents unbounded growth — no cap means O(n) memory per unique IP
}

// ── R6.6: Empty MAC bypasses allowlist ──────────────────────────────────
// If AllowedMACs is set, an attacker can bypass by sending an empty MAC.
func TestAttack_EmptyMACBypassesAllowlist(t *testing.T) {
	f := NewFilter(Config{
		AllowedMACs: []string{"aa:bb:cc:dd:ee:01"},
	})

	ok, _ := f.MACAllowed("")
	if ok {
		t.Error("empty MAC bypasses allowlist — should be denied when AllowedMACs is non-empty")
	}
}

// ── R6.7: Empty MAC bypasses blocklist ──────────────────────────────────
// If BlockedMACs is set, empty MAC should still be allowed (no bypass issue)
// but we verify it doesn't crash.
func TestAttack_EmptyMACWithBlocklist(t *testing.T) {
	f := NewFilter(Config{
		BlockedMACs: []string{"aa:bb:cc:dd:ee:ff"},
	})

	// Empty MAC must not crash
	ok, reason := f.MACAllowed("")
	if !ok {
		t.Logf("empty MAC was blocked: %s", reason)
	}
}

// ── R6.8: MAC normalization corner cases ────────────────────────────────
// Attacker uses unusual MAC formats to test normalization robustness.
func TestAttack_MACNormalizationCornerCases(t *testing.T) {
	f := NewFilter(Config{
		BlockedMACs: []string{"aabbccddeeff"},
	})

	tests := []struct {
		name  string
		mac   string
		block bool // true if expected to be blocked
	}{
		{"uppercase", "AA:BB:CC:DD:EE:FF", true},
		{"no separators", "aabbccddeeff", true},
		{"dot notation", "aabb.ccdd.eeff", true},
		{"dash notation", "aa-bb-cc-dd-ee-ff", true},
		{"mixed separators", "aa:bb-cc.dd:ee:ff", true},
		{"extra whitespace", "  aa:bb:cc:dd:ee:ff  ", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, reason := f.MACAllowed(tt.mac)
			if ok && tt.block {
				t.Errorf("MAC %q was not blocked (bypass): reason=%q", tt.mac, reason)
			}
		})
	}
}

// ── R6.9: ARP table poisoning via unbounded RecordDHCP ──────────────────
// Attacker floods DHCP ACK with unique IPs to fill arpTable memory.
func TestAttack_RecordDHCPUnbounded(t *testing.T) {
	f := NewFilter(Config{})
	const entries = 10000

	for i := 0; i < entries; i++ {
		ip := "10.0.0." + itoa(i)
		f.RecordDHCP(ip, "aa:bb:cc:dd:ee:ff")
	}

	count := countARPTable(f)
	t.Logf("ARP table has %d entries after DHCP flood", count)

	// Verify unbounded growth
	if count != entries {
		t.Errorf("expected %d entries, got %d", entries, count)
	}
}

// Helper: count ARP table entries
func countARPTable(f *Filter) int {
	f.mu.RLock()
	count := len(f.arpTable)
	f.mu.RUnlock()
	return count
}

// Simple integer to string without strconv import
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}
	result := ""
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		result = digits[n%10] + result
		n /= 10
	}
	if neg {
		result = "-" + result
	}
	return result
}
