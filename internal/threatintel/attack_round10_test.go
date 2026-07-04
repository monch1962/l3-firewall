// Red-team security hardening Round 10 — Threat intel edge cases
package threatintel

import (
	"net"
	"testing"
)

// ── R10.7: IPv4-mapped IPv6 bypass of blocklist ────────────────────
// An attacker using IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) can
// bypass the blocklist because net.ParseIP("::ffff:10.0.0.1") produces
// a 16-byte IP whose String() is "::ffff:10.0.0.1", which does not
// match "10.0.0.1" stored by Add("10.0.0.1").
//
// For dual-stack deployments, an attacker can send IPv6 packets with
// IPv4-mapped source addresses that should match IPv4 blocklist entries.
func TestAttack_IPv4MappedIPv6Bypass(t *testing.T) {
	bl := NewBlocklist()
	bl.Add("10.0.0.1")

	// Verify basic IPv4 match works
	if !bl.Contains("10.0.0.1") {
		t.Fatal("baseline: Contains('10.0.0.1') should be true")
	}

	// IPv4-mapped IPv6 form should also match
	mappedIP := "::ffff:10.0.0.1"
	got := bl.Contains(mappedIP)

	parsed := net.ParseIP(mappedIP)
	if parsed == nil {
		t.Fatalf("net.ParseIP(%q) returned nil — not a valid IP", mappedIP)
	}
	to4 := parsed.To4()
	if to4 == nil {
		t.Fatalf("net.ParseIP(%q).To4() returned nil — expected IPv4-mapped to convert", mappedIP)
	}
	t.Logf("net.ParseIP(%q).String() = %q, .To4().String() = %q",
		mappedIP, parsed.String(), to4.String())

	if got {
		t.Logf("Contains(%q) correctly returned true — IPv4-mapped IPv6 matches blocklist", mappedIP)
	} else {
		t.Errorf("Contains(%q) = false — IPv4-mapped IPv6 bypasses blocklist! "+
			"Add should normalize IPs with To4() before storing", mappedIP)
	}

	// Also test the reverse: add the mapped form, then check the bare IPv4 form
	bl2 := NewBlocklist()
	mappedEntry := "::ffff:192.168.1.1"
	bl2.Add(mappedEntry)

	parsed2 := net.ParseIP(mappedEntry)
	to4_2 := parsed2.To4()
	t.Logf("Add(%q): stored as %q (To4 form = %q)", mappedEntry, parsed2.String(), to4_2.String())

	if !bl2.Contains("192.168.1.1") {
		t.Errorf("Added %q but Contains('192.168.1.1') = false — "+
			"Add should normalize with To4() for consistent matching", mappedEntry)
	}

	// CIDR with IPv4-mapped notation
	bl3 := NewBlocklist()
	bl3.Add("::ffff:10.0.0.0/120") // last 8 bits for 10.0.0.x
	t.Logf("CIDR with IPv4-mapped prefix: added ::ffff:10.0.0.0/120")
	// Currently this is stored as a CIDR network; its String() is the original form
}

// ── R10.8: Contains with IP edge cases ──────────────────────────
// net.ParseIP should handle standard IP formats correctly from the
// engine pipeline which always produces canonical dotted decimal form.
func TestAttack_ContainsIPEdgeCases(t *testing.T) {
	bl := NewBlocklist()
	bl.Add("10.0.0.1")

	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"standard form", "10.0.0.1", true},
		{"not present", "10.0.0.2", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bl.Contains(tt.ip)
			if got != tt.want {
				t.Errorf("Contains(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

// ── R10.9: Add with very long string ──────────────────────────────
// Add should handle excessively long input strings without panic
// or excessive memory allocation.
func TestAttack_AddVeryLongString(t *testing.T) {
	bl := NewBlocklist()

	// Generate a 10KB string that looks like an IP
	long := make([]byte, 10240)
	for i := range long {
		long[i] = 'A'
	}

	// Must not panic
	bl.Add(string(long))
	t.Logf("Add with 10KB string completed without panic")

	// Verify it didn't add anything
	if bl.Len() != 0 {
		t.Errorf("Add with invalid 10KB string added %d entries, want 0", bl.Len())
	}
}

// ── R10.10: StartRefresher with nil stopCh returned ──────────────
// When StartRefresher is called with empty URLs, it returns nil.
// Verify the caller handles nil stopCh gracefully (no panic on close).
func TestAttack_StartRefresherNilStopCh(t *testing.T) {
	bl := NewBlocklist()

	stopCh := bl.StartRefresher(nil, 0)
	if stopCh != nil {
		t.Error("StartRefresher with nil URLs should return nil")
	}

	stopCh = bl.StartRefresher([]string{}, 0)
	if stopCh != nil {
		t.Error("StartRefresher with empty URLs should return nil")
	}

	bl2 := (*Blocklist)(nil)
	stopCh = bl2.StartRefresher([]string{"http://example.com"}, 0)
	if stopCh != nil {
		t.Error("StartRefresher on nil Blocklist should return nil")
	}
}
