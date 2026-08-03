// Red-team security hardening Round 41 — l2filter IPv4-mapped IPv6 key split.
//
// R40.1's propagation rule: grep every map keyed by an IP STRING and
// normalize with To4() everywhere. ratelimit, conntrack, and threatintel
// were fixed in R40/R19; l2filter's arpTable was the remaining IP-keyed
// map with RAW string keys — RecordDHCP and CheckARP stored and looked up
// bindings under whatever byte form arrived, so "10.0.0.1" and
// "::ffff:10.0.0.1" (the same IP) occupied two table entries:
//   - ARP-spoofing detection bypass: a binding learned under the bare form
//     is NOT found under the mapped alias, so the alias falls into learning
//     mode and records a duplicate instead of detecting the MAC change.
//   - Memory: one IP can consume two entries, halving the effective
//     MaxARPEntries budget and evicting legitimate bindings faster.
package l2filter

import "testing"

// ── R41.1: arpTable IPv4-mapped key split ──────────────────────────
// RecordDHCP("10.0.0.1") and RecordDHCP("::ffff:10.0.0.1") are the SAME
// IP but currently create two arpTable entries.
func TestAttack_ARPTableIPv4MappedKeySplit(t *testing.T) {
	f := NewFilter(Config{EnableDHCPCheck: true})

	f.RecordDHCP("10.0.0.1", "aa:bb:cc:dd:ee:01")
	f.RecordDHCP("::ffff:10.0.0.1", "aa:bb:cc:dd:ee:02")

	f.mu.RLock()
	size := len(f.arpTable)
	f.mu.RUnlock()
	if size != 1 {
		t.Errorf("IPv4-mapped alias created %d arpTable entries for one IP — "+
			"key split allows ARP-spoofing bypass and doubles per-IP table usage", size)
	}
}

// ── R41.2: ARP-spoof detection bypass via IPv4-mapped alias ────────
// A binding learned under the bare form must be found under the mapped
// alias, otherwise the alias bypasses spoof detection and re-enters
// learning mode with an attacker-chosen MAC.
func TestAttack_ARPSpoofBypassViaIPv4MappedAlias(t *testing.T) {
	f := NewFilter(Config{EnableARPCheck: true})

	// Binding learned under bare IPv4 form
	if ok, reason := f.CheckARP("10.0.0.1", "aa:bb:cc:dd:ee:01"); !ok {
		t.Fatalf("learning CheckARP should allow: %s", reason)
	}

	// Attacker reuses the IPv4-mapped alias with a DIFFERENT MAC
	ok, reason := f.CheckARP("::ffff:10.0.0.1", "aa:bb:cc:dd:ee:ff")
	if ok {
		t.Errorf("ARP spoof via IPv4-mapped alias NOT detected — alias key "+
			"missed the binding stored under bare form (reason: %q)", reason)
	}

	// Table must not have grown from the alias lookup
	f.mu.RLock()
	size := len(f.arpTable)
	f.mu.RUnlock()
	if size != 1 {
		t.Errorf("arpTable has %d entries after alias spoof attempt — expected 1", size)
	}
}
