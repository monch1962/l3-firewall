package l2filter

import (
	"testing"
)

// ── R45.10: DHCP empty-MAC binding poisoning ─────────────────────────
// RecordDHCP normalizes the MAC and stores it as the IP→MAC binding.
// A DHCP ACK with a MAC that normalizes to empty (e.g. "!!!", all
// punctuation, or separators only) stores "" as the binding for the
// victim IP. A subsequent CheckARP from the LEGITIMATE host then sees
// knownMAC("") != realMAC and flags the victim as an ARP spoofer — the
// attacker poisons the ARP table with an empty binding and DoS's the
// victim's traffic with a false spoofing alarm.
func TestAttack_RecordDHCPEmptyMACBindingPoisoning(t *testing.T) {
	f := NewFilter(Config{EnableARPCheck: true})

	// Attacker sends a DHCP ACK for victim IP with a garbage MAC that
	// normalizes to empty (no hex digits at all)
	recorded := f.RecordDHCP("10.0.0.7", "!!!")

	if recorded {
		t.Log("RecordDHCP accepted the empty-normalizing MAC")
	}

	// The legitimate host's real ARP must NOT be flagged as spoofing
	ok, reason := f.CheckARP("10.0.0.7", "AA:BB:CC:DD:EE:FF")
	if !ok {
		t.Errorf("legitimate host flagged as ARP spoofer after empty-MAC DHCP poisoning: %s", reason)
	}
}

// ── R45.11: Empty MAC must never be stored as a binding ──────────────
// Even if RecordDHCP accepts the call, the table must not contain an
// empty-string binding that mismatches every real MAC.
func TestAttack_RecordDHCPEmptyMACNotStored(t *testing.T) {
	f := NewFilter(Config{EnableARPCheck: true})

	f.RecordDHCP("10.0.0.9", "")
	f.RecordDHCP("10.0.0.9", ":")

	f.mu.Lock()
	binding, exists := f.arpTable["10.0.0.9"]
	f.mu.Unlock()

	if exists && binding == "" {
		t.Error("empty MAC binding stored in arpTable for 10.0.0.9")
	}

	// Legit host must still pass
	if ok, reason := f.CheckARP("10.0.0.9", "00:11:22:33:44:55"); !ok {
		t.Errorf("legitimate host flagged after empty-MAC RecordDHCP: %s", reason)
	}
}

// ── R45.12: Valid DHCP binding still records and matches ─────────────
// Regression guard: real bindings must still be stored and verified.
func TestAttack_RecordDHCPValidBindingStillWorks(t *testing.T) {
	f := NewFilter(Config{EnableARPCheck: true})

	f.RecordDHCP("10.0.0.10", "AA:BB:CC:DD:EE:FF")

	if ok, reason := f.CheckARP("10.0.0.10", "aa:bb:cc:dd:ee:ff"); !ok {
		t.Errorf("valid binding flagged as spoof: %s", reason)
	}
	if ok, _ := f.CheckARP("10.0.0.10", "00:11:22:33:44:55"); ok {
		t.Error("different MAC on learned IP not flagged — spoofing undetected")
	}
}
