// Red-team security hardening Round 41 — threatintel Remove() normalization.
//
// R10's Add/Remove lesson: Add and Contains were fixed with To4() in R19,
// but Remove() still deletes with the RAW ParseIP(...).String() key. On
// Go >= 1.23 IP.String() normalizes IPv4-mapped addresses (verified:
// go1.23.0 and go1.25.0 both return "10.0.0.1"), so the delete works by
// accident on the current toolchain — but on Go 1.20-1.24 the mapped form
// survives String(), the delete misses the normalized key, and the entry
// becomes un-deletable (an operator removing an IP via its mapped alias
// silently fails). This test locks the invariant so Remove stays correct
// on every toolchain; the fix aligns Remove with Add/Contains.
package threatintel

import "testing"

// ── R41.1: Remove must normalize IPv4-mapped aliases like Add/Contains ──
func TestAttack_RemoveIPv4MappedNormalization(t *testing.T) {
	// Remove by mapped alias of a bare-form entry
	bl := NewBlocklist()
	bl.Add("10.0.0.1")
	bl.Remove("::ffff:10.0.0.1")
	if bl.Contains("10.0.0.1") {
		t.Errorf("Remove via IPv4-mapped alias failed to delete bare-form entry — " +
			"un-deletable key (Add normalizes with To4, Remove does not)")
	}

	// Remove by bare form of a mapped-form entry
	bl2 := NewBlocklist()
	bl2.Add("::ffff:10.0.0.2")
	bl2.Remove("10.0.0.2")
	if bl2.Contains("10.0.0.2") {
		t.Errorf("Remove via bare form failed to delete IPv4-mapped entry — " +
			"un-deletable key (Add normalizes with To4, Remove does not)")
	}
}
