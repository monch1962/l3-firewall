package threatintel

import (
	"fmt"
	"testing"
)

// cidrFor returns the i-th distinct /24 network in a 3-octet key space
// (a.b.c.0/24 with a in 10..253, b and c varying) — 244×256×256 ≈ 16M
// distinct values, so loops up to maxBlocklistEntries never wrap into
// duplicates (the 2-octet 10.x.y.0/24 scheme used in early drafts collapsed
// after 65536 iterations, making the RED test pass vacuously via R45 dedup).
func cidrFor(i int) string {
	return fmt.Sprintf("%d.%d.%d.0/24", (i%244)+10, (i/244)%256, (i/(244*256))%256)
}

// ipInCIDR returns an address inside the i-th distinct /24 network.
func ipInCIDR(i int) string {
	return fmt.Sprintf("%d.%d.%d.1", (i%244)+10, (i/244)%256, (i/(244*256))%256)
}

// ── R58.1: Unbounded distinct-CIDR count → per-packet scan amplification ──
// R45 capped the *total* entry count (ips+nets jointly at maxBlocklistEntries)
// and deduplicated repeated CIDRs across refresh cycles, but left the number
// of DISTINCT networks in the nets slice unbounded — all 500k total slots can
// be distinct CIDRs. Contains() scans the entire nets slice on EVERY packet:
// engine.evaluatePacket calls threatIntel.Contains(pi.SrcIP) on the NFQUEUE
// hot path before OPA evaluation. The 50MB feed response cap admits ~3M
// single-line CIDRs, so one fetch from a malicious/compromised feed server
// (the R54/R45 threat model: feeds are fetched over plaintext HTTP with no
// authenticity check) fills nets with 500k distinct networks. Measured on
// this host: 500k networks ⇒ ~4.7ms per Contains() call (12ns × 500k). The
// receive loop is a single goroutine (MaxQueueLen=1024); at ~200 pps the
// firewall spends 100% of one core scanning blocklist networks and the queue
// overflows — the kernel drops ALL traffic. Exact-IP entries are O(1) map
// lookups; only the CIDR slice is O(n), so the two classes need SEPARATE
// caps.
func TestAttack_UnboundedDistinctCIDRScan(t *testing.T) {
	bl := NewBlocklist()

	// Distinct networks only — 3-octet space, no duplicates. Exceeds the
	// proposed separate nets cap (65536) but stays under the 500k total
	// cap, so the TOTAL cap cannot mask the missing per-type cap.
	for i := 0; i < maxBlocklistEntries; i++ {
		bl.Add(cidrFor(i))
	}

	if got := len(bl.nets); got > maxCIDRNetworks {
		t.Errorf("nets slice unbounded: %d distinct CIDRs stored (max %d) — every hot-path packet scans all of them",
			got, maxCIDRNetworks)
	}
}

// ── R58.2: Exact-IP entries must be unaffected by the nets cap ──────────
// The separate nets cap must not change the exact-IP path: IPs are O(1) map
// lookups, so the full maxBlocklistEntries budget for exact IPs still
// applies. Regression guard for the healthy path.
func TestAttack_ExactIPsUnaffectedByCIDRNetCap(t *testing.T) {
	bl := NewBlocklist()

	// Exhaust the nets budget with distinct CIDRs.
	for i := 0; i < maxCIDRNetworks; i++ {
		bl.Add(cidrFor(i))
	}
	if got := len(bl.nets); got != maxCIDRNetworks {
		t.Fatalf("expected nets at cap %d, got %d", maxCIDRNetworks, got)
	}

	// Exact IPs must still be accepted and match — the blocklist must keep
	// functioning for its O(1) class while the CIDR class is bounded.
	bl.Add("192.168.1.1")
	if !bl.Contains("192.168.1.1") {
		t.Error("exact IP added after CIDR cap exhausted must still be blocked")
	}
	// Networks already accepted (first /24) must still match.
	if !bl.Contains(ipInCIDR(0)) {
		t.Errorf("Contains(%s) should be true — accepted network must still match", ipInCIDR(0))
	}
}

// ── R58.3: Distinct CIDRs under the cap still match (healthy path) ─────
// Regression guard: the cap must not break matching for networks that were
// accepted. Add networks up to the cap, then verify Contains still works for
// an address inside the LAST accepted network, and that a network beyond the
// cap is NOT added.
func TestAttack_DistinctCIDRsUnderCapStillMatch(t *testing.T) {
	bl := NewBlocklist()

	for i := 0; i < maxCIDRNetworks; i++ {
		bl.Add(cidrFor(i))
	}
	if got := len(bl.nets); got != maxCIDRNetworks {
		t.Fatalf("expected nets at cap %d, got %d", maxCIDRNetworks, got)
	}

	// Address inside the LAST accepted network must match.
	if !bl.Contains(ipInCIDR(maxCIDRNetworks - 1)) {
		t.Errorf("Contains(%s) should be true — accepted network must still match", ipInCIDR(maxCIDRNetworks-1))
	}
	// Address inside the FIRST REJECTED (beyond-cap) network must NOT match.
	if bl.Contains(ipInCIDR(maxCIDRNetworks)) {
		t.Errorf("Contains(%s) should be false — beyond-cap network must not be added", ipInCIDR(maxCIDRNetworks))
	}
}
