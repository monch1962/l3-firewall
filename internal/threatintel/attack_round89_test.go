package threatintel

import (
	"fmt"
	"net"
	"testing"
)

// ── R89.6: per-packet CIDR cost still scales with feed size ─────────────
//
// R58 capped the number of DISTINCT networks (maxCIDRNetworks = 65536) and
// accepted the residual scan as "bounded to ~0.8ms worst case". That bound
// is not a safe bound: engine.evaluatePacket calls Contains() for EVERY
// packet on the single-goroutine NFQUEUE receive loop, so 65536 networks
// means 0.2-0.8 ms of linear scan per packet — a throughput ceiling of a few
// thousand packets per second. A 1 Gbps link at 1500-byte MTU is ~83k pps;
// the queue (1024) overflows and the kernel drops ALL traffic.
//
// The cap therefore converted "unbounded" into "still catastrophic": one
// feed — hostile, compromised, or simply large — carrying many DISTINCT
// prefixes (a /16-and-/24-per-ASN feed is a normal shape, and nothing about
// a prefix is implausible) is a complete denial of service against the
// firewall it feeds. Measured on this host before the fix:
//
//	51200 distinct networks -> ~227 µs per Contains()
//
// The cost must be independent of how many networks the feed carries. The
// lookup is a longest-prefix-style membership test, which is a hash probe
// per distinct PREFIX LENGTH (≤33 for IPv4, ≤129 for IPv6) — a property of
// the address family, not of the feed.
func TestAttack_CIDRLookupCostIndependentOfFeedSize(t *testing.T) {
	bl := NewBlocklist()
	for i := 0; i < maxCIDRNetworks; i++ {
		bl.Add(cidrFor(i))
	}
	if got := bl.Len(); got != maxCIDRNetworks {
		t.Fatalf("setup: expected %d networks stored, got %d", maxCIDRNetworks, got)
	}

	// Addresses that are NOT in the blocklist (the common case for every
	// packet the firewall sees) — the lookup cannot short-circuit.
	probes := []string{"203.0.113.9", "198.51.100.7", "192.0.2.55", "8.8.8.8"}
	for _, p := range probes {
		if bl.Contains(p) {
			t.Fatalf("setup: %s unexpectedly matches the blocklist", p)
		}
	}

	res := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bl.Contains(probes[i%len(probes)])
		}
	})
	nsPerOp := res.NsPerOp()
	t.Logf("Contains() over %d distinct CIDRs: %d ns/op (%.3f ms/op)", bl.Len(), nsPerOp, float64(nsPerOp)/1e6)

	// Budget: the whole per-packet decision (parse + conntrack + ratelimit +
	// blocklist + OPA) targets single-digit microseconds. A blocklist lookup
	// over a full-size feed must not dominate it.
	const budgetNs = 20_000 // 20 µs — 10x the pre-fix minimum, 100x the fixed cost
	if nsPerOp > budgetNs {
		t.Errorf("blocklist lookup costs %d ns/op at the 65536-network cap (budget %d ns) — "+
			"one feed with many distinct prefixes stalls the single-goroutine receive loop and drops all traffic",
			nsPerOp, budgetNs)
	}
}

// ── R89.6b: worst-case prefix-length spread stays cheap ──────────────────
// The bounded-cost property must hold for the adversarial shape too: a feed
// that spreads its entries over EVERY prefix length (one network per
// length) maximises the number of hash probes. Even then the cost must stay
// within the per-packet budget.
func TestAttack_CIDRLookupWorstCasePrefixSpread(t *testing.T) {
	bl := NewBlocklist()
	for ones := 1; ones <= 32; ones++ {
		// 10.0.0.0/ones ... one distinct network per IPv4 prefix length.
		if _, ipnet, err := net.ParseCIDR(fmt.Sprintf("10.0.0.0/%d", ones)); err == nil {
			bl.Add(ipnet.String())
		}
	}
	for ones := 1; ones <= 128; ones++ {
		if _, ipnet, err := net.ParseCIDR(fmt.Sprintf("2001:db8::/%d", ones)); err == nil {
			bl.Add(ipnet.String())
		}
	}
	// A network that cannot match: /8s and /96s only, no entry above them.
	res := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			bl.Contains("203.0.113.9")
			bl.Contains("2a00:1450:4001::1")
		}
	})
	nsPerOp := res.NsPerOp()
	t.Logf("worst-case prefix spread (%d buckets): %d ns/op for both families", bl.Len(), nsPerOp)
	const budgetNs = 20_000
	if nsPerOp > budgetNs {
		t.Errorf("lookup over a prefix-spread feed costs %d ns/op (budget %d)", nsPerOp, budgetNs)
	}
}

// ── R89.6c: the indexed lookup must be semantically identical ───────────
// The bucket index is a performance structure, not a policy change. Every
// accept/reject decision must match the brute-force reference
// (net.IPNet.Contains over the same accepted entries) for IPv4, IPv6,
// IPv4-mapped IPv6, /32, /128 and boundary addresses.
func TestAttack_CIDRIndexMatchesLinearReference(t *testing.T) {
	entries := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.1.0/24",
		"203.0.113.7/32",
		"0.0.0.0/1", // coarse but not whole-family: must still be honoured
		"2001:db8::/32",
		"2001:db8:1::/48",
		"2a00:1450::/31",
		"::ffff:198.51.100.0/120", // IPv4-mapped: matches 198.51.100.0/24
		"::1/128",
		"8.8.8.8",     // exact IP
		"2001:db8::1", // exact IPv6
	}
	// Reference set: the same entries, parsed straight into IPNets.
	var ref []*net.IPNet
	bl := NewBlocklist()
	for _, e := range entries {
		added := bl.Add(e)
		if _, ipnet, err := net.ParseCIDR(e); err == nil {
			ref = append(ref, ipnet)
			if !added {
				t.Fatalf("setup: %q was rejected by Add (%v)", e, ipnet)
			}
		}
	}

	probes := []string{
		"10.1.2.3", "10.255.255.255", "11.0.0.1",
		"172.16.0.1", "172.31.255.254", "172.32.0.1",
		"192.168.1.1", "192.168.2.1",
		"203.0.113.7", "203.0.113.8",
		"198.51.100.9", "198.51.100.250", "198.51.101.1",
		"8.8.8.8", "8.8.4.4",
		"127.0.0.1", "0.0.0.42", "100.64.0.1",
		"2001:db8::5", "2001:db8:1::5", "2001:db8:2::5",
		"2a00:1450:4001::1", "2a00:1451::1",
		"::1", "::2",
		"::ffff:198.51.100.9", "::ffff:10.1.2.3",
	}
	for _, p := range probes {
		ip := net.ParseIP(p)
		if ip == nil {
			t.Fatalf("bad probe %q", p)
		}
		norm := ip
		if v4 := ip.To4(); v4 != nil {
			norm = v4
		}
		want := false
		for _, n := range ref {
			if n.Contains(norm) {
				want = true
				break
			}
		}
		if got := bl.Contains(p); got != want {
			t.Errorf("Contains(%q) = %v, brute-force reference = %v", p, got, want)
		}
	}

	// Exact-IP entries (the map path) must survive the refactor too.
	if !bl.Contains("8.8.8.8") || !bl.Contains("2001:db8::1") {
		t.Error("exact-IP entries stopped matching")
	}
	// Remove must still work on the indexed structure.
	bl.Remove("172.16.0.0/12")
	if bl.Contains("172.16.0.1") {
		t.Error("Remove(/12) did not remove the network from the index")
	}
	if bl.Contains("192.168.1.1") != true {
		t.Error("Remove(/12) removed the wrong network")
	}
}

// ── R89.6d: index and storage cannot drift ────────────────────────────
// Add/Remove mutate two structures (the dedupe key set and the bucket
// index). Any drift silently changes policy, so the invariant is asserted
// across a mixed Add/Remove/re-Add sequence.
func TestAttack_CIDRIndexNoDrift(t *testing.T) {
	bl := NewBlocklist()
	for i := 0; i < 512; i++ {
		bl.Add(cidrFor(i))
	}
	for i := 0; i < 512; i += 3 {
		bl.Remove(cidrFor(i))
	}
	for i := 0; i < 512; i += 5 {
		bl.Add(cidrFor(i)) // re-add some
	}

	if bl.netCount != len(bl.netKeys) {
		t.Errorf("index/storage drift: %d networks in buckets, %d dedupe keys", bl.netCount, len(bl.netKeys))
	}
	for i := 0; i < 512; i++ {
		in := bl.Contains(ipInCIDR(i))
		_, want := bl.netKeys[normalizeCIDRKey(t, cidrFor(i))]
		if in != want {
			t.Errorf("entry %d (%s): Contains=%v but key-set=%v", i, cidrFor(i), in, want)
		}
	}
}

// normalizeCIDRKey returns the canonical form Add dedupes on.
func normalizeCIDRKey(t *testing.T, s string) string {
	t.Helper()
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", s, err)
	}
	return ipnet.String()
}
