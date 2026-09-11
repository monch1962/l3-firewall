package engine

import (
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/monch1962/l3-firewall/internal/packet"
)

// ── R79: the IPv6 plane is broken in both directions ─────────────────────────
//
// R79.1 (this file, engine/integration): the shipped policy's `allowed_subnets`
// is an IPv4-only wildcard, and net.cidr_contains() is family-strict, so
// ip_in_subnets() is false for EVERY IPv6 address — RULE 1 (deny_ip_spoofing)
// and RULE 5 (deny_ingress_egress) are enabled by default and fire on that
// false. Result: the firewall denies 100% of IPv6 traffic with
// reason "IP spoofing detected" in its shipped configuration, violating the
// deny-override contract ("traffic passes by default") for an entire address
// family — while internal/packet parses IPv6 (extension headers included).
//
// R79.2 (internal/packet + this file): once the allowlist is family-complete
// (the only way to make the firewall usable on IPv6), the parser's failure to
// resolve the L4 protocol behind an IPv6 extension header becomes a fail-open:
// ONE prepended HopByHop/Routing/Destination-Options/Fragment header turns a
// TCP SYN to blocked port 22 into protocol "IP-0"/"IP-43"/"IP-60"/"IP-44" with
// ports 0 and no flags, so every L4-keyed deny rule goes inert AND the
// destination kernel still delivers the unchanged segment.
//
// These two findings are complementary — fixing only one is worse than fixing
// neither, which is why they land in the same round.

// buildRawIPv6ExtPacket serializes an IPv6 packet carrying the given
// extension-header chain in front of a TCP SYN (l4 === layers.IPProtocolTCP) or
// a UDP segment. Serialization uses FixLengths so gopacket can decode the L4
// layer — the pre-existing ipv6_test.go builder omits it, which is why the
// ext-header path was never actually exercised.
func buildRawIPv6ExtPacket(t *testing.T, l4 layers.IPProtocol, srcPort, dstPort uint16, chain []layers.IPProtocol) []byte {
	t.Helper()

	first := l4
	if len(chain) > 0 {
		first = chain[0]
	}
	ip6 := &layers.IPv6{
		Version:    6,
		NextHeader: first,
		HopLimit:   64,
		SrcIP:      []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		DstIP:      []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
	}

	var l4Layer gopacket.SerializableLayer
	switch l4 {
	case layers.IPProtocolTCP:
		l4Layer = &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort),
			Seq: 12345, SYN: true, Window: 65535}
	case layers.IPProtocolUDP:
		l4Layer = &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	default:
		t.Fatalf("unsupported L4 protocol %v", l4)
	}
	if err := l4Layer.(interface {
		SetNetworkLayerForChecksum(gopacket.NetworkLayer) error
	}).SetNetworkLayerForChecksum(ip6); err != nil {
		t.Fatalf("checksum: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, ip6, l4Layer); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	full := buf.Bytes()
	if len(chain) == 0 {
		return full
	}

	var ext []byte
	for i, p := range chain {
		next := l4
		if i+1 < len(chain) {
			next = chain[i+1]
		}
		if p == layers.IPProtocolIPv6Fragment {
			ext = append(ext, byte(next), 0, 0, 0x01, 0, 0, 0, 1) // offset 0, M set
			continue
		}
		ext = append(ext, byte(next), 0, 1, 0, 0, 0, 0, 0) // Hdr Ext Len = 0 (8 bytes)
	}

	out := make([]byte, 0, 40+len(ext)+len(full)-40)
	out = append(out, full[:40]...)
	out = append(out, ext...)
	out = append(out, full[40:]...)
	plen := len(out) - 40
	out[4], out[5] = byte(plen>>8), byte(plen&0xff)
	return out
}

// TestAttack_ShippedPolicyDropsAllIPv6Traffic proves R79.1 end to end through
// the production wiring (packet.ParsePacket → Engine.evaluatePacket → the
// shipped opa-policies/l3.rego): a benign IPv6 TCP SYN to port 80 — allowed by
// default on IPv4 — is DENIED with reason "IP spoofing detected", and so is
// every other IPv6 packet. The firewall's documented "deny-override: traffic
// passes by default" contract is violated for the whole IPv6 address family.
func TestAttack_ShippedPolicyDropsAllIPv6Traffic(t *testing.T) {
	benign := []struct {
		name  string
		chain []layers.IPProtocol
		l4    layers.IPProtocol
		dst   uint16
	}{
		{"tcp_80", nil, layers.IPProtocolTCP, 80},
		{"udp_53", nil, layers.IPProtocolUDP, 53},
		{"tcp_443_hopbyhop", []layers.IPProtocol{layers.IPProtocolIPv6HopByHop}, layers.IPProtocolTCP, 443},
	}
	for _, tc := range benign {
		t.Run(tc.name, func(t *testing.T) {
			eng := newPolicyEngine(t)
			raw := buildRawIPv6ExtPacket(t, tc.l4, 40000, tc.dst, tc.chain)
			pi, err := packet.ParsePacket(raw)
			if err != nil {
				t.Fatalf("ParsePacket: %v", err)
			}
			res := eng.evaluatePacket(pi, len(raw))
			if !res.Allowed {
				t.Errorf("benign IPv6 packet DENIED (reason %q): allowed_subnets is an IPv4-only "+
					"wildcard {0.0.0.0/0}, net.cidr_contains() never contains an IPv6 address in an "+
					"IPv4 CIDR, so RULE 1/RULE 5 deny EVERY IPv6 packet as source spoofing — the "+
					"shipped default policy silently drops 100%% of IPv6 traffic", res.Reason)
			}
		})
	}
}

// TestAttack_CraftedIPv6ExtensionHeaderBypassesBlockedPort proves R79.2 end to
// end: an attacker-prepended IPv6 extension header must not be able to hide a
// blocked-port TCP/UDP packet from the policy. The packet flows through the
// REAL production path (packet.ParsePacket → evaluatePacket → shipped policy),
// and the assertion is on the DENY REASON, not merely on "not allowed":
//
//	pre-R79.1-fix  → denied as "IP spoofing detected" (the all-IPv6 block masked
//	                 the bypass; the reason assertion fails, exposing it)
//	post-R79.1-fix → ALLOWED (the bypass, live)
//	post-R79.2-fix → denied as "blocked port 22 (TCP)" — the port rule fires
func TestAttack_CraftedIPv6ExtensionHeaderBypassesBlockedPort(t *testing.T) {
	cases := []struct {
		name  string
		chain []layers.IPProtocol
		l4    layers.IPProtocol
		src   uint16
		dst   uint16
		want  string
	}{
		{"hop_by_hop_tcp_22", []layers.IPProtocol{layers.IPProtocolIPv6HopByHop}, layers.IPProtocolTCP, 40000, 22, "blocked port 22 (TCP)"},
		{"destination_options_tcp_22", []layers.IPProtocol{layers.IPProtocolIPv6Destination}, layers.IPProtocolTCP, 40000, 22, "blocked port 22 (TCP)"},
		{"routing_tcp_3389", []layers.IPProtocol{layers.IPProtocolIPv6Routing}, layers.IPProtocolTCP, 40000, 3389, "blocked port 3389 (TCP)"},
		{"fragment_tcp_22", []layers.IPProtocol{layers.IPProtocolIPv6Fragment}, layers.IPProtocolTCP, 40000, 22, "blocked port 22 (TCP)"},
		{"chained_hopbyhop_destopt_tcp_23", []layers.IPProtocol{layers.IPProtocolIPv6HopByHop, layers.IPProtocolIPv6Destination}, layers.IPProtocolTCP, 40000, 23, "blocked port 23 (TCP)"},
		{"destination_options_udp_3389", []layers.IPProtocol{layers.IPProtocolIPv6Destination}, layers.IPProtocolUDP, 5353, 3389, "blocked port 3389 (UDP)"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := newPolicyEngine(t)
			raw := buildRawIPv6ExtPacket(t, tc.l4, tc.src, tc.dst, tc.chain)
			pi, err := packet.ParsePacket(raw)
			if err != nil {
				t.Fatalf("ParsePacket: %v", err)
			}
			res := eng.evaluatePacket(pi, len(raw))
			if res.Allowed {
				t.Errorf("crafted IPv6 packet to blocked port %d was ALLOWED (reason %q): the "+
					"extension header %v hides the L4 header, so the parser reports protocol %q "+
					"with ports 0 and no flags and every L4-keyed deny rule goes inert — the "+
					"destination kernel strips the extension header and delivers the segment",
					tc.dst, res.Reason, tc.chain, pi.Protocol)
				return
			}
			if !strings.Contains(res.Reason, tc.want) {
				t.Errorf("blocked for the WRONG reason: %q, want it to contain %q — the packet "+
					"must be stopped by the port rule it trips, not by an unrelated default",
					res.Reason, tc.want)
			}
		})
	}
}

// TestAttack_IPv6BlockedPortStillDeniedWithoutExtensionHeader is the control:
// the same blocked-port packets WITHOUT an extension header are already denied
// for the port reason, which is exactly what the ext-header cases must match.
// It also pins that R79 did not weaken the plain-IPv6 path.
func TestAttack_IPv6BlockedPortStillDeniedWithoutExtensionHeader(t *testing.T) {
	eng := newPolicyEngine(t)
	raw := buildRawIPv6ExtPacket(t, layers.IPProtocolTCP, 40000, 22, nil)
	pi, err := packet.ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	res := eng.evaluatePacket(pi, len(raw))
	if res.Allowed {
		t.Fatalf("plain IPv6 TCP SYN to port 22 was ALLOWED (reason %q)", res.Reason)
	}
	if !strings.Contains(res.Reason, "blocked port 22 (TCP)") {
		t.Errorf("reason = %q, want it to contain %q", res.Reason, "blocked port 22 (TCP)")
	}
}
