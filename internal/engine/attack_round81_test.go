package engine

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/monch1962/l3-firewall/internal/packet"
)

// ── R81: RULE 7's ICMP controls are IPv4-literal ────────────────────────────
//
// R79 taught internal/packet to classify ICMPv6 as protocol "ICMPv6" and to
// populate icmp_type/icmp_code for it. The shipped policy was deliberately left
// keyed on protocol == "ICMP" so IPv4-tuned thresholds would not police IPv6
// NDP/router-advertisement traffic — but nothing was added for the
// family-neutral half of the control:
//
//	deny_icmp      if { input.packet.protocol == "ICMP"; blocked_icmp_types[input.packet.icmp_type] }
//	deny_icmp_flood if { input.packet.protocol == "ICMP"; input.rate.src_ip_pps > icmp_rate_per_second }
//
// Neither body can ever be true for an ICMPv6 packet, and `blocked_icmp_types`
// is only consulted inside them — so an operator who writes
// `blocked_icmp_types := {8, 128}` still cannot block an IPv6 echo request,
// and the ICMP flood control simply does not exist on the IPv6 plane. Measured
// pre-fix through the real production path with the shipped policy:
//
//	IPv4 ICMP echo request  : allowed=false reason="blocked ICMP type=8 code=0"
//	IPv6 ICMPv6 echo request: allowed=true  reason=""
//	IPv4 ICMP echo flood    : allowed=false reason="ICMP flood detected"
//	IPv6 ICMPv6 echo flood  : allowed=true  reason=""
//
// The destination host answers the IPv6 echo request just as it answers the
// IPv4 one, so "block ping, rate-limit ICMP floods" is a control the firewall
// silently does not implement for half the address space. The fixes keep NDP
// untouched: the v6 type set defaults to {128} (echo request — the v6 twin of
// IPv4 type 8) and the v6 flood threshold is 10x the IPv4 one, well above
// legitimate neighbour-discovery bursts.

// buildICMPv6Packet serializes an IPv6 packet carrying an ICMPv6 message.
func buildICMPv6Packet(t *testing.T, src, dst string, icmpType, code uint8) []byte {
	t.Helper()
	ip6 := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   64,
		SrcIP:      net.ParseIP(src),
		DstIP:      net.ParseIP(dst),
	}
	icmp6 := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(icmpType, code)}
	if err := icmp6.SetNetworkLayerForChecksum(ip6); err != nil {
		t.Fatalf("ICMPv6 checksum: %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		ip6, icmp6); err != nil {
		t.Fatalf("serializing ICMPv6 packet: %v", err)
	}
	return buf.Bytes()
}

// buildICMPv4Packet serializes an IPv4 packet carrying an ICMPv4 message.
func buildICMPv4Packet(t *testing.T, src, dst string, icmpType, code uint8) []byte {
	t.Helper()
	ip4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Id: 4242,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    net.ParseIP(src),
		DstIP:    net.ParseIP(dst),
	}
	icmp4 := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(icmpType, code)}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		ip4, icmp4); err != nil {
		t.Fatalf("serializing ICMPv4 packet: %v", err)
	}
	return buf.Bytes()
}

// TestAttack_ICMPv6EchoRequestBypassesTypeBlock is the core finding: the SAME
// "block echo request" control that denies an IPv4 ping allows its IPv6 twin.
// The reason is asserted so the packet is blocked by the ICMPv6 type rule and
// not incidentally.
func TestAttack_ICMPv6EchoRequestBypassesTypeBlock(t *testing.T) {
	t.Run("ipv4_control_blocked_by_type_rule", func(t *testing.T) {
		eng := newPolicyEngine(t)
		raw := buildICMPv4Packet(t, "198.51.100.9", "198.51.100.7", 8, 0) // echo request
		pi, err := packet.ParsePacket(raw)
		if err != nil {
			t.Fatalf("ParsePacket: %v", err)
		}
		res := eng.evaluatePacket(pi, len(raw))
		if res.Allowed {
			t.Fatalf("IPv4 echo request ALLOWED (reason %q); expected blocked_icmp_types", res.Reason)
		}
		if res.Reason != "blocked ICMP type=8 code=0" {
			t.Errorf("IPv4 reason = %q, want %q", res.Reason, "blocked ICMP type=8 code=0")
		}
	})

	t.Run("ipv6_echo_request_blocked_by_type_rule", func(t *testing.T) {
		eng := newPolicyEngine(t)
		raw := buildICMPv6Packet(t, "2001:db8::9", "2001:db8::7", 128, 0) // echo request
		pi, err := packet.ParsePacket(raw)
		if err != nil {
			t.Fatalf("ParsePacket: %v", err)
		}
		res := eng.evaluatePacket(pi, len(raw))
		if res.Allowed {
			t.Errorf("ICMPv6 echo request ALLOWED (reason %q): blocked_icmp_types (echo request) "+
				"is never consulted for protocol \"ICMPv6\", so 'block ping' does not exist on the v6 plane",
				res.Reason)
		}
		if res.Reason != "blocked ICMPv6 type=128 code=0" {
			t.Errorf("reason = %q, want %q (blocked for the TYPE, not incidentally)",
				res.Reason, "blocked ICMPv6 type=128 code=0")
		}
	})
}

// TestAttack_ICMPv6NeighborSolicitationNotFalseBlocked pins the scope of the
// fix: NDP (type 135 neighbour solicitation) is legitimate IPv6 plumbing and
// must keep flowing — an over-broad "block all ICMPv6" fix would break every
// IPv6 network.
func TestAttack_ICMPv6NeighborSolicitationNotFalseBlocked(t *testing.T) {
	eng := newPolicyEngine(t)
	raw := buildICMPv6Packet(t, "2001:db8::9", "2001:db8::7", 135, 0) // neighbour solicitation
	pi, err := packet.ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if res := eng.evaluatePacket(pi, len(raw)); !res.Allowed {
		t.Errorf("ICMPv6 neighbour solicitation BLOCKED (reason %q): NDP must not be policed "+
			"by the ICMP echo/flood controls", res.Reason)
	}
}

// TestAttack_ICMPv6FloodBypassesFloodControl proves the flood half: a burst of
// ICMPv6 echo replies (type 129 — not in any blocked-type set) from one source
// is never denied, while the identical IPv4 burst trips deny_icmp_flood.
func TestAttack_ICMPv6FloodBypassesFloodControl(t *testing.T) {
	const burst = 120

	t.Run("ipv4_control_flood_blocked", func(t *testing.T) {
		eng := newPolicyEngine(t)
		raw := buildICMPv4Packet(t, "198.51.100.9", "198.51.100.7", 0, 0) // echo reply
		pi, err := packet.ParsePacket(raw)
		if err != nil {
			t.Fatalf("ParsePacket: %v", err)
		}
		blocked, reason := false, ""
		for i := 0; i < burst; i++ {
			res := eng.evaluatePacket(pi, len(raw))
			if !res.Allowed {
				blocked, reason = true, res.Reason
				break
			}
		}
		if !blocked {
			t.Fatalf("%d IPv4 echo replies ALLOWED; deny_icmp_flood (10 pps) never fired", burst)
		}
		if reason != "ICMP flood detected" {
			t.Errorf("IPv4 flood reason = %q, want %q", reason, "ICMP flood detected")
		}
	})

	t.Run("ipv6_flood_blocked", func(t *testing.T) {
		eng := newPolicyEngine(t)
		raw := buildICMPv6Packet(t, "2001:db8::9", "2001:db8::7", 129, 0) // echo reply
		pi, err := packet.ParsePacket(raw)
		if err != nil {
			t.Fatalf("ParsePacket: %v", err)
		}
		blocked, reason := false, ""
		for i := 0; i < burst; i++ {
			res := eng.evaluatePacket(pi, len(raw))
			if !res.Allowed {
				blocked, reason = true, res.Reason
				break
			}
		}
		if !blocked {
			t.Errorf("%d ICMPv6 echo replies from one source ALLOWED: deny_icmp_flood is keyed "+
				"on protocol == \"ICMP\", so ICMP floods are unpoliced on the IPv6 plane", burst)
		} else if reason != "ICMPv6 flood detected" {
			t.Errorf("IPv6 flood reason = %q, want %q", reason, "ICMPv6 flood detected")
		}
	})
}
