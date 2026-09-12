package engine

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/monch1962/l3-firewall/internal/packet"
)

// ── R80: IPv4 fragmentation hides the L4 header from the shipped policy ──────
//
// R79 fixed this class for IPv6 only: ONE attacker-prepended wrapper (an IPv6
// extension header) hid the L4 protocol/ports/flags from every rule, because
// the parser resolved them from gopacket's decoded layers instead of from the
// bytes the DESTINATION kernel acts on.
//
// The IPv4 plane carried the identical gap, with IP fragmentation as the
// wrapper: gopacket refuses to decode the L4 layer of ANY fragmented IPv4
// packet (MF set or offset > 0), so parseIPv4Packet reported protocol "TCP"
// with src_port/dst_port 0 and every flag false. Measured on this host
// (TestProbe, pre-fix):
//
//	whole   IPv4+TCP SYN -> 22 : allowed=false reason="blocked port 22 (TCP)"
//	frag(0,MF) same segment   : allowed=true  reason=""
//
// The destination reassembles the two fragments and processes the unchanged
// segment, so a port block (and every flag/ICMP-type rule) is evaded by
// splitting the segment into IP fragments. Two shapes matter:
//
//	(a) first fragment carrying the COMPLETE L4 header — fixed in the parser
//	    by reading the L4 bytes at IHL*4, exactly as the IPv6 chain walk does
//	    behind a Fragment header with offset 0;
//	(b) RFC 1858 "tiny fragment" — fragment 1 stops short of the 20-byte TCP
//	    header, so no ports are on the wire at all. No parser can judge it, so
//	    the parser reports fragment.l4_incomplete and the shipped policy
//	    denies it (fail-closed on uninspectable input).
//
// The engine-level assertions below go through the REAL production path
// (packet.ParsePacket → Engine.evaluatePacket with the shipped policy) and
// assert the deny REASON, which distinguishes "blocked by the rule that
// matters" from "blocked by accident".

// buildIPv4Fragment serializes an IPv4 packet carrying payload as a fragment
// with the given offset (8-byte units) and MF flag.
func buildIPv4Fragment(t *testing.T, protocol layers.IPProtocol, fragOffset uint16, mf bool, payload []byte) []byte {
	t.Helper()
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Id: 31337, Protocol: protocol,
		SrcIP: net.ParseIP("203.0.113.9"), DstIP: net.ParseIP("198.51.100.7"),
		FragOffset: fragOffset,
	}
	if mf {
		ip.Flags = layers.IPv4MoreFragments
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		ip, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serializing IPv4 fragment: %v", err)
	}
	return buf.Bytes()
}

// rawTCPHeaderBytes builds a 20-byte TCP header with the given ports and SYN flag.
func rawTCPHeaderBytes(srcPort, dstPort uint16, syn bool) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:2], srcPort)
	binary.BigEndian.PutUint16(h[2:4], dstPort)
	if syn {
		h[13] = 0x02
	}
	return h
}

// TestAttack_FragmentedSynBypassesBlockedPort is the core finding: the SAME
// TCP SYN to blocked port 22 is blocked as a whole packet and was ALLOWED when
// sent as a first IP fragment. The deny reason is asserted, not just the
// verdict — a fragmented SYN must be blocked because of the PORT rule, with the
// same reason the whole packet produces.
func TestAttack_FragmentedSynBypassesBlockedPort(t *testing.T) {
	segment := rawTCPHeaderBytes(40000, 22, true)

	// Control: the whole segment, no fragment wrapper.
	t.Run("whole_segment_blocked_by_port_rule", func(t *testing.T) {
		eng := newPolicyEngine(t)
		raw := buildIPv4Fragment(t, layers.IPProtocolTCP, 0, false, segment)
		pi, err := packet.ParsePacket(raw)
		if err != nil {
			t.Fatalf("ParsePacket: %v", err)
		}
		res := eng.evaluatePacket(pi, len(raw))
		if res.Allowed {
			t.Fatalf("whole TCP SYN -> 22 ALLOWED (reason %q); expected the blocked-port rule", res.Reason)
		}
		if res.Reason != "blocked port 22 (TCP)" {
			t.Errorf("reason = %q, want %q", res.Reason, "blocked port 22 (TCP)")
		}
	})

	// The attack: fragment 1 (offset 0, MF) carries the complete TCP header,
	// fragment 2 carries the payload. The destination reassembles both.
	t.Run("first_fragment_with_complete_header_blocked_by_port_rule", func(t *testing.T) {
		eng := newPolicyEngine(t)
		f1 := buildIPv4Fragment(t, layers.IPProtocolTCP, 0, true, segment)
		f2 := buildIPv4Fragment(t, layers.IPProtocolTCP, 5, false, make([]byte, 40))
		for i, raw := range [][]byte{f1, f2} {
			pi, err := packet.ParsePacket(raw)
			if err != nil {
				t.Fatalf("ParsePacket(fragment %d): %v", i+1, err)
			}
			res := eng.evaluatePacket(pi, len(raw))
			if i == 0 && res.Allowed {
				t.Errorf("first fragment carrying the COMPLETE TCP header was ALLOWED (reason %q): "+
					"the destination reassembles it and delivers the SYN to blocked port 22", res.Reason)
			}
			if i == 0 && !res.Allowed && res.Reason != "blocked port 22 (TCP)" {
				t.Errorf("first fragment reason = %q, want %q (blocked for the PORT, not incidentally)",
					res.Reason, "blocked port 22 (TCP)")
			}
			if i == 1 && !res.Allowed {
				t.Errorf("continuation fragment (offset 5) BLOCKED (reason %q): legitimate fragmented "+
					"traffic must keep flowing — the header is judged in the first fragment", res.Reason)
			}
		}
	})
}

// TestAttack_TinyFragmentBypassesEveryL4Rule covers the RFC 1858 shape: the
// first fragment stops short of the 20-byte TCP header, so no ports are on the
// wire. Nothing in the packet can be judged, so it must be denied fail-closed
// (fragment.l4_incomplete → the shipped policy's RULE 11b).
func TestAttack_TinyFragmentBypassesEveryL4Rule(t *testing.T) {
	eng := newPolicyEngine(t)
	// 8 bytes of TCP header in fragment 1 — enough for both ports, not for the
	// flag byte, and gopacket decodes no L4 layer for a fragmented packet at
	// all, so pre-R80 the policy saw protocol TCP with dst_port 0, SYN false.
	segment := rawTCPHeaderBytes(40000, 22, true)
	f1 := buildIPv4Fragment(t, layers.IPProtocolTCP, 0, true, segment[:8])
	pi, err := packet.ParsePacket(f1)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if !pi.Fragment.L4Incomplete {
		t.Fatal("parser did not mark the tiny first fragment incomplete — the policy has no way " +
			"to fail closed on a packet it cannot judge")
	}
	res := eng.evaluatePacket(pi, len(f1))
	if res.Allowed {
		t.Errorf("RFC 1858 tiny fragment ALLOWED (reason %q): every port and flag rule is inert for "+
			"it while the destination reassembles the segment", res.Reason)
	}
	if want := "uninspectable fragment: incomplete L4 header (RFC 1858 tiny fragment)"; res.Reason != want {
		t.Errorf("reason = %q, want %q", res.Reason, want)
	}
}

// TestAttack_FragmentedICMPEchoBypassesTypeBlock proves the same gap suppresses
// the ICMP type rule: blocked_icmp_types = {8} is enabled by default and needs
// input.packet.icmp_type, which a first fragment does not carry pre-fix.
func TestAttack_FragmentedICMPEchoBypassesTypeBlock(t *testing.T) {
	eng := newPolicyEngine(t)
	raw := buildIPv4Fragment(t, layers.IPProtocolICMPv4, 0, true, []byte{8, 0, 0, 0})
	pi, err := packet.ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	res := eng.evaluatePacket(pi, len(raw))
	if res.Allowed {
		t.Errorf("ICMP echo request (type 8) inside a first fragment ALLOWED (reason %q) — "+
			"blocked_icmp_types = {8} is enabled by default and can never match", res.Reason)
	}
	if res.Reason != "blocked ICMP type=8 code=0" {
		t.Errorf("reason = %q, want %q", res.Reason, "blocked ICMP type=8 code=0")
	}
}

// TestAttack_FragmentedBenignTrafficStillAllowed is the false-block guard: a
// fragmented datagram to a NON-blocked port must still be allowed on every
// fragment — the fix must not become "deny all fragments" (the shipped default
// leaves fragment-flood policing to the generic rate rules; enable_fragment
// stays false).
func TestAttack_FragmentedBenignTrafficStillAllowed(t *testing.T) {
	eng := newPolicyEngine(t)
	segment := rawTCPHeaderBytes(40000, 443, true)
	f1 := buildIPv4Fragment(t, layers.IPProtocolTCP, 0, true, segment)
	f2 := buildIPv4Fragment(t, layers.IPProtocolTCP, 5, false, make([]byte, 40))
	for i, raw := range [][]byte{f1, f2} {
		pi, err := packet.ParsePacket(raw)
		if err != nil {
			t.Fatalf("ParsePacket(fragment %d): %v", i+1, err)
		}
		if pi.Fragment.L4Incomplete {
			t.Errorf("fragment %d marked incomplete, want false", i+1)
		}
		res := eng.evaluatePacket(pi, len(raw))
		if !res.Allowed {
			t.Errorf("benign fragmented traffic to port 443 BLOCKED on fragment %d (reason %q) — "+
				"the deny-override contract must hold for legitimate fragments", i+1, res.Reason)
		}
	}
}
