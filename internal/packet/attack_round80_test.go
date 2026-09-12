package packet

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ── R80: the IPv4 fragment plane hides the L4 header from every policy rule ──
//
// R79 fixed the IPv6 plane: the parser must read the L4 header the DESTINATION
// kernel will act on, at the offset the next-header chain resolves — including
// behind a Fragment header with offset 0 (a FIRST fragment, whose payload
// begins with the L4 header).
//
// The IPv4 plane was left with the pre-R79 shape. parseIPv4Packet populated
// the L4 fields from gopacket's DECODED layers, and gopacket refuses to decode
// the L4 layer of ANY fragmented IPv4 packet — measured on this host:
//
//	IPv4 (no fragment) + TCP SYN -> 22          -> protocol TCP, dst_port 22, SYN true
//	IPv4 first fragment (offset 0, MF) + TCP SYN -> protocol TCP, dst_port 0, no flags
//	IPv4 tiny fragment (8 L4 bytes, MF)          -> protocol TCP, dst_port 0, no flags
//
// The first-fragment shape is the exact analogue of the IPv6 case R79 fixed:
// the complete TCP header IS on the wire (the destination reassembles the
// datagram, the kernel processes the unchanged segment), but every rule keyed
// on a port or a flag sees zeros — blocked_ports, source-port filtering, SYN
// flood, port scan, protocol anomaly, state violation and ICMP type/code all
// go inert. An attacker therefore evades port blocking by splitting the
// segment into two IP fragments; the classic RFC 1858 "tiny fragment" variant
// puts only the first 8 bytes of the L4 header in fragment 1 so that even a
// parser which reads a first fragment's L4 header sees no ports.
//
// FragmentInfo.L4Incomplete is the second half of the fix: it marks a packet
// that MUST carry an L4 header but does not (a first fragment short of the
// protocol's minimum header size). The shipped policy denies such a packet
// (fail-closed on input that cannot be judged — the R40.3/R49 doctrine), which
// is what closes the tiny-fragment variant.

// ipv4Fragment builds an IPv4 packet carrying payload as a fragment with the
// given offset (8-byte units) and MF flag.
func ipv4Fragment(t *testing.T, protocol layers.IPProtocol, fragOffset uint16, mf bool, payload []byte) []byte {
	t.Helper()
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Id: 7, Protocol: protocol,
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

// rawTCPHeader builds a 20-byte TCP header with the given ports and SYN flag.
func rawTCPHeader(srcPort, dstPort uint16, syn bool) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:2], srcPort)
	binary.BigEndian.PutUint16(h[2:4], dstPort)
	if syn {
		h[13] = 0x02
	}
	return h
}

// rawUDPHeader builds an 8-byte UDP header with the given ports.
func rawUDPHeader(srcPort, dstPort uint16) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:2], srcPort)
	binary.BigEndian.PutUint16(h[2:4], dstPort)
	return h
}

// TestAttack_IPv4FirstFragmentHidesTCPPortsAndFlags proves that fragmenting a
// TCP segment makes the firewall blind to its ports and flags. Every case is a
// TCP SYN to blocked port 22 (blocked_ports = {22, 23, 3389, 5900, 5901}); the
// shipped deny_blocked_port rule requires protocol == "TCP" AND
// port_in_ranges(dst_port), so a packet reported with dst_port 0 is ALLOWED
// end to end while the destination reassembles and delivers the segment.
func TestAttack_IPv4FirstFragmentHidesTCPPortsAndFlags(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		want int
	}{
		{
			name: "first_fragment_complete_tcp_header",
			raw:  ipv4Fragment(t, layers.IPProtocolTCP, 0, true, rawTCPHeader(40000, 22, true)),
			want: 22,
		},
		{
			// The RFC 1858 tiny-fragment split: fragment 1 carries only the
			// first 8 bytes of the TCP header (which DO include both ports),
			// fragment 2 carries the rest.
			name: "tiny_fragment_8_l4_bytes",
			raw:  ipv4Fragment(t, layers.IPProtocolTCP, 0, true, rawTCPHeader(40000, 22, true)[:8]),
			want: 22,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info, err := ParsePacket(tc.raw)
			if err != nil {
				t.Fatalf("ParsePacket: %v", err)
			}
			if info.Protocol != "TCP" {
				t.Errorf("Protocol = %q, want %q", info.Protocol, "TCP")
			}
			if !info.Fragment.IsFragment || info.Fragment.Offset != 0 || !info.Fragment.MoreFragments {
				t.Errorf("fragment metadata = %+v, want a first fragment (offset 0, MF)", info.Fragment)
			}
			if tc.name == "first_fragment_complete_tcp_header" {
				if info.DstPort != 22 {
					t.Errorf("DstPort = %d, want 22 — the complete TCP header IS on the wire "+
						"(gopacket simply refuses to decode the L4 layer of a fragmented packet), so "+
						"reporting 0 makes deny_blocked_port inert for a fragmented SYN to a blocked port",
						info.DstPort)
				}
				if info.SrcPort != 40000 {
					t.Errorf("SrcPort = %d, want 40000", info.SrcPort)
				}
				if !info.TCPFlags.SYN {
					t.Error("TCPFlags.SYN = false, want true — deny_syn_flood and deny_port_scan " +
						"require the SYN flag and can never fire for a fragmented SYN")
				}
			} else {
				// A first fragment short of the 20-byte TCP header cannot be
				// judged at all: the parser must SAY so rather than report a
				// complete-looking zero-field packet the policy will allow.
				if !info.Fragment.L4Incomplete {
					t.Error("Fragment.L4Incomplete = false, want true — a first fragment carrying " +
						"only part of the L4 header is uninspectable (no ports, no flags), yet the " +
						"destination reassembles it and processes the segment: the classic RFC 1858 " +
						"tiny-fragment firewall evasion")
				}
			}
		})
	}
}

// TestAttack_IPv4FirstFragmentHidesUDPPort covers the UDP plane: the shipped
// deny_blocked_port and deny_source_port UDP branches never fire.
func TestAttack_IPv4FirstFragmentHidesUDPPort(t *testing.T) {
	raw := ipv4Fragment(t, layers.IPProtocolUDP, 0, true, rawUDPHeader(5353, 3389))
	info, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if info.Protocol != "UDP" {
		t.Errorf("Protocol = %q, want %q", info.Protocol, "UDP")
	}
	if info.DstPort != 3389 {
		t.Errorf("DstPort = %d, want 3389 (a blocked port)", info.DstPort)
	}
	if info.SrcPort != 5353 {
		t.Errorf("SrcPort = %d, want 5353", info.SrcPort)
	}
}

// TestAttack_IPv4FirstFragmentHidesICMPType proves the same gap suppresses
// ICMP type/code: blocked_icmp_types = {8} (echo request) is enabled by
// default, and it needs input.packet.icmp_type.
func TestAttack_IPv4FirstFragmentHidesICMPType(t *testing.T) {
	raw := ipv4Fragment(t, layers.IPProtocolICMPv4, 0, true, []byte{8, 0, 0, 0})
	info, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if info.Protocol != "ICMP" {
		t.Errorf("Protocol = %q, want %q", info.Protocol, "ICMP")
	}
	if info.ICMPType == nil {
		t.Fatal("ICMPType = nil, want 8 — blocked_icmp_types (default {8}) can never match, " +
			"so an ICMP echo request hidden in a first fragment is ALLOWED")
	}
	if *info.ICMPType != 8 {
		t.Errorf("ICMPType = %d, want 8", *info.ICMPType)
	}
}

// TestAttack_IPv4NonFirstFragmentContract is a regression guard: a NON-first
// fragment (offset > 0) carries no L4 header by definition, so it must keep
// the protocol-only contract — zero ports/flags and L4Incomplete FALSE (the
// datagram's FIRST fragment carries the header and is judged there; marking
// every continuation fragment uninspectable would deny all legitimate
// fragmented traffic).
func TestAttack_IPv4NonFirstFragmentContract(t *testing.T) {
	raw := ipv4Fragment(t, layers.IPProtocolTCP, 5, false, rawTCPHeader(40000, 22, true))
	info, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if info.Protocol != "TCP" {
		t.Errorf("Protocol = %q, want %q", info.Protocol, "TCP")
	}
	if info.SrcPort != 0 || info.DstPort != 0 {
		t.Errorf("ports = %d/%d, want 0/0 — continuation data is not an L4 header",
			info.SrcPort, info.DstPort)
	}
	if info.TCPFlags.SYN || info.TCPFlags.ACK || info.TCPFlags.RST || info.TCPFlags.FIN {
		t.Errorf("TCPFlags = %+v, want all false", info.TCPFlags)
	}
	if info.Fragment.L4Incomplete {
		t.Error("Fragment.L4Incomplete = true for a NON-first fragment — an L4 header is not " +
			"expected on the wire here, and denying continuation fragments would break every " +
			"legitimate fragmented datagram")
	}
}

// TestAttack_IPv4UnfragmentedStillJudged is the control: the same TCP SYN
// without the fragment wrapper keeps all of its evidence (so a fix cannot
// "block fragments" by accident — the difference must be the header read).
func TestAttack_IPv4UnfragmentedStillJudged(t *testing.T) {
	raw := ipv4Fragment(t, layers.IPProtocolTCP, 0, false, rawTCPHeader(40000, 22, true))
	info, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if info.Protocol != "TCP" || info.DstPort != 22 || !info.TCPFlags.SYN {
		t.Errorf("unfragmented SYN parsed as protocol=%q dst=%d syn=%v, want TCP/22/true",
			info.Protocol, info.DstPort, info.TCPFlags.SYN)
	}
	if info.Fragment.IsFragment {
		t.Error("IsFragment = true for an unfragmented packet")
	}
	if info.Fragment.L4Incomplete {
		t.Error("Fragment.L4Incomplete = true for a packet with a complete L4 header")
	}
}

// TestAttack_IPv6FirstFragmentL4Incomplete is the IPv6 counterpart of the
// tiny-fragment signal: the same contract must hold on both address families
// (R79's lesson — never fix one plane only). The builder from
// attack_round79_test.go is reused, so this file adds no duplicate helper.
func TestAttack_IPv6FirstFragmentL4Incomplete(t *testing.T) {
	// IPv6 + Fragment header (offset 0, M flag) + only 4 bytes of TCP header.
	full := buildV6Chain(layers.IPProtocolTCP, 40000, 22, []layers.IPProtocol{layers.IPProtocolIPv6Fragment})
	if len(full) < 48+4 {
		t.Fatalf("builder produced only %d bytes", len(full))
	}
	info, err := ParsePacket(full[:48+4])
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if !info.Fragment.IsFragment || info.Fragment.Offset != 0 {
		t.Fatalf("fragment metadata = %+v, want a first fragment", info.Fragment)
	}
	if !info.Fragment.L4Incomplete {
		t.Error("Fragment.L4Incomplete = false, want true — only 4 of the TCP header's 20 bytes " +
			"are on the wire behind a first-fragment header, so no L4-keyed rule can judge it")
	}
	if info.SrcPort != 0 || info.DstPort != 0 {
		t.Errorf("ports = %d/%d, want 0/0 (incomplete header must not be partially reported)",
			info.SrcPort, info.DstPort)
	}
}
