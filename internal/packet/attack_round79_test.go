package packet

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ── R79: IPv6 extension headers hide the L4 header from the firewall ─────────
//
// parseIPv6Packet resolved the L4 protocol used to populate Protocol/SrcPort/
// DstPort/TCPFlags with
//
//	for _, layer := range packet.Layers() {
//	    if name, ok := extHeaderTypes[layer.LayerType()]; ok {
//	        if ext, ok2 := layer.(interface{ NextLayerType() gopacket.LayerType }); ok2 {
//	            l4Proto = ipv6ProtoFromLayer(ext.NextLayerType())
//	        }
//	    }
//	}
//
// None of the four IPv6 extension-header layer types (*layers.IPv6HopByHop,
// *layers.IPv6Routing, *layers.IPv6Destination, *layers.IPv6Fragment)
// implements NextLayerType(), so the type assertion NEVER succeeds:
// ipv6ProtoFromLayer is unreachable dead code (0% coverage) and l4Proto stays
// at ipv6.NextHeader — the extension header's OWN protocol number (0/43/44/60)
// — instead of the encapsulated L4 protocol.
//
// populateL4 then takes its default branch, so an attacker who prepends ONE
// IPv6 extension header to a TCP/UDP packet gets a PacketInfo with
//
//	Protocol = "IP-0" / "IP-43" / "IP-44" / "IP-60"
//	SrcPort  = 0, DstPort = 0, TCPFlags = all false
//
// while the destination kernel processes the extension header chain normally
// and delivers the unchanged TCP/UDP segment. Every L4-keyed deny rule in the
// shipped policy (blocked_ports, source-port filtering, SYN flood, port scan,
// protocol anomaly, state violation) requires protocol == "TCP"/"UDP" or a
// flag/port value, so all of them go inert for such packets.
//
// The Go builders are deliberately independent of the ones in ipv6_test.go:
// those serialize with gopacket.SerializeOptions{} (FixLengths=false), which
// leaves IPv6.Length at 0 so gopacket never decodes the L4 layer at all —
// which is why TestIPv6NoExtensionHeaders/TestIPv6WithHopByHop asserted only
// Protocol (read from the IPv6 header) and the extension-header NAME, never
// the ports or flags that the firewall's policy actually keys on.

// buildV6Chain serializes an IPv6 packet carrying the given extension-header
// chain in front of a TCP SYN (l4Proto TCP) or UDP segment. The chain's
// next-header fields are wired so the last entry points at l4Proto.
func buildV6Chain(l4Proto layers.IPProtocol, srcPort, dstPort uint16, chain []layers.IPProtocol) []byte {
	first := l4Proto
	if len(chain) > 0 {
		first = chain[0]
	}
	ip6 := &layers.IPv6{
		Version:    6,
		NextHeader: first,
		HopLimit:   64,
		SrcIP:      parseIP6("2001:db8::1"),
		DstIP:      parseIP6("2001:db8::2"),
	}

	var l4 gopacket.SerializableLayer
	switch l4Proto {
	case layers.IPProtocolUDP:
		l4 = &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	case layers.IPProtocolTCP:
		l4 = &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort),
			Seq: 12345, SYN: true, ACK: false, Window: 65535}
	default:
		panic("buildV6Chain: unsupported L4")
	}
	if err := l4.(interface {
		SetNetworkLayerForChecksum(gopacket.NetworkLayer) error
	}).SetNetworkLayerForChecksum(ip6); err != nil {
		panic(err)
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, ip6, l4); err != nil {
		panic(err)
	}
	full := buf.Bytes()
	if len(chain) == 0 {
		return full
	}

	var ext []byte
	for i, p := range chain {
		next := l4Proto
		if i+1 < len(chain) {
			next = chain[i+1]
		}
		if p == layers.IPProtocolIPv6Fragment {
			// Fixed 8 bytes: next-header, reserved, offset+flags, identification.
			// Offset 0 with the M flag set — a first fragment, whose payload
			// carries the full L4 header.
			ext = append(ext, byte(next), 0, 0, 0x01, 0, 0, 0, 1)
			continue
		}
		// HopByHop / Routing / Destination Options: next-header, Hdr Ext Len=0
		// (8 bytes), six padding bytes (PadN).
		ext = append(ext, byte(next), 0, 1, 0, 0, 0, 0, 0)
	}

	out := make([]byte, 0, 40+len(ext)+len(full)-40)
	out = append(out, full[:40]...)
	out = append(out, ext...)
	out = append(out, full[40:]...)
	plen := len(out) - 40
	out[4], out[5] = byte(plen>>8), byte(plen&0xff)
	return out
}

// TestAttack_IPv6ExtensionHeaderHidesTCPPortsAndFlags proves that an attacker
// can strip the port and flag evidence from a TCP packet the firewall must
// judge, by prepending a single IPv6 extension header. Every case below is a
// TCP SYN to blocked port 22 (blocked_ports = {22, 23, 3389, 5900, 5901}) —
// the shipped policy's deny_blocked_port requires protocol == "TCP" and
// port_in_ranges(dst_port), so a misclassified packet is ALLOWED end to end.
func TestAttack_IPv6ExtensionHeaderHidesTCPPortsAndFlags(t *testing.T) {
	cases := []struct {
		name  string
		chain []layers.IPProtocol
	}{
		{"hop_by_hop", []layers.IPProtocol{layers.IPProtocolIPv6HopByHop}},
		{"routing", []layers.IPProtocol{layers.IPProtocolIPv6Routing}},
		{"destination_options", []layers.IPProtocol{layers.IPProtocolIPv6Destination}},
		{"fragment_first", []layers.IPProtocol{layers.IPProtocolIPv6Fragment}},
		{"chained_hop_by_hop_destination", []layers.IPProtocol{layers.IPProtocolIPv6HopByHop, layers.IPProtocolIPv6Destination}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Attacker: IPv6 + extension header(s) + TCP SYN 40000 -> 22.
			raw := buildV6Chain(layers.IPProtocolTCP, 40000, 22, tc.chain)

			info, err := ParsePacket(raw)
			if err != nil {
				t.Fatalf("ParsePacket: %v", err)
			}
			if info.SrcIP != "2001:db8::1" || info.DstIP != "2001:db8::2" {
				t.Fatalf("IPs = %s/%s, want 2001:db8::1/2001:db8::2", info.SrcIP, info.DstIP)
			}
			if info.Protocol != "TCP" {
				t.Errorf("Protocol = %q, want %q — the L4 protocol is hidden behind an IPv6 "+
					"extension header, so every policy rule keyed on protocol == \"TCP\" "+
					"(blocked_ports, SYN flood, port scan, protocol anomaly, state violation) "+
					"goes inert for this packet", info.Protocol, "TCP")
			}
			if info.DstPort != 22 {
				t.Errorf("DstPort = %d, want 22 — blocked_ports = {22,23,3389,5900,5901} cannot match "+
					"a zeroed port, so a SYN to a blocked port is ALLOWED", info.DstPort)
			}
			if info.SrcPort != 40000 {
				t.Errorf("SrcPort = %d, want 40000", info.SrcPort)
			}
			if !info.TCPFlags.SYN {
				t.Error("TCPFlags.SYN = false, want true — deny_syn_flood and deny_port_scan both " +
					"require the SYN flag and can never fire without it")
			}
			if len(info.IPv6ExtHeaders) != len(tc.chain) {
				t.Errorf("IPv6ExtHeaders = %v, want %d entries", info.IPv6ExtHeaders, len(tc.chain))
			}
		})
	}
}

// TestAttack_IPv6ExtensionHeaderHidesUDPPort proves the same classification gap
// hides a UDP destination port: the shipped policy's UDP port rules
// (deny_blocked_port UDP branch, deny_source_port UDP branch) never fire.
func TestAttack_IPv6ExtensionHeaderHidesUDPPort(t *testing.T) {
	raw := buildV6Chain(layers.IPProtocolUDP, 5353, 3389,
		[]layers.IPProtocol{layers.IPProtocolIPv6Destination})

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

// TestAttack_IPv6ICMPv6Unclassified proves ICMPv6 packets are not identified as
// ICMP at all (protocol "IP-58", nil type/code): the firewall cannot report,
// log, or police ICMPv6 (echo requests, NDP, router advertisements) and the
// OPA input document carries no icmp_type for them. R79 classifies them as
// "ICMPv6" and populates icmp_type/icmp_code; the shipped policy's ICMP rules
// are keyed on protocol == "ICMP" (IPv4) and are deliberately unchanged, so
// this fix adds visibility without changing default enforcement.
func TestAttack_IPv6ICMPv6Unclassified(t *testing.T) {
	ip6 := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: 64,
		SrcIP: parseIP6("2001:db8::1"), DstIP: parseIP6("2001:db8::2")}
	icmp6 := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(128, 0)} // echo request
	if err := icmp6.SetNetworkLayerForChecksum(ip6); err != nil {
		t.Fatalf("checksum: %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, ip6, icmp6); err != nil {
		t.Fatalf("serialize: %v", err)
	}

	info, err := ParsePacket(buf.Bytes())
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if info.Protocol != "ICMPv6" {
		t.Errorf("Protocol = %q, want %q (was %q — the raw IANA protocol number, which no "+
			"policy rule or conntrack timeout matches)", info.Protocol, "ICMPv6", "IP-58")
	}
	if info.ICMPType == nil {
		t.Fatal("ICMPType = nil, want 128 (echo request) — the OPA input's icmp_type is absent " +
			"for ICMPv6, so blocked_icmp_types / blocked_icmp_codes can never match")
	}
	if *info.ICMPType != 128 {
		t.Errorf("ICMPType = %d, want 128", *info.ICMPType)
	}
	if info.ICMPCode == nil || *info.ICMPCode != 0 {
		t.Errorf("ICMPCode = %v, want 0", info.ICMPCode)
	}
}

// TestAttack_IPv6ExtensionHeaderChainBounded is a regression guard: the chain
// walk must terminate on a crafted chain that never reaches an L4 protocol
// (here: 40 nested HopByHop headers whose next-header always points at another
// HopByHop) without panicking or reading past the packet.
func TestAttack_IPv6ExtensionHeaderChainBounded(t *testing.T) {
	var chain []layers.IPProtocol
	for i := 0; i < 40; i++ {
		chain = append(chain, layers.IPProtocolIPv6HopByHop)
	}
	// The chain's last entry points back at HopByHop, i.e. no L4 header at all.
	raw := buildV6Chain(layers.IPProtocolTCP, 40000, 22, chain)

	info, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket returned an error for a deep chain: %v", err)
	}
	if len(info.IPv6ExtHeaders) > 40 {
		t.Errorf("IPv6ExtHeaders = %d entries, want <= 40", len(info.IPv6ExtHeaders))
	}
}

// TestAttack_IPv6PlainPacketUnaffected is a regression guard for the working
// path: an IPv6 packet with NO extension header must keep its ports and flags
// (asserted by TestParseIPv6Packet already, repeated here next to the fix for
// the ext-header cases so a future regression is caught by the same file).
func TestAttack_IPv6PlainPacketUnaffected(t *testing.T) {
	raw := buildV6Chain(layers.IPProtocolTCP, 40001, 443, nil)
	info, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if info.Protocol != "TCP" || info.DstPort != 443 || !info.TCPFlags.SYN || info.SrcPort != 40001 {
		t.Errorf("plain IPv6 TCP parsed as protocol=%q src=%d dst=%d flags=%+v, want TCP/40001/443/SYN",
			info.Protocol, info.SrcPort, info.DstPort, info.TCPFlags)
	}
	if len(info.IPv6ExtHeaders) != 0 {
		t.Errorf("IPv6ExtHeaders = %v, want empty", info.IPv6ExtHeaders)
	}
}

// TestAttack_IPv6TruncatedExtensionHeaderChain pins the truncated-chain
// contract: when the declared extension header (or the L4 header behind it) is
// not actually on the wire, the parser must report the declared protocol and
// ZERO L4 fields — never invent ports/flags from bytes that are not there. The
// firewall still makes a policy decision on such a packet (packetHandler drops
// only packets ParsePacket rejects), so a fabricated port would fabricate deny
// evidence; a fabricated *flag* could equally hide one.
func TestAttack_IPv6TruncatedExtensionHeaderChain(t *testing.T) {
	full := buildV6Chain(layers.IPProtocolTCP, 40000, 22,
		[]layers.IPProtocol{layers.IPProtocolIPv6HopByHop})
	if len(full) < 60 {
		t.Fatalf("builder produced only %d bytes", len(full))
	}

	cases := []struct {
		name string
		raw  []byte
		want string // expected protocol
	}{
		{"declared_ext_header_absent", full[:40], "IP-0"},    // NextHeader says HopByHop, no ext bytes
		{"ext_header_cut_before_l4", full[:45], "TCP"},       // HopByHop present, TCP header missing
		{"ext_header_cut_before_l4_short", full[:43], "TCP"}, // same, mid-HopByHop
		{"l4_header_cut_midway", full[:52], "TCP"},           // 4 of 20 TCP bytes present
		{"complete_packet_control", full, "TCP"},             // control: full packet keeps its ports
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info, err := ParsePacket(tc.raw)
			if err != nil {
				t.Fatalf("ParsePacket(%d bytes): %v", len(tc.raw), err)
			}
			if info.Protocol != tc.want {
				t.Errorf("Protocol = %q, want %q", info.Protocol, tc.want)
			}
			if tc.name != "complete_packet_control" {
				if info.DstPort != 0 || info.SrcPort != 0 {
					t.Errorf("ports = %d/%d, want 0/0 — no L4 header is on the wire, "+
						"so any port reported here is fabricated from payload bytes",
						info.SrcPort, info.DstPort)
				}
				if info.TCPFlags.SYN || info.TCPFlags.ACK || info.TCPFlags.RST || info.TCPFlags.FIN {
					t.Errorf("TCPFlags = %+v, want all false", info.TCPFlags)
				}
			}
		})
	}
}
