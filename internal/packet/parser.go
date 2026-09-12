// Package packet provides L3/L4 packet header parsing using gopacket.
package packet

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TCPFlags represents the TCP control flags present in a packet.
type TCPFlags struct {
	SYN bool `json:"syn"`
	ACK bool `json:"ack"`
	RST bool `json:"rst"`
	FIN bool `json:"fin"`
}

// FragmentInfo holds IP fragmentation information.
type FragmentInfo struct {
	IsFragment    bool `json:"is_fragment"`
	MoreFragments bool `json:"more_fragments"`
	Offset        int  `json:"offset"` // fragment offset in 8-byte units
	// L4Incomplete reports a packet that MUST carry an L4 header but does not
	// (R80): a first fragment (offset 0) short of its protocol's minimum
	// header size, at either address family. No L4-keyed rule can judge such a
	// packet — it has no ports, flags or ICMP type on the wire — while the
	// destination reassembles the datagram and processes the segment (the
	// classic RFC 1858 tiny-fragment firewall evasion). The shipped policy
	// denies it (fail-closed on input that cannot be judged, the R40.3/R49
	// doctrine for uninspectable packets).
	//
	// Always false for a NON-first fragment (offset > 0): an L4 header is not
	// expected on the wire there — the datagram's FIRST fragment carries it and
	// is judged there. Marking continuation fragments would deny every
	// legitimate fragmented datagram.
	L4Incomplete bool `json:"l4_incomplete"`
}

// IPv6ExtHeaderType is a string representation of an IPv6 extension header.
type IPv6ExtHeaderType string

// PacketInfo holds all parsed fields from a single L3/L4 packet.
type PacketInfo struct {
	SrcMAC         string              `json:"src_mac,omitempty"` // source MAC address
	DstMAC         string              `json:"dst_mac,omitempty"` // destination MAC address
	SrcIP          string              `json:"src_ip"`
	DstIP          string              `json:"dst_ip"`
	Protocol       string              `json:"protocol"` // "TCP", "UDP", "ICMP", "ICMPv6", "IP-<n>"
	SrcPort        uint16              `json:"src_port"` // 0 for non-TCP/UDP
	DstPort        uint16              `json:"dst_port"` // 0 for non-TCP/UDP
	TCPFlags       TCPFlags            `json:"tcp_flags"`
	ICMPType       *uint8              `json:"icmp_type"` // nil for non-ICMP
	ICMPCode       *uint8              `json:"icmp_code"` // nil for non-ICMP
	Fragment       FragmentInfo        `json:"fragment"`
	PacketSize     int                 `json:"packet_size"`
	IPv6ExtHeaders []IPv6ExtHeaderType `json:"ipv6_ext_headers"`
}

// ParsePacket decodes a raw IP packet (IPv4 or IPv6) and returns parsed fields.
// Returns an error if the packet is too short or cannot be decoded.
func ParsePacket(raw []byte) (*PacketInfo, error) {
	if len(raw) < 1 {
		return nil, fmt.Errorf("packet too short: %d bytes", len(raw))
	}

	// Detect IP version from the first nibble of the raw packet.
	version := raw[0] >> 4

	switch version {
	case 4:
		return parseIPv4Packet(raw)
	case 6:
		return parseIPv6Packet(raw)
	default:
		return nil, fmt.Errorf("unsupported IP version: %d", version)
	}
}

func parseIPv4Packet(raw []byte) (*PacketInfo, error) {
	if len(raw) < 20 {
		return nil, fmt.Errorf("IPv4 packet too short: %d bytes", len(raw))
	}

	packet := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.Default)
	if packet == nil {
		return nil, fmt.Errorf("failed to decode IPv4 packet")
	}

	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer == nil {
		return nil, fmt.Errorf("no IPv4 layer found")
	}
	ipv4, ok := ipv4Layer.(*layers.IPv4)
	if !ok {
		return nil, fmt.Errorf("failed to cast IPv4 layer")
	}

	srcMAC, dstMAC := extractMAC(packet)

	info := &PacketInfo{
		SrcMAC:     srcMAC,
		DstMAC:     dstMAC,
		SrcIP:      ipv4.SrcIP.String(),
		DstIP:      ipv4.DstIP.String(),
		PacketSize: len(packet.Data()),
		Fragment: FragmentInfo{
			IsFragment:    ipv4.FragOffset > 0 || ipv4.Flags&layers.IPv4MoreFragments != 0,
			MoreFragments: ipv4.Flags&layers.IPv4MoreFragments != 0,
			Offset:        int(ipv4.FragOffset),
		},
	}

	// Populate L4 fields from the RAW bytes at IHL*4 — the offset the
	// destination's reassembled datagram carries its L4 header at.
	//
	// R80: the pre-R80 path used gopacket's DECODED layers (populateL4), and
	// gopacket refuses to decode the L4 layer of ANY fragmented IPv4 packet
	// (MF set or offset > 0). A FIRST fragment (offset 0, MF set) whose
	// payload begins with a complete TCP header was therefore reported as
	// protocol "TCP" with src_port/dst_port 0 and every flag false: every
	// L4-keyed rule (blocked_ports, source-port filtering, SYN flood, port
	// scan, protocol anomaly, state violation, ICMP type/code) went inert
	// while the destination reassembled the datagram and delivered the
	// unchanged segment — the R79.2 class on the IPv4 plane, which R79 fixed
	// for IPv6 only. Reading the bytes the kernel acts on, at the same offset
	// the IPv6 chain walk resolves to behind a Fragment header with offset 0,
	// makes the two planes judge a fragmented packet identically.
	//
	// A NON-first fragment (offset > 0) carries only continuation data — no
	// L4 header is on the wire — so it keeps the protocol-only contract and is
	// NOT marked L4Incomplete: the datagram's first fragment is where the
	// header is judged, and marking continuations would deny every legitimate
	// fragmented datagram.
	if ipv4.FragOffset > 0 {
		info.Protocol = protocolName(ipv4.Protocol)
		return info, nil
	}
	// A malformed IHL (< 5) puts the L4 offset INSIDE the IP header, where
	// reading "ports" would fabricate them out of the IP header's own bytes
	// (measured pre-R80: gopacket rejected the layer, so the fields stayed
	// zero). Such a packet is uninspectable — the kernel drops it — so report
	// the protocol name only and mark it incomplete rather than inventing
	// evidence.
	l4Off := int(ipv4.IHL) * 4
	if l4Off < ipv4HeaderLen {
		info.Protocol = protocolName(ipv4.Protocol)
		info.Fragment.L4Incomplete = true
		return info, nil
	}
	populateL4FromBytes(info, raw, l4Off, ipv4.Protocol)
	return info, nil
}

// extHeaderTypes maps IPv6 extension-header protocol numbers to short names for
// the extension header list. The protocol-number key space is deliberate: the
// walk below reads the chain from the raw bytes, so it must map an on-the-wire
// protocol number (not a gopacket layer type) to a name.
var extHeaderTypes = map[layers.IPProtocol]IPv6ExtHeaderType{
	layers.IPProtocolIPv6HopByHop:    "HopByHop",
	layers.IPProtocolIPv6Routing:     "Routing",
	layers.IPProtocolIPv6Fragment:    "Fragment",
	layers.IPProtocolIPv6Destination: "Destination",
}

const (
	// ipv4HeaderLen is the minimum IPv4 header size, i.e. IHL == 5.
	ipv4HeaderLen = 20
	// ipv6HeaderLen is the fixed IPv6 header size (RFC 8200 §3).
	ipv6HeaderLen = 40
	// ipv6FragmentHeaderLen is the fixed Fragment extension header size
	// (RFC 8200 §4.5) — it has no Hdr Ext Len field.
	ipv6FragmentHeaderLen = 8
	// Minimum L4 header sizes used before reading port/flag/type fields.
	tcpMinHeaderLen = 20
	udpHeaderLen    = 8
	// icmpMinHeaderLen is the ICMPv4/ICMPv6 minimum (type + code + checksum).
	icmpMinHeaderLen = 4
)

// ipv6HeaderChain is the result of following an IPv6 packet's next-header chain
// from the outer header to the encapsulated L4 protocol.
type ipv6HeaderChain struct {
	// L4Proto is the encapsulated L4 protocol — the protocol the policy keys on.
	L4Proto layers.IPProtocol
	// L4Offset is the byte offset of the L4 header, or -1 when the packet
	// carries no L4 header on the wire (non-first fragment, truncated or
	// extension-only chain). Without an L4 header there are no ports, flags or
	// ICMP type/code to report.
	L4Offset int
	// ExtHeaders names every extension header traversed, outermost first.
	ExtHeaders []IPv6ExtHeaderType
	// Fragment reports the fragment header state (zero value when the chain
	// carried no fragment header).
	Fragment FragmentInfo
}

// walkIPv6HeaderChain follows the IPv6 next-header chain and reports the L4
// protocol, its byte offset, the names of the extension headers traversed and
// the fragment state.
//
// It reads the RAW packet bytes instead of the decoded gopacket layers for two
// independent reasons, both of which are fail-open bypasses when ignored:
//
//  1. None of the four IPv6 extension-header layer types (*layers.IPv6HopByHop,
//     *layers.IPv6Routing, *layers.IPv6Destination, *layers.IPv6Fragment)
//     implements NextLayerType(). The pre-R79 walk asserted
//     `layer.(interface{ NextLayerType() gopacket.LayerType })`, which NEVER
//     succeeded: ipv6ProtoFromLayer was unreachable dead code and the L4
//     protocol stayed at ipv6.NextHeader — the extension header's OWN protocol
//     number (0/43/44/60). populateL4 then took its default branch.
//  2. gopacket does not decode the L4 layer behind every extension header
//     either: behind a Routing header (or a Fragment header) the decoded layer
//     set stops at the extension header, so even a correctly resolved protocol
//     would yield ports 0 and no flags from the layer lookup.
//
// Together those made ONE attacker-prepended extension header hide the L4
// header from every policy layer: a TCP SYN to blocked port 22 was reported as
// protocol "IP-0"/"IP-43"/"IP-44"/"IP-60" with SrcPort=DstPort=0 and all flags
// false, while the destination kernel strips the extension header and delivers
// the unchanged segment — every L4-keyed deny rule (blocked_ports, source-port
// filtering, SYN flood, port scan, protocol anomaly, state violation) went
// inert (R79.2).
//
// Per RFC 8200 the first byte of every extension header is its Next Header
// field, the second byte of HopByHop/Routing/Destination Options is Hdr Ext Len
// (total header size = (len+1)*8), and the Fragment header is a fixed 8 bytes
// whose Fragment Offset/More-Fragments live in bytes 2-3. Each hop advances by
// at least 8 bytes, so the walk always terminates.
func walkIPv6HeaderChain(raw []byte, first layers.IPProtocol) ipv6HeaderChain {
	chain := ipv6HeaderChain{L4Proto: first, L4Offset: -1, ExtHeaders: []IPv6ExtHeaderType{}}
	proto := first
	off := ipv6HeaderLen

	for {
		name, ok := extHeaderTypes[proto]
		if !ok {
			// L4 (or unrecognized) protocol terminator.
			chain.L4Proto = proto
			if off < len(raw) {
				chain.L4Offset = off
			}
			return chain
		}
		if off >= len(raw) {
			// Truncated chain: the declared extension header is not on the
			// wire, so neither this firewall nor the destination can process
			// it. Report the declared protocol and no L4 fields.
			chain.L4Proto = proto
			return chain
		}
		chain.ExtHeaders = append(chain.ExtHeaders, name)

		next := layers.IPProtocol(raw[off])
		if proto == layers.IPProtocolIPv6Fragment {
			if off+ipv6FragmentHeaderLen > len(raw) {
				chain.L4Proto = proto
				return chain
			}
			flagsOffset := binary.BigEndian.Uint16(raw[off+2 : off+4])
			chain.Fragment = FragmentInfo{
				IsFragment:    true,
				MoreFragments: flagsOffset&1 == 1,
				Offset:        int(flagsOffset >> 3),
			}
			if chain.Fragment.Offset > 0 {
				// Non-first fragment: the remaining bytes are continuation
				// data, not an L4 header. Reading "ports" out of them would
				// invent evidence the destination never sees (and could block
				// or allow on payload bytes), so report the protocol only —
				// the same contract the IPv4 non-first-fragment path has.
				chain.L4Proto = next
				return chain
			}
			proto = next
			off += ipv6FragmentHeaderLen
			continue
		}
		if off+2 > len(raw) {
			chain.L4Proto = proto
			return chain
		}
		hlen := (int(raw[off+1]) + 1) * 8
		proto = next
		off += hlen
	}
}

// populateL4FromBytes fills the L4 fields the policy keys on — protocol name,
// ports, TCP flags, ICMP type/code — directly from the packet bytes at off (the
// offset walkIPv6HeaderChain resolved, or IHL*4 for IPv4 since R80).
//
// It is the ONLY L4 population path for both address families: gopacket's
// decoded layers cannot be trusted for this job. For IPv6, gopacket does not
// decode the L4 layer behind an extension header; for IPv4, gopacket refuses to
// decode the L4 layer of ANY fragmented packet — including a FIRST fragment
// (offset 0, MF set) whose payload begins with the L4 header the destination
// reassembles and the kernel acts on (R79 and R80 respectively).
//
// off < 0, or a packet too short to hold the protocol's minimum header, sets
// the protocol name and leaves the remaining fields zero — the honest "no L4
// header on the wire" report. When a header IS expected at off but does not fit
// (off >= 0), Fragment.L4Incomplete is set so the policy can fail closed on a
// packet no L4-keyed rule can judge (R80: the RFC 1858 tiny-fragment evasion —
// the destination still reassembles and processes the segment). Partial fields
// are never reported: an incomplete header yields zeros, not invented ports.
func populateL4FromBytes(info *PacketInfo, raw []byte, off int, proto layers.IPProtocol) {
	info.Protocol = protocolName(proto)
	if off < 0 {
		// No L4 header is on the wire at all (non-first fragment, or a
		// truncated chain): nothing to report and nothing to expect.
		return
	}
	switch proto {
	case layers.IPProtocolTCP:
		if off+tcpMinHeaderLen > len(raw) {
			info.Fragment.L4Incomplete = true
			return
		}
		info.SrcPort = binary.BigEndian.Uint16(raw[off : off+2])
		info.DstPort = binary.BigEndian.Uint16(raw[off+2 : off+4])
		flags := raw[off+13]
		info.TCPFlags = TCPFlags{
			SYN: flags&0x02 != 0,
			ACK: flags&0x10 != 0,
			RST: flags&0x04 != 0,
			FIN: flags&0x01 != 0,
		}

	case layers.IPProtocolUDP:
		if off+udpHeaderLen > len(raw) {
			info.Fragment.L4Incomplete = true
			return
		}
		info.SrcPort = binary.BigEndian.Uint16(raw[off : off+2])
		info.DstPort = binary.BigEndian.Uint16(raw[off+2 : off+4])

	case layers.IPProtocolICMPv4, layers.IPProtocolICMPv6:
		// ICMPv6 is named separately from IPv4 "ICMP" so the shipped policy's
		// ICMP rules (keyed on protocol == "ICMP", thresholds tuned for IPv4
		// and for traffic such as NDP/router advertisements that IPv6 needs)
		// do not silently start policing ICMPv6 (R79).
		if off+icmpMinHeaderLen > len(raw) {
			info.Fragment.L4Incomplete = true
			return
		}
		t, c := raw[off], raw[off+1]
		info.ICMPType = &t
		info.ICMPCode = &c
	}
}

// protocolName maps an IP protocol number to the policy-facing protocol name
// without reading any L4 bytes — the naming half of populateL4FromBytes, for
// packets that carry no readable L4 header (non-first fragments and truncated
// chains). The switch is deliberately identical to populateL4FromBytes's so a
// packet's protocol name never depends on whether its L4 header was readable.
func protocolName(proto layers.IPProtocol) string {
	switch proto {
	case layers.IPProtocolTCP:
		return "TCP"
	case layers.IPProtocolUDP:
		return "UDP"
	case layers.IPProtocolICMPv4:
		return "ICMP"
	case layers.IPProtocolICMPv6:
		return "ICMPv6"
	default:
		return fmt.Sprintf("IP-%d", proto)
	}
}

func parseIPv6Packet(raw []byte) (*PacketInfo, error) {
	if len(raw) < 40 {
		return nil, fmt.Errorf("IPv6 packet too short: %d bytes", len(raw))
	}

	packet := gopacket.NewPacket(raw, layers.LayerTypeIPv6, gopacket.Default)
	if packet == nil {
		return nil, fmt.Errorf("failed to decode IPv6 packet")
	}

	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer == nil {
		return nil, fmt.Errorf("no IPv6 layer found")
	}
	ipv6, ok := ipv6Layer.(*layers.IPv6)
	if !ok {
		return nil, fmt.Errorf("failed to cast IPv6 layer")
	}

	// Resolve the L4 protocol, its offset and the extension-header chain from
	// the raw bytes — the protocol and ports the policy must judge, not the
	// outer next-header field.
	chain := walkIPv6HeaderChain(raw, ipv6.NextHeader)

	// Extract MAC addresses from ethernet layer
	srcMAC, dstMAC := extractMAC(packet)

	info := &PacketInfo{
		SrcMAC:         srcMAC,
		DstMAC:         dstMAC,
		SrcIP:          ipv6.SrcIP.String(),
		DstIP:          ipv6.DstIP.String(),
		PacketSize:     len(packet.Data()),
		IPv6ExtHeaders: chain.ExtHeaders,
		Fragment:       chain.Fragment,
	}

	populateL4FromBytes(info, raw, chain.L4Offset, chain.L4Proto)
	return info, nil
}

// extractMAC returns the source and destination MAC addresses from the ethernet layer.
func extractMAC(packet gopacket.Packet) (srcMAC, dstMAC string) {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return "", ""
	}
	eth, ok := ethLayer.(*layers.Ethernet)
	if !ok {
		return "", ""
	}
	return eth.SrcMAC.String(), eth.DstMAC.String()
}
