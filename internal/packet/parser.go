// Package packet provides L3/L4 packet header parsing using gopacket.
package packet

import (
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
}

// IPv6ExtHeaderType is a string representation of an IPv6 extension header.
type IPv6ExtHeaderType string

// PacketInfo holds all parsed fields from a single L3/L4 packet.
type PacketInfo struct {
	SrcMAC        string             `json:"src_mac,omitempty"` // source MAC address
	DstMAC        string             `json:"dst_mac,omitempty"` // destination MAC address
	SrcIP         string             `json:"src_ip"`
	DstIP         string             `json:"dst_ip"`
	Protocol      string             `json:"protocol"` // "TCP", "UDP", "ICMP", etc.
	SrcPort       uint16             `json:"src_port"`  // 0 for non-TCP/UDP
	DstPort       uint16             `json:"dst_port"`  // 0 for non-TCP/UDP
	TCPFlags      TCPFlags           `json:"tcp_flags"`
	ICMPType      *uint8             `json:"icmp_type"`  // nil for non-ICMP
	ICMPCode      *uint8             `json:"icmp_code"`  // nil for non-ICMP
	Fragment      FragmentInfo       `json:"fragment"`
	PacketSize    int                `json:"packet_size"`
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
		SrcMAC:      srcMAC,
		DstMAC:      dstMAC,
		SrcIP:       ipv4.SrcIP.String(),
		DstIP:       ipv4.DstIP.String(),
		PacketSize:  len(packet.Data()),
		Fragment: FragmentInfo{
			IsFragment:    ipv4.FragOffset > 0 || ipv4.Flags&layers.IPv4MoreFragments != 0,
			MoreFragments: ipv4.Flags&layers.IPv4MoreFragments != 0,
			Offset:        int(ipv4.FragOffset),
		},
	}

	// Populate L4 fields based on the IP protocol number.
	populateL4(info, packet, ipv4.Protocol)
	return info, nil
}

// extHeaderTypes maps gopacket layer types to short names for the extension header list.
var extHeaderTypes = map[gopacket.LayerType]IPv6ExtHeaderType{
	layers.LayerTypeIPv6HopByHop:    "HopByHop",
	layers.LayerTypeIPv6Routing:     "Routing",
	layers.LayerTypeIPv6Fragment:    "Fragment",
	layers.LayerTypeIPv6Destination: "Destination",
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

	// Find the actual L4 protocol by walking through extension headers
	l4Proto := ipv6.NextHeader
	extHeaders := []IPv6ExtHeaderType{}

	// Extract MAC addresses from ethernet layer
	srcMAC, dstMAC := extractMAC(packet)

	// Check all layers for extension headers
	for _, layer := range packet.Layers() {
		if name, ok := extHeaderTypes[layer.LayerType()]; ok {
			extHeaders = append(extHeaders, name)
			// Update the protocol to the next header from this extension
			if ext, ok2 := layer.(interface{ NextLayerType() gopacket.LayerType }); ok2 {
				l4Proto = ipv6ProtoFromLayer(ext.NextLayerType())
			}
		}
	}

	info := &PacketInfo{
		SrcMAC:         srcMAC,
		DstMAC:         dstMAC,
		SrcIP:          ipv6.SrcIP.String(),
		DstIP:          ipv6.DstIP.String(),
		PacketSize:     len(packet.Data()),
		IPv6ExtHeaders: extHeaders,
	}

	// Check if a fragment extension header was present
	for _, layer := range packet.Layers() {
		if frag, ok := layer.(*layers.IPv6Fragment); ok {
			info.Fragment.IsFragment = true
			info.Fragment.MoreFragments = frag.MoreFragments
			info.Fragment.Offset = int(frag.FragmentOffset)
			break
		}
	}

	populateL4(info, packet, l4Proto)
	return info, nil
}

// ipv6ProtoFromLayer converts a gopacket layer type back to an IP protocol number.
func ipv6ProtoFromLayer(lt gopacket.LayerType) layers.IPProtocol {
	switch lt {
	case layers.LayerTypeTCP:
		return layers.IPProtocolTCP
	case layers.LayerTypeUDP:
		return layers.IPProtocolUDP
	case layers.LayerTypeICMPv4:
		return layers.IPProtocolICMPv4
	case layers.LayerTypeICMPv6:
		return layers.IPProtocolICMPv6
	case layers.LayerTypeIPv6HopByHop:
		return layers.IPProtocolIPv6HopByHop
	case layers.LayerTypeIPv6Routing:
		return layers.IPProtocolIPv6Routing
	case layers.LayerTypeIPv6Fragment:
		return layers.IPProtocolIPv6Fragment
	case layers.LayerTypeIPv6Destination:
		return layers.IPProtocolIPv6Destination
	default:
		return layers.IPProtocol(0)
	}
}

// populateL4 fills in L4 protocol fields (TCP, UDP, ICMP) from a decoded packet.
func populateL4(info *PacketInfo, packet gopacket.Packet, proto layers.IPProtocol) {
	switch proto {
	case layers.IPProtocolTCP:
		info.Protocol = "TCP"
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, ok := tcpLayer.(*layers.TCP)
			if ok {
				info.SrcPort = uint16(tcp.SrcPort)
				info.DstPort = uint16(tcp.DstPort)
				info.TCPFlags = TCPFlags{
					SYN: tcp.SYN,
					ACK: tcp.ACK,
					RST: tcp.RST,
					FIN: tcp.FIN,
				}
			}
		}

	case layers.IPProtocolUDP:
		info.Protocol = "UDP"
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, ok := udpLayer.(*layers.UDP)
			if ok {
				info.SrcPort = uint16(udp.SrcPort)
				info.DstPort = uint16(udp.DstPort)
			}
		}

	case layers.IPProtocolICMPv4:
		info.Protocol = "ICMP"
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			icmp, ok := icmpLayer.(*layers.ICMPv4)
			if ok {
				t := uint8(icmp.TypeCode.Type())
				c := uint8(icmp.TypeCode.Code())
				info.ICMPType = &t
				info.ICMPCode = &c
			}
		}

	default:
		info.Protocol = fmt.Sprintf("IP-%d", proto)
	}
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
