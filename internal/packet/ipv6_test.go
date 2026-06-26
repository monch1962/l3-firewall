package packet

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestIPv6NoExtensionHeaders(t *testing.T) {
	raw := buildIPv6TCP("::1", "::2", 44001, 443)
	info, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if len(info.IPv6ExtHeaders) != 0 {
		t.Errorf("expected no extension headers, got %v", info.IPv6ExtHeaders)
	}
	if info.Protocol != "TCP" {
		t.Errorf("protocol = %q, want TCP", info.Protocol)
	}
}

func TestIPv6WithHopByHop(t *testing.T) {
	raw := buildIPv6WithExt("::1", "::2", 44001, 443, layers.IPProtocolIPv6HopByHop)
	info, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if len(info.IPv6ExtHeaders) == 0 {
		t.Fatal("expected extension header")
	}
	found := false
	for _, h := range info.IPv6ExtHeaders {
		if string(h) == "HopByHop" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected HopByHop in headers, got %v", info.IPv6ExtHeaders)
	}
}

func TestIPv6WithFragment(t *testing.T) {
	raw := buildIPv6WithExt("::1", "::2", 44001, 443, layers.IPProtocolIPv6Fragment)
	info, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if !info.Fragment.IsFragment {
		t.Error("expected IsFragment=true for IPv6 fragment")
	}
	if info.Fragment.Offset <= 0 {
		t.Error("expected positive fragment offset")
	}
}

func parseIP6(s string) net.IP {
	return net.ParseIP(s)
}

func buildIPv6TCP(src, dst string, srcPort, dstPort uint16) []byte {
	ip6 := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolTCP,
		SrcIP:      parseIP6(src),
		DstIP:      parseIP6(dst),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(ip6)
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, ip6, tcp)
	return buf.Bytes()
}

func buildIPv6WithExt(src, dst string, srcPort, dstPort uint16, extType layers.IPProtocol) []byte {
	// Build a basic IPv6 TCP packet
	ip6 := &layers.IPv6{
		Version:    6,
		NextHeader: extType,
		SrcIP:      parseIP6(src),
		DstIP:      parseIP6(dst),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(ip6)
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, ip6, tcp)
	full := buf.Bytes()

	// Build extension header bytes to insert after the 40-byte IPv6 header
	var ext []byte
	switch extType {
	case layers.IPProtocolIPv6HopByHop:
		// Next-header=TCP, length=0 (means 8 bytes), pad bytes
		ext = []byte{byte(layers.IPProtocolTCP), 0, 0, 0, 0, 0, 0, 0}
	case layers.IPProtocolIPv6Fragment:
		// Next-header=TCP, reserved, offset+flags, identification
		ext = make([]byte, 8)
		ext[0] = byte(layers.IPProtocolTCP) // next header
		ext[1] = 0                           // reserved
		ext[2] = 0x03                        // fragment offset high
		ext[3] = 0x20                        // MoreFragments + offset low
	default:
		ext = []byte{byte(layers.IPProtocolTCP), 0, 0, 0, 0, 0, 0, 0}
	}

	// Combine: IPv6 header (40) + ext header + TCP payload
	result := make([]byte, 0, 40+len(ext)+len(full)-40)
	result = append(result, full[:40]...)
	result = append(result, ext...)
	result = append(result, full[40:]...)

	// Fix payload length in IPv6 header (bytes 4-5)
	plen := len(result) - 40
	result[4] = byte(plen >> 8)
	result[5] = byte(plen & 0xff)

	return result
}
