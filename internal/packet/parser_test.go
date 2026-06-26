// Package packet provides L3/L4 packet header parsing using gopacket.
package packet

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// buildTCPPacket creates a raw TCP/IP packet for testing.
func buildTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort layers.TCPPort, syn, ack, rst, fin bool) []byte {
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		SYN:     syn,
		ACK:     ack,
		RST:     rst,
		FIN:     fin,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, ip, tcp); err != nil {
		panic("buildTCPPacket: " + err.Error())
	}
	return buf.Bytes()
}

// buildUDPPacket creates a raw UDP/IP packet for testing.
func buildUDPPacket(srcIP, dstIP net.IP, srcPort, dstPort layers.UDPPort) []byte {
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: srcPort,
		DstPort: dstPort,
	}
	udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, ip, udp); err != nil {
		panic("buildUDPPacket: " + err.Error())
	}
	return buf.Bytes()
}

// buildICMPPacket creates a raw ICMP echo request packet for testing.
func buildICMPPacket(srcIP, dstIP net.IP, icmpType, icmpCode uint8) []byte {
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolICMPv4,
	}
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(icmpType, icmpCode),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, ip, icmp); err != nil {
		panic("buildICMPPacket: " + err.Error())
	}
	return buf.Bytes()
}

// =============================================================================
// Tests
// =============================================================================

func TestParseTCPPacket(t *testing.T) {
	raw := buildTCPPacket(
		net.ParseIP("10.0.1.100"), net.ParseIP("10.0.2.50"),
		44001, 443,
		true, false, false, false, // SYN flag
	)

	info, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}

	if info.SrcIP != "10.0.1.100" {
		t.Errorf("SrcIP = %q, want %q", info.SrcIP, "10.0.1.100")
	}
	if info.DstIP != "10.0.2.50" {
		t.Errorf("DstIP = %q, want %q", info.DstIP, "10.0.2.50")
	}
	if info.Protocol != "TCP" {
		t.Errorf("Protocol = %q, want %q", info.Protocol, "TCP")
	}
	if info.SrcPort != 44001 {
		t.Errorf("SrcPort = %d, want %d", info.SrcPort, 44001)
	}
	if info.DstPort != 443 {
		t.Errorf("DstPort = %d, want %d", info.DstPort, 443)
	}
	if !info.TCPFlags.SYN {
		t.Error("TCPFlags.SYN = false, want true")
	}
	if info.TCPFlags.ACK {
		t.Error("TCPFlags.ACK = true, want false")
	}
	if info.TCPFlags.RST {
		t.Error("TCPFlags.RST = true, want false")
	}
	if info.TCPFlags.FIN {
		t.Error("TCPFlags.FIN = true, want false")
	}
}

func TestParseTCPPacketAllFlags(t *testing.T) {
	raw := buildTCPPacket(
		net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.2"),
		12345, 80,
		true, true, false, true, // SYN+ACK+FIN (anomalous)
	)

	info, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}

	if !info.TCPFlags.SYN {
		t.Error("TCPFlags.SYN = false, want true")
	}
	if !info.TCPFlags.ACK {
		t.Error("TCPFlags.ACK = false, want true")
	}
	if !info.TCPFlags.FIN {
		t.Error("TCPFlags.FIN = false, want true")
	}
	if info.TCPFlags.RST {
		t.Error("TCPFlags.RST = true, want false")
	}
}

func TestParseUDPPacket(t *testing.T) {
	raw := buildUDPPacket(
		net.ParseIP("10.0.1.100"), net.ParseIP("10.0.2.50"),
		44001, 53,
	)

	info, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}

	if info.Protocol != "UDP" {
		t.Errorf("Protocol = %q, want %q", info.Protocol, "UDP")
	}
	if info.SrcPort != 44001 {
		t.Errorf("SrcPort = %d, want %d", info.SrcPort, 44001)
	}
	if info.DstPort != 53 {
		t.Errorf("DstPort = %d, want %d", info.DstPort, 53)
	}
	// UDP should have nil/no TCP flags
	if info.TCPFlags.SYN || info.TCPFlags.ACK || info.TCPFlags.RST || info.TCPFlags.FIN {
		t.Error("UDP packet should not have TCP flags set")
	}
}

func TestParseICMPPacket(t *testing.T) {
	raw := buildICMPPacket(
		net.ParseIP("10.0.1.100"), net.ParseIP("10.0.2.50"),
		8, 0, // Echo request
	)

	info, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}

	if info.Protocol != "ICMP" {
		t.Errorf("Protocol = %q, want %q", info.Protocol, "ICMP")
	}
	if info.ICMPType == nil || *info.ICMPType != 8 {
		t.Errorf("ICMPType = %v, want 8", info.ICMPType)
	}
	if info.ICMPCode == nil || *info.ICMPCode != 0 {
		t.Errorf("ICMPCode = %v, want 0", info.ICMPCode)
	}
	// ICMP should not have ports
	if info.SrcPort != 0 {
		t.Errorf("SrcPort = %d, want 0 for ICMP", info.SrcPort)
	}
	if info.DstPort != 0 {
		t.Errorf("DstPort = %d, want 0 for ICMP", info.DstPort)
	}
}

func TestParseShortPacket(t *testing.T) {
	_, err := ParsePacket([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for short packet, got nil")
	}
}

func TestParseEmptyPacket(t *testing.T) {
	_, err := ParsePacket(nil)
	if err == nil {
		t.Fatal("expected error for nil packet, got nil")
	}
}

func TestParsePacketSize(t *testing.T) {
	raw := buildTCPPacket(
		net.ParseIP("10.0.1.100"), net.ParseIP("10.0.2.50"),
		44001, 443,
		true, false, false, false,
	)

	info, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}

	if info.PacketSize <= 0 {
		t.Errorf("PacketSize = %d, want > 0", info.PacketSize)
	}
}

func TestParseIPv6Packet(t *testing.T) {
	// Build an IPv6 TCP packet
	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		SrcIP:      net.ParseIP("2001:db8::1"),
		DstIP:      net.ParseIP("2001:db8::2"),
		NextHeader: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 44001,
		DstPort: 443,
		SYN:     true,
		ACK:     false,
	}
	tcp.SetNetworkLayerForChecksum(ip6)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, ip6, tcp); err != nil {
		t.Fatalf("build IPv6 packet: %v", err)
	}

	info, err := ParsePacket(buf.Bytes())
	if err != nil {
		t.Fatalf("ParsePacket IPv6 failed: %v", err)
	}

	if info.SrcIP != "2001:db8::1" {
		t.Errorf("SrcIP = %q, want %q", info.SrcIP, "2001:db8::1")
	}
	if info.DstIP != "2001:db8::2" {
		t.Errorf("DstIP = %q, want %q", info.DstIP, "2001:db8::2")
	}
	if info.Protocol != "TCP" {
		t.Errorf("Protocol = %q, want %q", info.Protocol, "TCP")
	}
	if info.SrcPort != 44001 {
		t.Errorf("SrcPort = %d, want %d", info.SrcPort, 44001)
	}
	if info.DstPort != 443 {
		t.Errorf("DstPort = %d, want %d", info.DstPort, 443)
	}
	if !info.TCPFlags.SYN {
		t.Error("TCPFlags.SYN = false, want true")
	}
}
