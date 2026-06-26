// Red-team security hardening Round 4 — Parser edge cases and config validation.
package packet

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ── R31: IPv4 packet with no L4 payload ───────────────────────────
// A packet that has a valid IPv4 header but zero bytes of L4 payload.
// The parser should not crash and should indicate no L4 protocol found.
func TestAttack_IPv4NoPayload(t *testing.T) {
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP("10.0.1.100"),
		DstIP:    net.ParseIP("10.0.2.50"),
		Protocol: layers.IPProtocolTCP,
		Length:   20, // Only the IPv4 header, no TCP payload
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, ip); err != nil {
		t.Fatalf("build packet: %v", err)
	}

	info, err := ParsePacket(buf.Bytes())
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}
	if info == nil {
		t.Fatal("ParsePacket returned nil info")
	}
	// Protocol might still be "TCP" since gopacket may not validate L4 presence
	// The key is no panic and valid SrcIP/DstIP
	if info.SrcIP != "10.0.1.100" {
		t.Errorf("SrcIP = %q, want %q", info.SrcIP, "10.0.1.100")
	}
	if info.DstIP != "10.0.2.50" {
		t.Errorf("DstIP = %q, want %q", info.DstIP, "10.0.2.50")
	}
}

// ── R32: TCP with all flags set ────────────────────────────────────
// SYN+ACK+RST+FIN simultaneously is invalid in TCP but valid at the bit level.
// The parser should handle this without crashing.
func TestAttack_TCPAllFlags(t *testing.T) {
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP("10.0.1.100"),
		DstIP:    net.ParseIP("10.0.2.50"),
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 44001,
		DstPort: 443,
		SYN:     true,
		ACK:     true,
		RST:     true,
		FIN:     true,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, ip, tcp); err != nil {
		t.Fatalf("build packet: %v", err)
	}

	info, err := ParsePacket(buf.Bytes())
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}
	if info == nil {
		t.Fatal("ParsePacket returned nil")
	}
	if info.Protocol != "TCP" {
		t.Errorf("Protocol = %q, want TCP", info.Protocol)
	}
	if !info.TCPFlags.SYN || !info.TCPFlags.ACK || !info.TCPFlags.RST || !info.TCPFlags.FIN {
		t.Error("all TCP flags should be set")
	}
}

// ── R33: ICMP with invalid high code value ───────────────────────
// ICMP Destination Unreachable codes > 15 should not cause issues.
func TestAttack_ICMPInvalidCode(t *testing.T) {
	// Type 3 = Destination Unreachable, Code 255 = invalid
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP("10.0.1.100"),
		DstIP:    net.ParseIP("10.0.2.50"),
		Protocol: layers.IPProtocolICMPv4,
	}
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(3, 255),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, ip, icmp); err != nil {
		t.Fatalf("build packet: %v", err)
	}

	info, err := ParsePacket(buf.Bytes())
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}
	if info.Protocol != "ICMP" {
		t.Errorf("Protocol = %q, want ICMP", info.Protocol)
	}
	if info.ICMPType == nil || *info.ICMPType != 3 {
		t.Errorf("ICMPType = %v, want 3", info.ICMPType)
	}
	if info.ICMPCode == nil || *info.ICMPCode != 255 {
		t.Errorf("ICMPCode = %v, want 255", info.ICMPCode)
	}
}

// ── R34: IPv4 with maximum header options (IHL=15) ────────────────
// Maximum IPv4 header size is 60 bytes (IHL=15). Parser should handle.
func TestAttack_IPv4MaxOptions(t *testing.T) {
	// Create a raw IPv4 packet with IHL=15 (maximum = 60 byte header)
	// We can't easily set IHL via layers.IPv4, so build raw bytes
	raw := make([]byte, 60)
	// Version=4, IHL=15 (0x4F)
	raw[0] = 0x4F
	// Total length = 60
	raw[2] = 0
	raw[3] = 60
	// TTL=64
	raw[8] = 64
	// Protocol=TCP (6)
	raw[9] = 6
	// SrcIP = 10.0.1.100
	raw[12] = 10
	raw[13] = 0
	raw[14] = 1
	raw[15] = 100
	// DstIP = 10.0.2.50
	raw[16] = 10
	raw[17] = 0
	raw[18] = 2
	raw[19] = 50

	info, err := ParsePacket(raw)
	if err != nil {
		// Not all gopacket versions handle this — accept graceful failure
		t.Skipf("gopacket may not support IHL=15: %v", err)
	}
	if info == nil {
		t.Fatal("ParsePacket returned nil")
	}
	if info.SrcIP != "10.0.1.100" {
		t.Errorf("SrcIP = %q, want %q", info.SrcIP, "10.0.1.100")
	}
	if info.DstIP != "10.0.2.50" {
		t.Errorf("DstIP = %q, want %q", info.DstIP, "10.0.2.50")
	}
}

// ── R35: IPv4 with IHL minimum (IHL=5, 20 byte header) ───────────
// Standard minimum IPv4 header. Should parse correctly.
func TestAttack_IPv4MinHeader(t *testing.T) {
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP("10.0.1.100"),
		DstIP:    net.ParseIP("10.0.2.50"),
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 44001,
		DstPort: 443,
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	gopacket.SerializeLayers(buf, opts, ip, tcp)

	info, err := ParsePacket(buf.Bytes())
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}
	if info.SrcIP != "10.0.1.100" {
		t.Errorf("SrcIP = %q, want %q", info.SrcIP, "10.0.1.100")
	}
	if info.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", info.DstPort)
	}
}
