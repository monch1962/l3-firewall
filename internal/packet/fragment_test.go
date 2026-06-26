package packet

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestFragmentInfo(t *testing.T) {
	// Build a fragmented IPv4 packet (offset > 0, More Fragments set)
	ip := &layers.IPv4{
		Version:    4,
		TTL:        64,
		SrcIP:      net.ParseIP("10.0.1.100"),
		DstIP:      net.ParseIP("10.0.2.50"),
		Protocol:   layers.IPProtocolTCP,
		FragOffset: 100, // offset in 8-byte units = 800 bytes
		Flags:      layers.IPv4MoreFragments,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	if err := gopacket.SerializeLayers(buf, opts, ip); err != nil {
		t.Fatalf("build fragment: %v", err)
	}

	info, err := ParsePacket(buf.Bytes())
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}

	if !info.Fragment.IsFragment {
		t.Error("IsFragment = false, want true")
	}
	if !info.Fragment.MoreFragments {
		t.Error("MoreFragments = false, want true")
	}
	if info.Fragment.Offset != 100 {
		t.Errorf("Offset = %d, want 100", info.Fragment.Offset)
	}
}

func TestFragmentFirstPacket(t *testing.T) {
	// First fragment: offset=0, More Fragments set
	ip := &layers.IPv4{
		Version:    4,
		TTL:        64,
		SrcIP:      net.ParseIP("10.0.1.100"),
		DstIP:      net.ParseIP("10.0.2.50"),
		Protocol:   layers.IPProtocolTCP,
		FragOffset: 0,
		Flags:      layers.IPv4MoreFragments,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts, ip)

	info, err := ParsePacket(buf.Bytes())
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}

	if !info.Fragment.IsFragment {
		t.Error("first fragment: IsFragment should be true")
	}
	if info.Fragment.Offset != 0 {
		t.Errorf("Offset = %d, want 0", info.Fragment.Offset)
	}
}

func TestNonFragmentPacket(t *testing.T) {
	raw := buildTCPPacket(
		net.ParseIP("10.0.1.100"), net.ParseIP("10.0.2.50"),
		44001, 443,
		true, false, false, false,
	)

	info, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}

	if info.Fragment.IsFragment {
		t.Error("normal TCP should not be a fragment")
	}
	if info.Fragment.Offset != 0 {
		t.Errorf("Offset = %d, want 0", info.Fragment.Offset)
	}
}
