package engine

import (
	"strings"
	"testing"

	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/opa"
	"github.com/monch1962/l3-firewall/internal/packet"
	"github.com/monch1962/l3-firewall/internal/ratelimit"
)

func TestAttack_VeryLongOPAReason(t *testing.T) {
	longReason := strings.Repeat("A", 100*1024)
	policy := `package l3_firewall
import rego.v1
default allow := true
allow := false if { input.packet.dst_port == 22 }
reason := "` + longReason + `" if { input.packet.dst_port == 22 }
`
	eval, err := opa.NewEmbedded(opa.EmbedConfig{Policy: policy})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	eng := New(eval, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(10000, 100000000), true, false, nil, nil, nil)

	pi := &packet.PacketInfo{
		SrcIP: "10.0.1.100", DstIP: "10.0.2.50", Protocol: "TCP",
		SrcPort: 44001, DstPort: 22,
		TCPFlags: packet.TCPFlags{SYN: true},
	}
	result := eng.evaluatePacket(pi, 64)
	if result.Allowed {
		t.Fatal("expected block for SSH port 22")
	}
	if len(result.Reason) > 1024 {
		t.Errorf("reason string not truncated: got %d bytes, want <= 1024", len(result.Reason))
	}
	blocks := eng.RecentBlocks()
	if len(blocks) > 0 && len(blocks[0].Reason) > 1024 {
		t.Errorf("block log reason not truncated: got %d bytes", len(blocks[0].Reason))
	}
}

func TestAttack_NegativeRateLimitFlags(t *testing.T) {
	l := ratelimit.NewLimiter(-100, 1000)
	if l == nil {
		t.Fatal("NewLimiter returned nil for negative PPS")
	}
	pps, bps := l.Allow("10.0.1.100", 64)
	if pps <= 0 {
		t.Errorf("PPS = %f, want > 0", pps)
	}
	if bps <= 0 {
		t.Errorf("BPS = %f, want > 0", bps)
	}

	l2 := ratelimit.NewLimiter(100, -1000)
	if l2 == nil {
		t.Fatal("NewLimiter returned nil for negative BPS")
	}
	pps2, bps2 := l2.Allow("10.0.1.100", 64)
	if pps2 <= 0 {
		t.Errorf("PPS = %f, want > 0", pps2)
	}
	if bps2 <= 0 {
		t.Errorf("BPS = %f, want > 0", bps2)
	}
}

func TestAttack_InvalidProtocolNumber(t *testing.T) {
	eval, _ := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true`,
	})
	eng := New(eval, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(10000, 100000000), true, false, nil, nil, nil)

	pi := &packet.PacketInfo{
		SrcIP: "10.0.1.100", DstIP: "10.0.2.50", Protocol: "IP-255",
		SrcPort: 0, DstPort: 0,
	}
	result := eng.evaluatePacket(pi, 64)
	if result == nil {
		t.Fatal("evaluatePacket returned nil for unknown protocol")
	}
	_ = result
}

func TestAttack_EmptyOPAReason(t *testing.T) {
	policy := `package l3_firewall
import rego.v1
default allow := true
allow := false if { input.packet.dst_port == 22 }
`
	eval, _ := opa.NewEmbedded(opa.EmbedConfig{Policy: policy})
	eng := New(eval, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(10000, 100000000), true, false, nil, nil, nil)

	pi := &packet.PacketInfo{
		SrcIP: "10.0.1.100", DstIP: "10.0.2.50", Protocol: "TCP",
		SrcPort: 44001, DstPort: 22,
		TCPFlags: packet.TCPFlags{SYN: true},
	}
	result := eng.evaluatePacket(pi, 64)
	if result.Allowed {
		t.Error("expected block for SSH port 22")
	}
	_ = result.Reason
}

func TestAttack_ZeroSizePacket(t *testing.T) {
	l := ratelimit.NewLimiter(100, 1000)
	l.Allow("10.0.1.100", 0)
	pps := l.GetPPS("10.0.1.100")
	if pps < 0 {
		t.Errorf("PPS = %f, want >= 0", pps)
	}
}
