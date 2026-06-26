// Red-team security hardening Round 3 — Cross-component attacks and upstream validation.
package engine

import (
	"strings"
	"testing"

	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/opa"
	"github.com/monch1962/l3-firewall/internal/packet"
	"github.com/monch1962/l3-firewall/internal/ratelimit"
)

// ── R26: Very long OPA reason string ──────────────────────────────
// OPA returns a 100KB reason string, causing memory bloat in blockStats and recentBlocks.
func TestAttack_VeryLongOPAReason(t *testing.T) {
	store := opa.NewDataStore()
	longReason := strings.Repeat("A", 100*1024) // 100KB reason
	policy := `package l3_firewall
import rego.v1
default allow := true
allow := false if { input.packet.dst_port == 22 }
reason := "` + longReason + `" if { input.packet.dst_port == 22 }
`
	eval, err := opa.NewEmbedded(opa.EmbedConfig{Policy: policy, Store: store})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	eng := New(eval, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(10000, 100000000), true, false)

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
	// Also check recentBlocks stores truncated reason
	blocks := eng.RecentBlocks()
	if len(blocks) > 0 && len(blocks[0].Reason) > 1024 {
		t.Errorf("block log reason not truncated: got %d bytes", len(blocks[0].Reason))
	}
}

// ── R27: Negative rate limit flags ────────────────────────────────
// NewLimiter with negative PPS/BPS limits causes undefined behavior.
func TestAttack_NegativeRateLimitFlags(t *testing.T) {
	// Negative PPS
	l := ratelimit.NewLimiter(-100, 1000)
	if l == nil {
		t.Fatal("NewLimiter returned nil for negative PPS")
	}
	pps, bps := l.Allow("10.0.1.100", 64)
	if pps <= 0 {
		t.Errorf("PPS = %f, want > 0 even with negative limit", pps)
	}
	if bps <= 0 {
		t.Errorf("BPS = %f, want > 0 even with negative limit", bps)
	}

	// Negative BPS
	l2 := ratelimit.NewLimiter(100, -1000)
	if l2 == nil {
		t.Fatal("NewLimiter returned nil for negative BPS")
	}
	pps2, bps2 := l2.Allow("10.0.1.100", 64)
	if pps2 <= 0 {
		t.Errorf("PPS = %f, want > 0", pps2)
	}
	if bps2 <= 0 {
		t.Errorf("BPS = %f, want > 0 even with negative limit", bps2)
	}
}

// ── R28: Packet parser with invalid protocol number ────────────────
// A packet with protocol number 255 (Reserved) or protocol 0 should not crash.
func TestAttack_InvalidProtocolNumber(t *testing.T) {
	// Protocol 0 is "IPv6 Hop-by-Hop Option" which is effectively no L4 payload
	// The packet parser should handle this by returning Protocol="IP-0"
	store := opa.NewDataStore()
	eval, _ := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true`,
		Store:  store,
	})
	eng := New(eval, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(10000, 100000000), true, false)

	pi := &packet.PacketInfo{
		SrcIP: "10.0.1.100", DstIP: "10.0.2.50", Protocol: "IP-255",
		SrcPort: 0, DstPort: 0,
	}
	result := eng.evaluatePacket(pi, 64)
	if result == nil {
		t.Fatal("evaluatePacket returned nil for unknown protocol")
	}
	// Should not crash — should produce some valid result
	_ = result
}

// ── R29: Empty reason string handling ─────────────────────────────
// OPA returns empty reason. Should not cause issues in logging or storage.
func TestAttack_EmptyOPAReason(t *testing.T) {
	store := opa.NewDataStore()
	policy := `package l3_firewall
import rego.v1
default allow := true
allow := false if { input.packet.dst_port == 22 }
`
	eval, _ := opa.NewEmbedded(opa.EmbedConfig{Policy: policy, Store: store})
	eng := New(eval, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(10000, 100000000), true, false)

	pi := &packet.PacketInfo{
		SrcIP: "10.0.1.100", DstIP: "10.0.2.50", Protocol: "TCP",
		SrcPort: 44001, DstPort: 22,
		TCPFlags: packet.TCPFlags{SYN: true},
	}
	result := eng.evaluatePacket(pi, 64)
	// Empty reason should not cause a panic or invalid state
	if result.Allowed {
		t.Error("expected block for SSH port 22")
	}
	// The reason might be empty (no `reason` rule), that's acceptable
	_ = result.Reason
}

// ── R30: Rate limiter with zero packet size ───────────────────────
// A packet with size 0 should not cause division issues in rate calculation.
func TestAttack_ZeroSizePacket(t *testing.T) {
	l := ratelimit.NewLimiter(100, 1000)
	l.Allow("10.0.1.100", 0)
	pps := l.GetPPS("10.0.1.100")
	if pps < 0 {
		t.Errorf("PPS = %f, want >= 0 for zero-size packet", pps)
	}
}
