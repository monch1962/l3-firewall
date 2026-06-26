package engine

import (
	"testing"

	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/opa"
	"github.com/monch1962/l3-firewall/internal/packet"
	"github.com/monch1962/l3-firewall/internal/ratelimit"
)

const testPolicy = `package l3_firewall
import rego.v1
default allow := true
deny_ssh if { input.packet.dst_port == 22 }
allow := false if { deny_ssh }
reason := "blocked SSH" if { deny_ssh }
`

func newTestEngine(t *testing.T) *Engine {
	t.Helper()

	store := opa.NewDataStore()
	eval, err := opa.NewEmbedded(opa.EmbedConfig{
		Policy: testPolicy,
		Store:  store,
	})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}

	return &Engine{
		eval:         eval,
		conntrack:    conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit:    ratelimit.NewLimiter(10000, 100000000),
		auditOnly:    false,
		failClosed:   true,
		recentBlocks: make([]BlockLogEntry, 0, maxRecentBlocks),
		blockStats:   make(map[string]int64),
	}
}

func buildTestPacket(srcIP, dstIP string, srcPort, dstPort uint16, syn, ack bool) *packet.PacketInfo {
	return &packet.PacketInfo{
		SrcIP: srcIP, DstIP: dstIP, Protocol: "TCP",
		SrcPort: srcPort, DstPort: dstPort,
		TCPFlags:   packet.TCPFlags{SYN: syn, ACK: ack},
		PacketSize: 64,
	}
}

func TestEvaluateAllowsHTTPS(t *testing.T) {
	eng := newTestEngine(t)
	pi := buildTestPacket("10.0.1.100", "10.0.2.50", 44001, 443, true, false)
	result := eng.evaluatePacket(pi, 64)
	if !result.Allowed {
		t.Errorf("HTTPS allowed: got reason %s", result.Reason)
	}
}

func TestEvaluateBlocksSSH(t *testing.T) {
	eng := newTestEngine(t)
	pi := buildTestPacket("10.0.1.100", "10.0.2.50", 44001, 22, true, false)
	result := eng.evaluatePacket(pi, 64)
	if result.Allowed {
		t.Error("SSH should be blocked")
	}
	if result.Reason != "blocked SSH" {
		t.Errorf("Reason = %q, want %q", result.Reason, "blocked SSH")
	}
}

func TestRecentBlocks(t *testing.T) {
	eng := newTestEngine(t)
	pi := buildTestPacket("10.0.1.100", "10.0.2.50", 44001, 22, true, false)
	eng.evaluatePacket(pi, 64)

	blocks := eng.RecentBlocks()
	if len(blocks) != 1 {
		t.Fatalf("RecentBlocks len = %d, want 1", len(blocks))
	}
	if blocks[0].Reason != "blocked SSH" {
		t.Errorf("Block reason = %q, want %q", blocks[0].Reason, "blocked SSH")
	}
	if blocks[0].SrcIP != "10.0.1.100" {
		t.Errorf("SrcIP = %q, want %q", blocks[0].SrcIP, "10.0.1.100")
	}
	if blocks[0].DstIP != "10.0.2.50" {
		t.Errorf("DstIP = %q, want %q", blocks[0].DstIP, "10.0.2.50")
	}
	if blocks[0].DstPort != 22 {
		t.Errorf("DstPort = %d, want %d", blocks[0].DstPort, 22)
	}
	if blocks[0].Protocol != "TCP" {
		t.Errorf("Protocol = %q, want %q", blocks[0].Protocol, "TCP")
	}
}

func TestRecentBlocksMaxCapacity(t *testing.T) {
	eng := newTestEngine(t)
	pi := buildTestPacket("10.0.1.100", "10.0.2.50", 44001, 22, true, false)

	// Generate 150 blocks (capacity is 100)
	for i := 0; i < 150; i++ {
		eng.evaluatePacket(pi, 64)
	}

	blocks := eng.RecentBlocks()
	if len(blocks) > 100 {
		t.Errorf("RecentBlocks len = %d, want <= 100", len(blocks))
	}
}

func TestRecentBlocksEmpty(t *testing.T) {
	eng := newTestEngine(t)
	blocks := eng.RecentBlocks()
	if blocks != nil {
		t.Errorf("RecentBlocks = %v, want nil", blocks)
	}
}

func TestEngineRunningStatus(t *testing.T) {
	eng := newTestEngine(t)
	if eng.Running() {
		t.Error("Engine should not be running before Run()")
	}
}

func TestEngineStats(t *testing.T) {
	eng := newTestEngine(t)
	pi := buildTestPacket("10.0.1.100", "10.0.2.50", 44001, 443, true, false)
	eng.evaluatePacket(pi, 64)

	// Block SSH
	pi2 := buildTestPacket("10.0.2.50", "10.0.1.100", 40001, 22, true, false)
	eng.evaluatePacket(pi2, 64)

	s := eng.Stats()
	if s.PacketsProcessed != 2 {
		t.Errorf("PacketsProcessed = %d, want 2", s.PacketsProcessed)
	}
	if s.PacketsAllowed != 1 {
		t.Errorf("PacketsAllowed = %d, want 1", s.PacketsAllowed)
	}
	if s.PacketsBlocked != 1 {
		t.Errorf("PacketsBlocked = %d, want 1", s.PacketsBlocked)
	}
}

func TestEngineConntrackStats(t *testing.T) {
	eng := newTestEngine(t)
	s := eng.ConntrackStats()
	if s.Created != 0 {
		t.Errorf("Created = %d, want 0", s.Created)
	}
}

func TestAuditOnlyDefense(t *testing.T) {
	eng := newTestEngine(t)
	eng.auditOnly = true
	pi := buildTestPacket("10.0.1.100", "10.0.2.50", 44001, 22, true, false)
	result := eng.evaluatePacket(pi, 64)
	if !result.Allowed {
		t.Error("SSH should be allowed in audit-only mode")
	}
}

func TestFailClosed(t *testing.T) {
	eng := &Engine{
		eval:         nil,
		conntrack:    conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit:    ratelimit.NewLimiter(10000, 100000000),
		failClosed:   true,
		recentBlocks: make([]BlockLogEntry, 0, maxRecentBlocks),
		blockStats:   make(map[string]int64),
	}
	pi := buildTestPacket("10.0.1.100", "10.0.2.50", 44001, 443, true, false)
	result := eng.evaluatePacket(pi, 64)
	if result.Allowed {
		t.Error("fail-closed should block when evaluator is nil")
	}
}

func TestBlockLogContainsMetadata(t *testing.T) {
	eng := newTestEngine(t)
	pi := buildTestPacket("10.0.1.100", "10.0.2.50", 44001, 22, true, false)
	eng.evaluatePacket(pi, 64)

	blocks := eng.RecentBlocks()
	if len(blocks) == 0 {
		t.Fatal("no blocks recorded")
	}
	b := blocks[0]
	if b.Timestamp.IsZero() {
		t.Error("block timestamp should be set")
	}
	if b.SrcPort != 44001 {
		t.Errorf("SrcPort = %d, want 44001", b.SrcPort)
	}
	if b.PacketSize != 64 {
		t.Errorf("PacketSize = %d, want 64", b.PacketSize)
	}
}
