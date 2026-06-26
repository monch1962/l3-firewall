package engine

import (
	"testing"
	"time"

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
	eval, err := opa.NewEmbedded(opa.EmbedConfig{Policy: testPolicy})
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

func TestEvaluateAllowsHTTPS(t *testing.T) {
	eng := newTestEngine(t)

	pi := buildTestPacket("10.0.1.100", "10.0.2.50", 44001, 443, true, false)
	result := eng.evaluatePacket(pi, 64)

	if result == nil {
		t.Fatal("evaluatePacket returned nil")
	}
	if !result.Allowed {
		t.Errorf("expected allowed for HTTPS, got blocked: %s", result.Reason)
	}
}

func TestEvaluateBlocksSSH(t *testing.T) {
	eng := newTestEngine(t)

	pi := buildTestPacket("10.0.1.100", "10.0.2.50", 44001, 22, true, false)
	result := eng.evaluatePacket(pi, 64)

	if result == nil {
		t.Fatal("evaluatePacket returned nil")
	}
	if result.Allowed {
		t.Errorf("expected blocked for SSH, got allowed")
	}
	if result.Reason != "blocked SSH" {
		t.Errorf("reason = %q, want %q", result.Reason, "blocked SSH")
	}
}

func TestRecentBlocks(t *testing.T) {
	eng := newTestEngine(t)
	pi := buildTestPacket("10.0.1.100", "10.0.2.50", 44001, 22, true, false)
	eng.evaluatePacket(pi, 64)

	blocks := eng.RecentBlocks()
	if len(blocks) == 0 {
		t.Fatal("expected at least one block entry")
	}
	if blocks[0].Reason != "blocked SSH" {
		t.Errorf("block reason = %q, want %q", blocks[0].Reason, "blocked SSH")
	}
	if blocks[0].SrcIP != "10.0.1.100" {
		t.Errorf("src_ip = %q, want %q", blocks[0].SrcIP, "10.0.1.100")
	}
}

func TestRecentBlocksMaxCapacity(t *testing.T) {
	eng := newTestEngine(t)
	for i := 0; i < maxRecentBlocks+50; i++ {
		pi := buildTestPacket("10.0.1.100", "10.0.2.50", 44001, 22, true, false)
		eng.evaluatePacket(pi, 64)
	}
	blocks := eng.RecentBlocks()
	if len(blocks) > maxRecentBlocks {
		t.Errorf("blocks = %d, want <= %d", len(blocks), maxRecentBlocks)
	}
}

func TestRecentBlocksEmpty(t *testing.T) {
	eng := newTestEngine(t)
	blocks := eng.RecentBlocks()
	if len(blocks) != 0 {
		t.Errorf("expected empty blocks, got %d", len(blocks))
	}
}

func TestEngineRunningStatus(t *testing.T) {
	eng := newTestEngine(t)
	if eng.Running() {
		t.Error("engine should not be running before Start() is called")
	}
}

func TestEngineStats(t *testing.T) {
	eng := newTestEngine(t)
	eng.evaluatePacket(buildTestPacket("10.0.2.50", "10.0.1.100", 443, 44001, true, false), 64)
	stats := eng.Stats()
	if stats.PacketsProcessed < 1 {
		t.Errorf("PacketsProcessed = %d, want >= 1", stats.PacketsProcessed)
	}
}

func TestEngineConntrackStats(t *testing.T) {
	eng := newTestEngine(t)
	pi := buildTestPacket("10.0.1.100", "10.0.2.50", 44001, 443, true, false)
	eng.evaluatePacket(pi, 64)

	ctStats := eng.ConntrackStats()
	if ctStats.Created == 0 {
		t.Error("expected at least one conntrack entry")
	}
}

func TestAuditOnlyDefense(t *testing.T) {
	eval, _ := opa.NewEmbedded(opa.EmbedConfig{Policy: testPolicy})
	eng := &Engine{
		eval:         eval,
		conntrack:    conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit:    ratelimit.NewLimiter(10000, 100000000),
		auditOnly:    true,
		failClosed:   true,
		recentBlocks: make([]BlockLogEntry, 0, maxRecentBlocks),
		blockStats:   make(map[string]int64),
	}
	pi := buildTestPacket("10.0.1.100", "10.0.2.50", 44001, 22, true, false)
	result := eng.evaluatePacket(pi, 64)
	if !result.Allowed {
		t.Error("audit-only should allow all traffic")
	}
}

func TestFailClosed(t *testing.T) {
	eng := &Engine{
		eval:         nil,
		conntrack:    conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit:    ratelimit.NewLimiter(10000, 100000000),
		auditOnly:    false,
		failClosed:   true,
		recentBlocks: make([]BlockLogEntry, 0, maxRecentBlocks),
		blockStats:   make(map[string]int64),
	}
	pi := buildTestPacket("10.0.1.100", "10.0.2.50", 44001, 443, true, false)
	result := eng.evaluatePacket(pi, 64)
	if result == nil {
		t.Fatal("evaluatePacket returned nil")
	}
	if result.Allowed {
		t.Error("expected blocked result due to nil evaluator + failClosed")
	}
}

func TestBlockLogContainsMetadata(t *testing.T) {
	eng := newTestEngine(t)
	pi := buildTestPacket("10.0.1.100", "10.0.2.50", 44001, 22, true, false)
	eng.evaluatePacket(pi, 64)

	blocks := eng.RecentBlocks()
	if len(blocks) == 0 {
		t.Fatal("expected at least one block entry")
	}
	if blocks[0].SrcIP != "10.0.1.100" {
		t.Errorf("SrcIP = %q, want %q", blocks[0].SrcIP, "10.0.1.100")
	}
	if blocks[0].DstIP != "10.0.2.50" {
		t.Errorf("DstIP = %q, want %q", blocks[0].DstIP, "10.0.2.50")
	}
	if blocks[0].Protocol != "TCP" {
		t.Errorf("Protocol = %q, want TCP", blocks[0].Protocol)
	}
	if blocks[0].DstPort != 22 {
		t.Errorf("DstPort = %d, want 22", blocks[0].DstPort)
	}
	if blocks[0].Reason != "blocked SSH" {
		t.Errorf("Reason = %q, want %q", blocks[0].Reason, "blocked SSH")
	}
}

func TestEngineConnectionLimit(t *testing.T) {
	cfg := conntrack.Config{
		MaxEntries:       1000,
		MaxFlowsPerSrcIP: 1,
		IdleTimeout:      300 * time.Second,
		UDPTimeout:       30 * time.Second,
		ICMPTimeout:      5 * time.Second,
		PortScanMaxPorts: 100,
	}
	eval, _ := opa.NewEmbedded(opa.EmbedConfig{Policy: testPolicy})
	eng := &Engine{
		eval:         eval,
		conntrack:    conntrack.NewTable(cfg),
		ratelimit:    ratelimit.NewLimiter(10000, 100000000),
		auditOnly:    false,
		failClosed:   true,
		recentBlocks: make([]BlockLogEntry, 0, maxRecentBlocks),
		blockStats:   make(map[string]int64),
	}

	// First flow from this src should be allowed
	pi1 := buildTestPacket("10.0.1.100", "10.0.2.50", 44001, 443, true, false)
	r1 := eng.evaluatePacket(pi1, 64)
	if r1 == nil || !r1.Allowed {
		t.Errorf("first flow expected allowed, got blocked: %v", r1)
	}

	// Second flow from same src should be blocked due to connection limit
	pi2 := buildTestPacket("10.0.1.100", "10.0.2.51", 44002, 80, true, false)
	r2 := eng.evaluatePacket(pi2, 64)
	if r2 == nil || r2.Allowed {
		t.Errorf("second flow expected blocked (connection limit), got allowed: %v", r2)
	}
	if r2.Reason != "connection limit exceeded for source IP" {
		t.Errorf("block reason = %q, want %q", r2.Reason, "connection limit exceeded for source IP")
	}
}

func TestEngineConnectionLimitDifferentSrcOK(t *testing.T) {
	cfg := conntrack.Config{
		MaxEntries:       1000,
		MaxFlowsPerSrcIP: 1,
		IdleTimeout:      300 * time.Second,
		UDPTimeout:       30 * time.Second,
		ICMPTimeout:      5 * time.Second,
		PortScanMaxPorts: 100,
	}
	eval, _ := opa.NewEmbedded(opa.EmbedConfig{Policy: testPolicy})
	eng := &Engine{
		eval:         eval,
		conntrack:    conntrack.NewTable(cfg),
		ratelimit:    ratelimit.NewLimiter(10000, 100000000),
		auditOnly:    false,
		failClosed:   true,
		recentBlocks: make([]BlockLogEntry, 0, maxRecentBlocks),
		blockStats:   make(map[string]int64),
	}

	pi1 := buildTestPacket("10.0.1.100", "10.0.2.50", 44001, 443, true, false)
	r1 := eng.evaluatePacket(pi1, 64)
	if r1 == nil || !r1.Allowed {
		t.Fatalf("first flow expected allowed")
	}

	// Different source should be allowed
	pi2 := buildTestPacket("10.0.2.100", "10.0.2.50", 44001, 80, true, false)
	r2 := eng.evaluatePacket(pi2, 64)
	if r2 == nil || !r2.Allowed {
		t.Errorf("flow from different source expected allowed, got blocked: %v", r2)
	}
}

func buildTestPacket(srcIP, dstIP string, srcPort, dstPort uint16, syn, ack bool) *packet.PacketInfo {
	return &packet.PacketInfo{
		SrcIP: srcIP, DstIP: dstIP, Protocol: "TCP",
		SrcPort: srcPort, DstPort: dstPort,
		TCPFlags: packet.TCPFlags{SYN: syn, ACK: ack},
	}
}
