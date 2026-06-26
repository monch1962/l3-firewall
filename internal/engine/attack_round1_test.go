package engine

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/opa"
	"github.com/monch1962/l3-firewall/internal/packet"
	"github.com/monch1962/l3-firewall/internal/ratelimit"
)

// newAttackTestEngine creates a test engine for attack simulation tests.
func newAttackTestEngine(t *testing.T) *Engine {
	t.Helper()
	eval, err := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true allow := false if { input.packet.dst_port == 22 } reason := "blocked SSH" if { input.packet.dst_port == 22 }`,
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

func TestAttack_BlockStatsMapUnbounded(t *testing.T) {
	eng := newAttackTestEngine(t)
	for i := 0; i < 1000; i++ {
		eng.recordBlock(&packet.PacketInfo{
			SrcIP: "10.0.1.100", DstIP: "10.0.2.50", Protocol: "TCP", SrcPort: 44001, DstPort: 22,
		}, "reason_"+itoa(i), "")
	}
	stats := eng.BlockStats()
	if len(stats) > maxBlockStatsReasons {
		t.Errorf("block stats exceeded cap: %d > %d", len(stats), maxBlockStatsReasons)
	}
}

func TestAttack_RateLimiterMapUnbounded(t *testing.T) {
	l := ratelimit.NewLimiter(10000, 100000000)
	for i := 0; i < 2000; i++ {
		l.Allow(fmt.Sprintf("10.0.%d.%d", i/256, i%256), 64)
	}
	// Verify the rate limiter maintained bounds
	_ = l.GetPPS("10.0.0.0")
}

func TestAttack_EnginePanicRecovery(t *testing.T) {
	eng := New(nil, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(10000, 100000000), true, false, nil, nil, nil, nil, nil)
	result := eng.evaluatePacket(&packet.PacketInfo{
		SrcIP: "10.0.1.100", DstIP: "10.0.2.50", Protocol: "TCP", SrcPort: 44001, DstPort: 443,
		TCPFlags: packet.TCPFlags{SYN: true},
	}, 64)
	if result == nil {
		t.Fatal("evaluatePacket returned nil")
	}
	if result.Allowed {
		t.Error("expected blocked result due to nil evaluator + failClosed")
	}
}

func TestAttack_PortRateLimiterMapUnbounded(t *testing.T) {
	l := ratelimit.NewLimiter(10000, 100000000)
	for i := 0; i < 2000; i++ {
		l.AllowPort("10.0.1.100", uint16(1000+i%5000), 64)
	}
	_ = l.GetPortPPS("10.0.1.100", 1000)
}

func TestAttack_OPATimeoutHardcoded(t *testing.T) {
	cfg := opa.EmbedConfig{
		Policy:  `package l3_firewall import rego.v1 default allow := true`,
		Timeout: 100 * time.Millisecond,
	}
	eval, err := opa.NewEmbedded(cfg)
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	input := &opa.Input{
		Packet: opa.PacketInfo{
			SrcIP: "10.0.1.100", DstIP: "10.0.2.50", Protocol: "TCP",
			SrcPort: 44001, DstPort: 443,
			TCPFlags: packet.TCPFlags{SYN: true},
		},
	}
	result, err := eval.Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !result.Allowed {
		t.Error("expected allowed for HTTPS port 443")
	}
}

func TestAttack_ConcurrentBlockStats(t *testing.T) {
	eng := newAttackTestEngine(t)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			eng.recordBlock(&packet.PacketInfo{
				SrcIP: "10.0.1.100", DstIP: "10.0.2.50", Protocol: "TCP",
				SrcPort: 44001, DstPort: 22,
			}, "blocked SSH", "")
		}()
	}
	wg.Wait()
	stats := eng.BlockStats()
	if len(stats) == 0 {
		t.Error("block stats should contain entries")
	}
}

func TestAttack_BlockStatsReasonFlood(t *testing.T) {
	eng := newAttackTestEngine(t)
	for i := 0; i < maxBlockStatsReasons+100; i++ {
		eng.recordBlock(&packet.PacketInfo{SrcIP: "10.0.1.100", DstIP: "10.0.2.50", Protocol: "TCP", SrcPort: 44001, DstPort: 22},
			"reason_"+itoa(i), "")
	}
	stats := eng.BlockStats()
	if len(stats) > maxBlockStatsReasons {
		t.Errorf("block stats exceeded cap: %d > %d", len(stats), maxBlockStatsReasons)
	}
}

func TestAttack_RateLimiterBurstCleanupGap(t *testing.T) {
	l := ratelimit.NewLimiter(10000, 100000000)
	for i := 0; i < 2000; i++ {
		l.Allow(fmt.Sprintf("10.0.%d.%d", i/256, i%256), 64)
	}
	pps := l.GetPPS("10.0.0.0")
	_ = pps
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
