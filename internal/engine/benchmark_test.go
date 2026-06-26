package engine

import (
	"testing"

	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/opa"
	"github.com/monch1962/l3-firewall/internal/packet"
	"github.com/monch1962/l3-firewall/internal/ratelimit"
)

func BenchmarkEvaluatePacketAllow(b *testing.B) {
	eval, _ := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true`,
	})
	eng := &Engine{
		eval:         eval,
		conntrack:    conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit:    ratelimit.NewLimiter(10000, 100000000),
		recentBlocks: make([]BlockLogEntry, 0, maxRecentBlocks),
		blockStats:   make(map[string]int64),
	}
	pi := &packet.PacketInfo{
		SrcIP: "10.0.1.100", DstIP: "10.0.2.50",
		Protocol: "TCP", SrcPort: 44001, DstPort: 443,
		TCPFlags: packet.TCPFlags{SYN: true, ACK: true},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.evaluatePacket(pi, 64)
	}
}

func BenchmarkEvaluatePacketBlock(b *testing.B) {
	eval, _ := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1
		default allow := true
		deny_test if { input.packet.dst_port == 22 }
		allow := false if { deny_test }
		reason := "blocked" if { deny_test }`,
	})
	eng := &Engine{
		eval:         eval,
		conntrack:    conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit:    ratelimit.NewLimiter(10000, 100000000),
		recentBlocks: make([]BlockLogEntry, 0, maxRecentBlocks),
		blockStats:   make(map[string]int64),
	}
	pi := &packet.PacketInfo{
		SrcIP: "10.0.1.100", DstIP: "10.0.2.50",
		Protocol: "TCP", SrcPort: 44001, DstPort: 22,
		TCPFlags: packet.TCPFlags{SYN: true},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.evaluatePacket(pi, 64)
	}
}

func BenchmarkConntrackLookup(b *testing.B) {
	ct := conntrack.NewTable(conntrack.DefaultConfig())
	for i := 0; i < 10000; i++ {
		ct.LookupOrCreate("10.0.1.1", "10.0.2.1", "TCP", uint16(40000+i), 80)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct.LookupOrCreate("10.0.1.1", "10.0.2.1", "TCP", uint16(50000+(i%10000)), 80)
	}
}

func BenchmarkRateLimiter(b *testing.B) {
	rl := ratelimit.NewLimiter(10000, 100000000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.Allow("10.0.1.100", 64)
	}
}

func BenchmarkOPAEval(b *testing.B) {
	eval, _ := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true`,
	})
	input := &opa.Input{
		Packet: opa.PacketInfo{
			SrcIP: "10.0.1.100", DstIP: "10.0.2.50",
			Protocol: "TCP", SrcPort: 44001, DstPort: 443,
		},
		Rate: opa.RateInfo{SrcIPpps: 100, SrcIPbps: 6400},
		Time: opa.TimeInfo{UtcHour: 12, UtcDay: 3},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eval.Evaluate(input)
	}
}
