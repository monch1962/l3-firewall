package engine

import (
	"testing"

	"github.com/florianl/go-nfqueue"
	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/packet"
	"github.com/monch1962/l3-firewall/internal/ratelimit"
)

// ── R40.3: unparseable packets fail OPEN (accepted) ────────────────
// packetHandler returns 0 (NF_ACCEPT) when packet.ParsePacket fails.
// Round 10 made PANICS in the packet path fail-closed (ret=1), but parse
// errors — equally attacker-influenced — still fail open: anything the
// firewall cannot understand is silently passed, bypassing every policy
// layer. For a security device, unparseable must mean DROP (fail-closed).
func TestAttack_ParseErrorFailOpen(t *testing.T) {
	eng := New(nil, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(0, 0),
		false, false, nil, nil, nil, nil, nil, "", nil)

	payloads := [][]byte{
		{0xde, 0xad, 0xbe, 0xef}, // not IP at all / too short
		{0x07, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // IP version 7
		{0x45, 0x00, 0x00}, // truncated IPv4 header
	}
	for _, payload := range payloads {
		id := uint32(1)
		attr := nfqueue.Attribute{Payload: &payload, PacketID: &id}
		if ret := eng.packetHandler(attr); ret != 1 {
			t.Errorf("unparseable packet verdict = %d (want 1 = DROP); fail-open accept bypasses all policy", ret)
		}
	}
}

// ── R40.4: --rate-limit-pps / --rate-limit-bps flags never enforced ─
// The flags are documented as per-IP packet/byte rate limits, but the
// values only populate Limiter fields that nothing ever reads. The engine
// passes measured rates to OPA, whose hardcoded policy threshold is 10000
// pps — an operator setting --rate-limit-pps 100 believes traffic is
// capped at 100 pps when the firewall actually allows 10000. The operator's
// rate-limit intent is silently dropped.
func TestAttack_RateLimitPPSFlagNotEnforced(t *testing.T) {
	eng := New(nil, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(1, 0), // operator: cap at 1 pps
		false, false, nil, nil, nil, nil, nil, "", nil)

	pi := &packet.PacketInfo{
		SrcIP: "10.0.0.1", DstIP: "8.8.8.8", Protocol: "UDP",
		SrcPort: 1000, DstPort: 53, PacketSize: 64,
	}

	blocked := 0
	for i := 0; i < 5; i++ {
		if res := eng.evaluatePacket(pi, 64); !res.Allowed {
			blocked++
		}
	}
	if blocked == 0 {
		t.Error("5 packets sent at ~1M pps against --rate-limit-pps 1: none blocked — rate limit flag not enforced")
	}
	t.Logf("blocked %d of 5 packets over the configured 1 pps limit", blocked)
}

// ── R40.4 (BPS variant) ─────────────────────────────────────────────
func TestAttack_RateLimitBPSFlagNotEnforced(t *testing.T) {
	eng := New(nil, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(0, 100), // operator: cap at 100 bytes/s
		false, false, nil, nil, nil, nil, nil, "", nil)

	pi := &packet.PacketInfo{
		SrcIP: "10.0.0.1", DstIP: "8.8.8.8", Protocol: "UDP",
		SrcPort: 1000, DstPort: 53, PacketSize: 100000,
	}

	blocked := 0
	for i := 0; i < 5; i++ {
		if res := eng.evaluatePacket(pi, 100000); !res.Allowed {
			blocked++
		}
	}
	if blocked == 0 {
		t.Error("100KB packets against --rate-limit-bps 100: none blocked — byte rate limit flag not enforced")
	}
}
