package engine

import (
	"testing"

	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/opa"
	"github.com/monch1962/l3-firewall/internal/packet"
	"github.com/monch1962/l3-firewall/internal/ratelimit"
	"github.com/monch1962/l3-firewall/internal/threatintel"
)

// ── R82.1 (engine plane): a poisoned blocklist blackholes the v4 plane ──
// The threat-intel layer returns a hard deny before OPA is consulted, so a
// blocklist that matches everything is a total-outage switch. Prove the
// engine path end to end: a benign packet must stay allowed when the only
// blocklist content is the mapped-space entry.
func TestAttack_ThreatIntelPoisonEntryDoesNotBlackholeEngine(t *testing.T) {
	bl := threatintel.NewBlocklist()
	bl.Add("::ffff:0:0/96") // the single poison feed line

	eval, err := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true`,
	})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	eng := New(eval, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(10000, 100000000),
		false, false, nil, nil, nil, bl, nil, "", nil)

	pi := &packet.PacketInfo{
		SrcIP:    "203.0.113.9", // ordinary public source
		DstIP:    "10.0.0.5",
		Protocol: "TCP",
		SrcPort:  44321,
		DstPort:  443,
	}
	result := eng.evaluatePacket(pi, 64)
	if result == nil {
		t.Fatal("evaluatePacket returned nil")
	}
	if !result.Allowed {
		t.Errorf("benign packet was BLOCKED (reason=%q) — one poison blocklist entry blackholed all IPv4", result.Reason)
	}
}

// ── R82.3 (contract pin): threat intel is a hard safety layer ────────
// --opa-audit-only governs POLICY decisions only. The pre-OPA hard layers
// (connection limit, per-IP rate limit, L2 MAC, threat intel) enforce
// unconditionally — otherwise the operator's explicit blocklist would be a
// silently dropped control (R40.4). Pin the behaviour so the README text
// and the code can never drift apart again.
func TestAttack_ThreatIntelEnforcesInAuditOnlyMode(t *testing.T) {
	bl := threatintel.NewBlocklist()
	bl.Add("198.51.100.23")

	eval, err := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true`,
	})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	eng := New(eval, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(10000, 100000000),
		false, true /* audit-only */, nil, nil, nil, bl, nil, "", nil)

	pi := &packet.PacketInfo{
		SrcIP:    "198.51.100.23",
		DstIP:    "10.0.0.5",
		Protocol: "TCP",
		SrcPort:  40000,
		DstPort:  443,
	}
	result := eng.evaluatePacket(pi, 64)
	if result == nil {
		t.Fatal("evaluatePacket returned nil")
	}
	if result.Allowed {
		t.Error("blocklisted source ALLOWED under --opa-audit-only — the threat-intel layer is a hard " +
			"safety layer and must enforce (README now states audit-only governs policy only)")
	}
	if result.Reason != "source IP in threat intelligence blocklist" {
		t.Errorf("unexpected reason %q", result.Reason)
	}
}

// ── R82.1 control: the blocklist still blocks a listed source ────────
func TestAttack_ThreatIntelListedSourceStillBlocked(t *testing.T) {
	bl := threatintel.NewBlocklist()
	bl.Add("203.0.113.66")

	eval, err := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true`,
	})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	eng := New(eval, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(10000, 100000000),
		false, false, nil, nil, nil, bl, nil, "", nil)

	pi := &packet.PacketInfo{
		SrcIP: "203.0.113.66", DstIP: "10.0.0.5", Protocol: "TCP", SrcPort: 40001, DstPort: 443,
	}
	if result := eng.evaluatePacket(pi, 64); result == nil || result.Allowed {
		t.Errorf("listed source allowed — threat intel regression: %+v", result)
	}
}
