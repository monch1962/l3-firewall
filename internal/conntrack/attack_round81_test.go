package conntrack

import (
	"testing"
	"time"
)

// ── R81.3: ICMPv6 flows inherit the TCP idle timeout ─────────────────────────
//
// idleTimeoutFor() has cases for "UDP" and "ICMP" and falls through to
// cfg.IdleTimeout (the TCP timeout, 300s) for everything else. R79 changed the
// parser's ICMPv6 classification from "IP-58" to "ICMPv6" — which is what the
// conntrack flow key stores — but the timeout switch was never given the new
// name, so ICMPv6 flows are held for 300s instead of cfg.ICMPTimeout (5s).
//
// Security consequence: the flow table is the firewall's only per-5-tuple
// state. An attacker sending ICMPv6 (echo request/reply, or any forged ICMPv6
// type) from spoofed source addresses fills MaxEntries slots that — at 300s
// residency rather than 5s — live 60x longer, so the same packet rate pins the
// table full 60x more effectively and evicts legitimate TCP/UDP flows (state
// loss: Established=false for live connections). ICMP is exactly the protocol
// whose flows have no handshake for the table to key on, which is why the
// ICMPTimeout exists at all — ICMPv6 needs the same treatment.
func TestAttack_ICMPv6FlowInheritsTCPIdleTimeout(t *testing.T) {
	cfg := Config{
		MaxEntries:       1000,
		IdleTimeout:      300 * time.Second, // TCP default
		UDPTimeout:       30 * time.Second,
		ICMPTimeout:      50 * time.Millisecond,
		PortScanMaxPorts: 100,
	}
	ct := NewTable(cfg)

	ct.LookupOrCreate("2001:db8::9", "2001:db8::7", "ICMPv6", 0, 0)
	// Control: a TCP flow must NOT expire on the ICMP timeout.
	ct.LookupOrCreate("2001:db8::9", "2001:db8::7", "TCP", 40000, 443)

	time.Sleep(80 * time.Millisecond)

	expired := ct.Expire()
	if expired != 1 {
		t.Errorf("Expire() = %d flows, want 1: the ICMPv6 flow must expire on ICMPTimeout "+
			"(50ms), not on the TCP IdleTimeout (300s) — the table held it 60x too long", expired)
	}
	if ct.Len() != 1 {
		t.Errorf("Len() = %d, want 1 (only the TCP flow should remain)", ct.Len())
	}

	// The same 5-tuple in ICMPv4 form must have identical lifetime semantics —
	// the family must not decide how long the firewall remembers a flow.
	ct4 := NewTable(cfg)
	ct4.LookupOrCreate("198.51.100.9", "198.51.100.7", "ICMP", 0, 0)
	time.Sleep(80 * time.Millisecond)
	if n := ct4.Expire(); n != 1 {
		t.Errorf("ICMPv4 control: Expire() = %d, want 1 (the v4 arm of the same control)", n)
	}
}
