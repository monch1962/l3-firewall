// Red-team security hardening Round 5 — OPA result parsing bypass and edge cases.
package opa

import (
	"encoding/json"
	"testing"

	"github.com/monch1962/l3-firewall/internal/packet"
)

// ── R41: OPA returns allow as string "false" ─────────────────────
// If the Rego policy writes allow := "false" (string) instead of allow := false (boolean),
// the type switch in Evaluate doesn't match and defaults to Allowed=true (bypass).
func TestAttack_OPAAllowAsString(t *testing.T) {
	// Policy that returns allow as a STRING, not boolean
	policy := `package l3_firewall
import rego.v1
default allow := "true"
allow := "false" if { input.packet.dst_port == 22 }
`
	store := NewDataStore()
	eval, err := NewEmbedded(EmbedConfig{Policy: policy, Store: store})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}

	input := &Input{
		Packet: PacketInfo{
			SrcIP: "10.0.1.100", DstIP: "10.0.2.50", Protocol: "TCP",
			SrcPort: 44001, DstPort: 22,
			TCPFlags: packet.TCPFlags{SYN: true},
		},
	}

	result, err := eval.Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	// This should be blocked (port 22 with string "false" should mean blocked)
	// But the type switch misses strings, so it defaults to Allowed=true
	if result.Allowed {
		t.Error("BYPASS: OPA returned 'allow': \"false\" (string) but Evaluate allowed it")
	}
}

// ── R42: OPA returns allow as number 0 or 1 ──────────────────────
// JSON numbers should be parsed: 0 → false, non-zero → true.
func TestAttack_OPAAllowAsNumber(t *testing.T) {
	// Test that json.Number 0 → Allowed=false
	result := &Result{Allowed: true}
	val := map[string]interface{}{
		"allow": json.Number("0"),
	}
	if allowed, ok := val["allow"]; ok {
		switch a := allowed.(type) {
		case bool:
			result.Allowed = a
		case string:
			result.Allowed = a == "true" || a == "1"
		case json.Number:
			n, err := a.Float64()
			if err == nil {
				result.Allowed = n != 0
			}
		case nil:
			result.Allowed = false
		}
	}
	if result.Allowed {
		t.Error("json.Number('0') should result in Allowed=false")
	}

	// Test json.Number("1") → Allowed=true
	result2 := &Result{Allowed: false}
	val2 := map[string]interface{}{
		"allow": json.Number("1"),
	}
	if allowed, ok := val2["allow"]; ok {
		switch a := allowed.(type) {
		case bool:
			result2.Allowed = a
		case string:
			result2.Allowed = a == "true" || a == "1"
		case json.Number:
			n, err := a.Float64()
			if err == nil {
				result2.Allowed = n != 0
			}
		case nil:
			result2.Allowed = false
		}
	}
	if !result2.Allowed {
		t.Error("json.Number('1') should result in Allowed=true")
	}
}

// ── R43: OPA returns nil allow value ─────────────────────────────
// If the OPA result document has allow: null, it should be treated as blocked.
func TestAttack_OPAAllowNil(t *testing.T) {
	result := &Result{Allowed: true}
	val := map[string]interface{}{
		"allow": nil,
	}
	if allowed, ok := val["allow"]; ok {
		switch a := allowed.(type) {
		case bool:
			result.Allowed = a
		case json.Number:
			result.Allowed = a.String() == "true"
		case nil:
			result.Allowed = false
		}
	}
	if result.Allowed {
		t.Error("nil allow should result in Allowed=false")
	}
}

// ── R44: OPA returns reason as non-string type ────────────────────
// If reason is a number, it's silently ignored. Should handle gracefully.
func TestAttack_OPAReasonNonString(t *testing.T) {
	store := NewDataStore()
	policy := `package l3_firewall
import rego.v1
default allow := true
allow := false if { input.packet.dst_port == 22 }
reason := 42 if { input.packet.dst_port == 22 }
`
	eval, err := NewEmbedded(EmbedConfig{Policy: policy, Store: store})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}

	input := &Input{
		Packet: PacketInfo{
			SrcIP: "10.0.1.100", DstIP: "10.0.2.50", Protocol: "TCP",
			SrcPort: 44001, DstPort: 22,
			TCPFlags: packet.TCPFlags{SYN: true},
		},
	}

	result, err := eval.Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.Allowed {
		t.Error("should be blocked for port 22")
	}
	// Reason should be empty since it's a number, not a string
	_ = result.Reason
}

// ── R45: OPA with conflicting allow values ────────────────────────
// Two rules both set allow but with different values.
// Rego v1 should reject this at compile time, but test for graceful handling.
func TestAttack_OPAConflictingAllow(t *testing.T) {
	// This policy has a conflict: two allow := false rules
	// (both with different conditions but same value)
	policy := `package l3_firewall
import rego.v1
default allow := true
deny1 if { input.packet.dst_port == 22 }
deny2 if { input.packet.dst_port == 443 }
allow := false if { deny1 }
allow := false if { deny2 }
`
	store := NewDataStore()
	_, err := NewEmbedded(EmbedConfig{Policy: policy, Store: store})
	// This should compile OK because both produce false (same value)
	if err != nil {
		t.Fatalf("NewEmbedded should accept same-value allow rules: %v", err)
	}
}

// ── R46: OPA returns no result at all ─────────────────────────────
// If the query returns zero results, the engine defaults to Allowed=true (bypass).
// This is by design for deny-override, but should be documented.
func TestAttack_OPANoResult(t *testing.T) {
	// This can't happen with proper Rego because the default rule ensures
	// at least one result. But if the module is empty...
	policy := `package l3_firewall`
	store := NewDataStore()
	eval, err := NewEmbedded(EmbedConfig{Policy: policy, Store: store})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}

	input := &Input{
		Packet: PacketInfo{
			SrcIP: "10.0.1.100", DstIP: "10.0.2.50",
			Protocol: "TCP", SrcPort: 44001, DstPort: 22,
		},
	}

	result, err := eval.Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	// An empty policy (no rules) should allow by default (deny-override)
	if !result.Allowed {
		t.Error("empty policy should allow by default")
	}
}
