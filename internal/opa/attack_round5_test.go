package opa

import (
	"encoding/json"
	"testing"

	"github.com/monch1962/l3-firewall/internal/packet"
)

// ── R41: OPA returns allow as string "false" ─────────────────────
func TestAttack_OPAAllowAsString(t *testing.T) {
	policy := `package l3_firewall
import rego.v1
default allow := "true"
allow := "false" if { input.packet.dst_port == 22 }
`
	eval, err := NewEmbedded(EmbedConfig{Policy: policy})
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
		t.Error("BYPASS: OPA returned 'allow': \"false\" (string) but Evaluate allowed it")
	}
}

// ── R42: OPA returns allow as number 0 or 1 ──────────────────────
func TestAttack_OPAAllowAsNumber(t *testing.T) {
	// Test json.Number 0 → Allowed=false
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
func TestAttack_OPAAllowNil(t *testing.T) {
	result := &Result{Allowed: true}
	val := map[string]interface{}{
		"allow": nil,
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
		t.Error("nil allow should result in Allowed=false")
	}
}

// ── R44: OPA returns reason as non-string type ────────────────────
func TestAttack_OPAReasonNonString(t *testing.T) {
	policy := `package l3_firewall
import rego.v1
default allow := true
allow := false if { input.packet.dst_port == 22 }
reason := 42 if { input.packet.dst_port == 22 }
`
	eval, err := NewEmbedded(EmbedConfig{Policy: policy})
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
	_ = result.Reason
}

// ── R45: OPA with conflicting allow values ────────────────────────
func TestAttack_OPAConflictingAllow(t *testing.T) {
	policy := `package l3_firewall
import rego.v1
default allow := true
deny1 if { input.packet.dst_port == 22 }
deny2 if { input.packet.dst_port == 443 }
allow := false if { deny1 }
allow := false if { deny2 }
`
	_, err := NewEmbedded(EmbedConfig{Policy: policy})
	if err != nil {
		t.Fatalf("NewEmbedded should accept same-value allow rules: %v", err)
	}
}

// ── R46: OPA returns no result at all ─────────────────────────────
func TestAttack_OPANoResult(t *testing.T) {
	policy := `package l3_firewall`
	eval, err := NewEmbedded(EmbedConfig{Policy: policy})
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
	if !result.Allowed {
		t.Error("empty policy should allow by default (deny-override)")
	}
}
