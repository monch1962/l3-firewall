package opa

import (
	"encoding/json"
	"testing"

	"github.com/monch1962/l3-firewall/internal/packet"
)

func TestResultJSON(t *testing.T) {
	r := &Result{Allowed: false, Reason: "SYN flood detected"}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	var got Result
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if got.Allowed != r.Allowed {
		t.Errorf("Allowed = %v, want %v", got.Allowed, r.Allowed)
	}
	if got.Reason != r.Reason {
		t.Errorf("Reason = %q, want %q", got.Reason, r.Reason)
	}
}

func TestResultAllowedDefault(t *testing.T) {
	r := &Result{Allowed: true}
	if !r.Allowed {
		t.Error("default result should be allowed")
	}
	if r.Reason != "" {
		t.Errorf("default reason should be empty, got %q", r.Reason)
	}
}

func TestBuildInput(t *testing.T) {
	pi := &packet.PacketInfo{
		SrcIP:    "10.0.1.100",
		DstIP:    "10.0.2.50",
		Protocol: "TCP",
		SrcPort:  44001,
		DstPort:  443,
		TCPFlags: packet.TCPFlags{SYN: true, ACK: false},
	}

	input := BuildInput(pi, 5.2, 42000, false, "", 0, 0, 0, nil)

	if input.Packet.SrcIP != "10.0.1.100" {
		t.Errorf("SrcIP = %q, want %q", input.Packet.SrcIP, "10.0.1.100")
	}
	if input.Packet.Protocol != "TCP" {
		t.Errorf("Protocol = %q, want %q", input.Packet.Protocol, "TCP")
	}
	if input.Rate.SrcIPpps != 5.2 {
		t.Errorf("SrcIPpps = %f, want %f", input.Rate.SrcIPpps, 5.2)
	}
	if input.Connection.Established {
		t.Error("Connection.Established should be false for new connection")
	}
}

func TestBuildInputWithRecentPorts(t *testing.T) {
	pi := &packet.PacketInfo{
		SrcIP:    "10.0.1.100",
		DstIP:    "10.0.2.50",
		Protocol: "TCP",
		SrcPort:  44001,
		DstPort:  80,
		TCPFlags: packet.TCPFlags{SYN: true},
	}

	recentPorts := []uint16{22, 23, 25, 80, 443, 8080, 3306, 5432, 6379, 27017}
	input := BuildInput(pi, 0, 0, false, "", 0, 0, 0, recentPorts)

	if len(input.Connection.RecentPorts) != 10 {
		t.Errorf("RecentPorts length = %d, want 10", len(input.Connection.RecentPorts))
	}
}

func TestBuildInputWithICMP(t *testing.T) {
	icmpType := uint8(8)
	icmpCode := uint8(0)
	pi := &packet.PacketInfo{
		SrcIP:    "10.0.1.100",
		DstIP:    "10.0.2.50",
		Protocol: "ICMP",
		ICMPType: &icmpType,
		ICMPCode: &icmpCode,
	}

	input := BuildInput(pi, 0, 0, false, "", 0, 0, 0, nil)

	if input.Packet.Protocol != "ICMP" {
		t.Errorf("Protocol = %q, want %q", input.Packet.Protocol, "ICMP")
	}
	if input.Packet.SrcPort != 0 {
		t.Errorf("SrcPort for ICMP = %d, want 0", input.Packet.SrcPort)
	}
	if input.Packet.DstPort != 0 {
		t.Errorf("DstPort for ICMP = %d, want 0", input.Packet.DstPort)
	}
}

func TestEmbeddedEvaluator(t *testing.T) {
	policy := `package l3_firewall
import rego.v1
default allow := true
allow := false if { input.packet.dst_port == 22 }
reason := "blocked SSH" if { allow == false }
`
	eval, err := NewEmbedded(EmbedConfig{Policy: policy})
	if err != nil {
		t.Fatalf("NewEmbedded failed: %v", err)
	}

	// Block SSH (port 22)
	input := &Input{
		Packet: PacketInfo{
			SrcIP: "10.0.1.100", DstIP: "10.0.2.50",
			Protocol: "TCP", SrcPort: 44001, DstPort: 22,
			TCPFlags: packet.TCPFlags{SYN: true},
		},
	}
	result, err := eval.Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if result.Allowed {
		t.Error("SSH to port 22 should be blocked")
	}
	if result.Reason != "blocked SSH" {
		t.Errorf("Reason = %q, want %q", result.Reason, "blocked SSH")
	}

	// Allow HTTP (port 80)
	input2 := &Input{
		Packet: PacketInfo{
			SrcIP: "10.0.1.100", DstIP: "10.0.2.50",
			Protocol: "TCP", SrcPort: 44002, DstPort: 80,
			TCPFlags: packet.TCPFlags{SYN: true},
		},
	}
	result2, err := eval.Evaluate(input2)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if !result2.Allowed {
		t.Error("HTTP to port 80 should be allowed")
	}
}

func TestEmbeddedEvaluatorLoad(t *testing.T) {
	// Initial policy
	initial := `package l3_firewall
import rego.v1
default allow := true
blocked_port := 8080
allow := false if { input.packet.dst_port == blocked_port }
`
	eval, err := NewEmbedded(EmbedConfig{Policy: initial})
	if err != nil {
		t.Fatalf("NewEmbedded failed: %v", err)
	}

	// Should block port 8080
	input := &Input{
		Packet: PacketInfo{
			SrcIP: "10.0.1.100", DstIP: "10.0.2.50",
			Protocol: "TCP", SrcPort: 44001, DstPort: 8080,
			TCPFlags: packet.TCPFlags{SYN: true},
		},
	}
	result, err := eval.Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if result.Allowed {
		t.Error("port 8080 should be blocked by initial policy")
	}

	// Hot-reload with new policy
	updated := `package l3_firewall
import rego.v1
default allow := true
blocked_port := 9090
allow := false if { input.packet.dst_port == blocked_port }
`
	if err := eval.Load(updated); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Should now block port 9090 instead
	input2 := &Input{
		Packet: PacketInfo{
			SrcIP: "10.0.1.100", DstIP: "10.0.2.50",
			Protocol: "TCP", SrcPort: 44001, DstPort: 9090,
			TCPFlags: packet.TCPFlags{SYN: true},
		},
	}
	result2, err := eval.Evaluate(input2)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if result2.Allowed {
		t.Error("port 9090 should be blocked after reload")
	}

	// Port 8080 should now be allowed (policy changed)
	input3 := &Input{
		Packet: PacketInfo{
			SrcIP: "10.0.1.100", DstIP: "10.0.2.50",
			Protocol: "TCP", SrcPort: 44001, DstPort: 8080,
			TCPFlags: packet.TCPFlags{SYN: true},
		},
	}
	result3, err := eval.Evaluate(input3)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if !result3.Allowed {
		t.Error("port 8080 should be allowed after reload (policy changed to block 9090)")
	}
}

func TestEmbeddedEvaluatorLoadEmpty(t *testing.T) {
	eval, err := NewEmbedded(EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true`,
	})
	if err != nil {
		t.Fatalf("NewEmbedded failed: %v", err)
	}

	if err := eval.Load(""); err == nil {
		t.Error("expected error for empty policy, got nil")
	}
}

func TestEmbeddedEvaluatorBadPolicy(t *testing.T) {
	_, err := NewEmbedded(EmbedConfig{Policy: "invalid rego {{"})
	if err == nil {
		t.Fatal("expected error for bad policy, got nil")
	}
}

func TestEmbeddedEvaluatorNilStoreNotNeeded(t *testing.T) {
	// DataStore is no longer required — configuration lives in the policy.
	_, err := NewEmbedded(EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true`,
	})
	if err != nil {
		t.Fatalf("NewEmbedded should work without store: %v", err)
	}
}

func TestEmbeddedEvaluatorReloadCh(t *testing.T) {
	eval, err := NewEmbedded(EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true`,
	})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}

	ch := eval.ReloadCh()
	if ch == nil {
		t.Fatal("ReloadCh returned nil")
	}

	// Trigger a reload
	eval.Load(`package l3_firewall import rego.v1 default allow := true allow := false if { input.packet.dst_port == 22 }`)

	// Check that the channel received a signal
	select {
	case <-ch:
		// Got the reload notification
	default:
		t.Error("expected reload notification on channel")
	}
}
