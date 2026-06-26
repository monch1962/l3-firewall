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

	input := BuildInput(pi, 5.2, 42000, false, nil)

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
	if input.Rate.SrcIPpps != 5.2 {
		t.Errorf("SrcIPpps = %f, want %f", input.Rate.SrcIPpps, 5.2)
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
	input := BuildInput(pi, 0, 0, false, recentPorts)

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

	input := BuildInput(pi, 0, 0, false, nil)

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

func TestDataStoreParams(t *testing.T) {
	store := NewDataStore()
	if store == nil {
		t.Fatal("NewDataStore returned nil")
	}

	params := store.GetParams()
	if params == nil {
		t.Fatal("GetParams should return non-nil map")
	}

	// Set and get params
	newParams := map[string]interface{}{
		"syn_rate_per_second": float64(200),
		"max_packets_per_second": float64(20000),
	}
	store.SetParams(newParams)

	got := store.GetParams()
	if got["syn_rate_per_second"] != float64(200) {
		t.Errorf("syn_rate_per_second = %v, want 200", got["syn_rate_per_second"])
	}
}

func TestDataStoreLoadParamsFromJSON(t *testing.T) {
	store := NewDataStore()
	jsonData := []byte(`{
		"syn_rate_per_second": 150,
		"icmp_rate_per_second": 5
	}`)

	if err := store.LoadParamsFromJSON(jsonData); err != nil {
		t.Fatalf("LoadParamsFromJSON failed: %v", err)
	}

	params := store.GetParams()
	if params["syn_rate_per_second"] != float64(150) {
		t.Errorf("syn_rate_per_second = %v, want 150", params["syn_rate_per_second"])
	}
	if params["icmp_rate_per_second"] != float64(5) {
		t.Errorf("icmp_rate_per_second = %v, want 5", params["icmp_rate_per_second"])
	}
}

func TestDataStoreLoadParamsInvalidJSON(t *testing.T) {
	store := NewDataStore()
	err := store.LoadParamsFromJSON([]byte(`{invalid json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestEmbeddedEvaluator(t *testing.T) {
	policy := `package l3_firewall
import rego.v1
default allow := true
allow := false if { input.packet.dst_port == 22 }
reason := "blocked SSH" if { allow == false }
`
	store := NewDataStore()
	eval, err := NewEmbedded(EmbedConfig{
		Policy: policy,
		Store:  store,
	})
	if err != nil {
		t.Fatalf("NewEmbedded failed: %v", err)
	}

	// Block SSH (port 22)
	input := &Input{
		Packet: PacketInfo{
			SrcIP:    "10.0.1.100",
			DstIP:    "10.0.2.50",
			Protocol: "TCP",
			SrcPort:  44001,
			DstPort:  22,
			TCPFlags: TCPFlags{SYN: true},
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
			SrcIP:    "10.0.1.100",
			DstIP:    "10.0.2.50",
			Protocol: "TCP",
			SrcPort:  44002,
			DstPort:  80,
			TCPFlags: TCPFlags{SYN: true},
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

func TestEmbeddedEvaluatorWithParams(t *testing.T) {
	policy := `package l3_firewall
import rego.v1
default allow := true
blocked_port := object.get(data.params, "blocked_port", 0)
allow := false if { input.packet.dst_port == blocked_port }
`
	store := NewDataStore()
	store.SetParams(map[string]interface{}{
		"blocked_port": float64(8080),
	})

	eval, err := NewEmbedded(EmbedConfig{
		Policy: policy,
		Store:  store,
	})
	if err != nil {
		t.Fatalf("NewEmbedded failed: %v", err)
	}

	input := &Input{
		Packet: PacketInfo{
			SrcIP: "10.0.1.100", DstIP: "10.0.2.50",
			Protocol: "TCP", SrcPort: 44001, DstPort: 8080,
			TCPFlags: TCPFlags{SYN: true},
		},
	}
	result, err := eval.Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if result.Allowed {
		t.Error("port 8080 should be blocked via params")
	}
}

func TestEmbeddedEvaluatorSetParamsRuntime(t *testing.T) {
	policy := `package l3_firewall
import rego.v1
default allow := true
deny_if_high_rate if { input.rate.src_ip_pps > object.get(data.params, "max_pps", 100) }
allow := false if { deny_if_high_rate }
`
	store := NewDataStore()
	store.SetParams(map[string]interface{}{
		"max_pps": float64(50),
	})

	eval, err := NewEmbedded(EmbedConfig{
		Policy: policy,
		Store:  store,
	})
	if err != nil {
		t.Fatalf("NewEmbedded failed: %v", err)
	}

	// Should block at 100 pps (exceeds 50)
	input := &Input{
		Packet: PacketInfo{SrcIP: "10.0.1.100", DstIP: "10.0.2.50", Protocol: "TCP", DstPort: 80, TCPFlags: TCPFlags{SYN: true}},
		Rate:   RateInfo{SrcIPpps: 100},
	}
	result, err := eval.Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if result.Allowed {
		t.Error("should be blocked at 100 pps with max=50")
	}

	// Update params to allow higher rate
	eval.SetParams(map[string]interface{}{
		"max_pps": float64(200),
	})
	result2, err := eval.Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if !result2.Allowed {
		t.Error("should be allowed at 100 pps with max=200")
	}
}

func TestEmbeddedEvaluatorBadPolicy(t *testing.T) {
	_, err := NewEmbedded(EmbedConfig{
		Policy: "invalid rego {{",
		Store:  NewDataStore(),
	})
	if err == nil {
		t.Fatal("expected error for bad policy, got nil")
	}
}

func TestEmbeddedEvaluatorNilStore(t *testing.T) {
	_, err := NewEmbedded(EmbedConfig{
		Policy: `package test default allow := true`,
		Store:  nil,
	})
	if err == nil {
		t.Fatal("expected error for nil store, got nil")
	}
}
