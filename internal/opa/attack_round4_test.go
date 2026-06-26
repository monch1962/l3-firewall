package opa

import (
	"testing"

	"github.com/monch1962/l3-firewall/internal/packet"
)

func TestAttack_PolicyLoadAndReload(t *testing.T) {
	policy := `package l3_firewall import rego.v1 default allow := true blocked_ports := {22} allow := false if { input.packet.dst_port == 22 }`
	eval, err := NewEmbedded(EmbedConfig{Policy: policy})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}

	input := &Input{
		Packet: PacketInfo{SrcIP: "10.0.1.100", DstIP: "10.0.2.50", Protocol: "TCP", DstPort: 22, TCPFlags: packet.TCPFlags{SYN: true}},
	}
	result, err := eval.Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.Allowed {
		t.Error("expected block for port 22")
	}
}

func TestAttack_PolicyManyConfigConstants(t *testing.T) {
	p := `package l3_firewall import rego.v1 default allow := true `
	for i := 0; i < 100; i++ {
		p += `c` + itoa(i) + ` := ` + itoa(i) + ` `
	}
	p += ` allow := false if { input.packet.dst_port == 22 }`

	eval, err := NewEmbedded(EmbedConfig{Policy: p})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	input := &Input{
		Packet: PacketInfo{SrcIP: "10.0.1.100", DstIP: "10.0.2.50", Protocol: "TCP", DstPort: 22, TCPFlags: packet.TCPFlags{SYN: true}},
	}
	result, err := eval.Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.Allowed {
		t.Error("expected block for port 22")
	}
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
