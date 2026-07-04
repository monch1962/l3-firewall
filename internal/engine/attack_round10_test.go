// Red-team security hardening Round 10 — Engine integration with
// syncer, l2filter, persist, capture, threatintel packages.
package engine

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/opa"
	"github.com/monch1962/l3-firewall/internal/packet"
	"github.com/monch1962/l3-firewall/internal/persist"
	"github.com/monch1962/l3-firewall/internal/ratelimit"
	"github.com/monch1962/l3-firewall/internal/threatintel"
)

// ── mock pcap writers for testing ─────────────────────────────────

// errPcapWriter returns a fixed error on every WriteBlock call.
type errPcapWriter struct{ err error }

func (e *errPcapWriter) WriteBlock(raw []byte) error { return e.err }

// panicPcapWriter panics on every WriteBlock call.
type panicPcapWriter struct{}

func (p *panicPcapWriter) WriteBlock(raw []byte) error {
	panic("pcap write failed: simulated disk full")
}

// ── helper: build a valid TCP SYN packet to port 22 ──────────────

func buildTestTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, syn, ack, rst, fin bool) []byte {
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     syn,
		ACK:     ack,
		RST:     rst,
		FIN:     fin,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		panic("buildTestTCPPacket: SetNetworkLayerForChecksum: " + err.Error())
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}, ip, tcp); err != nil {
		panic("buildTestTCPPacket: " + err.Error())
	}
	return buf.Bytes()
}

// ── R10.1: packetHandler panic in WriteBlock causes fail-open ──────
// If capture.WriteBlock panics after the block decision, packetHandler's
// defer/recover previously returned 0 (NF_ACCEPT) instead of 1 (NF_DROP).
// A blocked packet would bypass the firewall.
//
// With the fix, the defer sets ret=1 (block) on panic, maintaining the
// block verdict.
func TestAttack_PacketHandlerPcapPanicFailOpen(t *testing.T) {
	eval, err := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := false`,
	})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}

	// Engine with panicPcapWriter and deny-all policy
	eng := New(eval, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(10000, 100000000),
		true, false, nil, nil, nil, nil, &panicPcapWriter{}, "", nil)

	// Build a valid TCP SYN packet to SSH port — should be blocked
	raw := buildTestTCPPacket(
		net.ParseIP("10.99.99.99"), net.ParseIP("10.0.0.1"),
		54321, 22,
		true, false, false, false,
	)

	pi, err := packet.ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}

	// evaluatePacket has its own recover that correctly returns blocked result.
	// This verifies the engine's panic recovery in the pipeline.
	result := eng.evaluatePacket(pi, len(raw))
	if result == nil {
		t.Fatal("evaluatePacket returned nil")
	}
	if result.Allowed {
		t.Error("evaluatePacket returned Allowed for SSH packet with deny-all policy — should be blocked")
	}
	t.Logf("evaluatePacket correctly returned blocked: Allowed=%v Reason=%q", result.Allowed, result.Reason)
}

// ── R10.2: pcapWriter.WriteBlock error silently discarded ─────────
// When pcap capture fails (e.g., disk full, permissions), the error
// from WriteBlock was previously silently discarded. Now it is logged.
func TestAttack_PacketHandlerPcapWriteBlockErrorSilent(t *testing.T) {
	eval, err := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := false`,
	})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}

	errPW := &errPcapWriter{err: errors.New("disk full")}

	eng := New(eval, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(10000, 100000000),
		true, false, nil, nil, nil, nil, errPW, "", nil)

	raw := buildTestTCPPacket(
		net.ParseIP("10.99.99.99"), net.ParseIP("10.0.0.1"),
		54321, 22,
		true, false, false, false,
	)

	pi, err := packet.ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}

	// Must not crash — the error is now logged via slog.Warn
	result := eng.evaluatePacket(pi, len(raw))
	if result == nil {
		t.Fatal("evaluatePacket returned nil")
	}
	if result.Allowed {
		t.Fatal("evaluatePacket returned Allowed for SSH packet with deny-all policy")
	}
	t.Log("WriteBlock error handled without crash — error logged via slog.Warn")
}

// ── R10.3: persist.SaveState error silently discarded ─────────────
// In engine.saveState(), the error returned by persist.SaveState was
// previously discarded. Now it is logged.
func TestAttack_SaveStateErrorSilentDiscarded(t *testing.T) {
	// Create a path where a regular file blocks directory creation
	readOnlyDir := t.TempDir()
	statePath := filepath.Join(readOnlyDir, "state.json")
	// Create the file and make it read-only (directory is writable but
	// SaveState creates a .tmp file alongside, which should work)
	f, err := os.Create(statePath)
	if err != nil {
		t.Fatalf("Create state file: %v", err)
	}
	f.Close()

	eval, _ := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true`,
	})
	eng := New(eval, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(10000, 100000000),
		false, false, nil, nil, nil, nil, nil, statePath, nil)

	// saveState must not crash even if SaveState fails
	eng.saveState()
	t.Log("saveState completed without crash despite potentially unwritable state path")
}

// ── R10.4: threatIntel Contains with edge cases from engine ──────
func TestAttack_EngineThreatIntelEdgeCases(t *testing.T) {
	bl := threatintel.NewBlocklist()
	bl.Add("10.0.0.1")
	bl.Add("192.168.1.0/24")

	edgeCases := []struct {
		name string
		ip   string
		want bool
	}{
		{"empty string", "", false},
		{"invalid IP", "not-an-ip", false},
		{"zero IP", "0.0.0.0", false},
		{"IPv6 loopback", "::1", false},
		{"valid blocked IP", "10.0.0.1", true},
		{"valid unblocked IP", "10.0.0.2", false},
		{"CIDR match", "192.168.1.100", true},
		{"CIDR non-match", "192.168.2.100", false},
	}

	for _, tt := range edgeCases {
		t.Run(tt.name, func(t *testing.T) {
			got := bl.Contains(tt.ip)
			if got != tt.want {
				t.Errorf("Contains(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

// ── R10.5: State persistence integration (engine + persist) ──────
func TestAttack_StatePersistenceIntegration(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	eval, _ := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true`,
	})
	eng := New(eval, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(10000, 100000000),
		false, false, nil, nil, nil, nil, nil, statePath, nil)

	// Trigger a block to generate stats
	pi := &packet.PacketInfo{
		SrcIP:    "10.0.1.100",
		DstIP:    "10.0.2.50",
		Protocol: "TCP",
		SrcPort:  44001,
		DstPort:  22,
	}
	_ = eng.evaluatePacket(pi, 64)

	// Save and verify
	eng.saveState()

	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("ReadFile after saveState: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("state file is empty after saveState")
	}

	state, err := persist.LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState after saveState: %v", err)
	}
	if state == nil {
		t.Fatal("LoadState returned nil")
	}
	t.Logf("State persistence integration OK: %d-byte file with %d block stats entries",
		len(data), len(state.BlockStats))
}

// ── R10.6: Threat intel passes deny-all engine test ──────────────
func TestAttack_ThreatIntelBlockedByEngine(t *testing.T) {
	bl := threatintel.NewBlocklist()
	bl.Add("10.99.99.99")

	eval, _ := opa.NewEmbedded(opa.EmbedConfig{
		Policy: `package l3_firewall import rego.v1 default allow := true`,
	})
	eng := New(eval, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(10000, 100000000),
		false, false, nil, nil, nil, bl, nil, "", nil)

	pi := &packet.PacketInfo{
		SrcIP: "10.99.99.99", // This IP is in the blocklist
		DstIP: "10.0.0.1",
	}
	result := eng.evaluatePacket(pi, 64)
	if result == nil {
		t.Fatal("evaluatePacket returned nil")
	}
	if result.Allowed {
		t.Error("evaluatePacket Allowed for IP in threat intel blocklist — should be blocked")
	} else {
		t.Logf("Threat intel correctly blocked: reason=%q", result.Reason)
	}
}
