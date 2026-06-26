// Package engine implements the firewall evaluation pipeline that ties together
// packet parsing, connection tracking, rate limiting, and OPA policy evaluation.
//
// Architecture per packet:
//   raw bytes → gopacket parse → conntrack lookup → rate track →
//   build OPA input → OPA eval → NF_ACCEPT or NF_DROP
package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/opa"
	"github.com/monch1962/l3-firewall/internal/packet"
	"github.com/monch1962/l3-firewall/internal/ratelimit"

	"github.com/florianl/go-nfqueue"
)

const maxRecentBlocks = 100

// BlockLogEntry records a single blocked packet for the admin API.
type BlockLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	SrcIP      string    `json:"src_ip"`
	DstIP      string    `json:"dst_ip"`
	Protocol   string    `json:"protocol"`
	SrcPort    uint16    `json:"src_port"`
	DstPort    uint16    `json:"dst_port"`
	Reason     string    `json:"reason"`
	PacketSize int       `json:"packet_size"`
}

// Engine is the core firewall evaluation pipeline.
type Engine struct {
	eval      opa.Evaluator
	conntrack *conntrack.Table
	ratelimit *ratelimit.Limiter
	auditOnly bool
	failClosed bool
	running   bool

	// Stats counters
	packetsProcessed int64
	packetsAllowed   int64
	packetsBlocked   int64

	// Recent blocks ring buffer
	recentMu    sync.RWMutex
	recentBlocks []BlockLogEntry

	// NFQUEUE lifecycle
	ctx    context.Context
	cancel context.CancelFunc
}

// New creates a firewall engine with the given components.
func New(eval opa.Evaluator, ct *conntrack.Table, rl *ratelimit.Limiter, failClosed, auditOnly bool) *Engine {
	return &Engine{
		eval:         eval,
		conntrack:    ct,
		ratelimit:    rl,
		failClosed:   failClosed,
		auditOnly:    auditOnly,
		recentBlocks: make([]BlockLogEntry, 0, maxRecentBlocks),
	}
}

// Stats holds current packet counters.
type Stats struct {
	PacketsProcessed int64
	PacketsAllowed   int64
	PacketsBlocked   int64
}

func (e *Engine) Stats() Stats {
	return Stats{
		PacketsProcessed: e.packetsProcessed,
		PacketsAllowed:   e.packetsAllowed,
		PacketsBlocked:   e.packetsBlocked,
	}
}

// Running returns whether the engine is actively running (NFQUEUE connected).
func (e *Engine) Running() bool {
	return e.running
}

// ConntrackStats returns the connection tracking stats.
func (e *Engine) ConntrackStats() conntrack.Stats {
	return e.conntrack.Stats()
}

// RecentBlocks returns a copy of the recent blocked packet log.
func (e *Engine) RecentBlocks() []BlockLogEntry {
	e.recentMu.RLock()
	defer e.recentMu.RUnlock()
	if len(e.recentBlocks) == 0 {
		return nil
	}
	result := make([]BlockLogEntry, len(e.recentBlocks))
	copy(result, e.recentBlocks)
	return result
}

// recordBlock appends a block log entry, keeping at most maxRecentBlocks.
func (e *Engine) recordBlock(pi *packet.PacketInfo, reason string) {
	e.recentMu.Lock()
	defer e.recentMu.Unlock()

	entry := BlockLogEntry{
		Timestamp:  time.Now(),
		SrcIP:      pi.SrcIP,
		DstIP:      pi.DstIP,
		Protocol:   pi.Protocol,
		SrcPort:    pi.SrcPort,
		DstPort:    pi.DstPort,
		Reason:     reason,
		PacketSize: pi.PacketSize,
	}
	if len(e.recentBlocks) >= maxRecentBlocks {
		e.recentBlocks = e.recentBlocks[1:]
	}
	e.recentBlocks = append(e.recentBlocks, entry)
}

// evaluatePacket runs the full firewall evaluation pipeline on a parsed packet.
// Returns the OPA result (Allowed + Reason).
func (e *Engine) evaluatePacket(pi *packet.PacketInfo, packetSize int) *opa.Result {
	e.packetsProcessed++

	// 1. Connection tracking with TCP state machine
	var flow *conntrack.Flow
	if pi.Protocol == "TCP" {
		flow = e.conntrack.UpdateTCPState(pi.SrcIP, pi.DstIP, pi.Protocol,
			pi.SrcPort, pi.DstPort,
			pi.TCPFlags.SYN, pi.TCPFlags.ACK, pi.TCPFlags.RST, pi.TCPFlags.FIN)
	} else {
		flow = e.conntrack.LookupOrCreate(pi.SrcIP, pi.DstIP, pi.Protocol, pi.SrcPort, pi.DstPort)
	}

	// Track destination port for scan detection
	if pi.Protocol == "TCP" || pi.Protocol == "UDP" {
		e.conntrack.RecordDestPort(pi.SrcIP, pi.DstPort)
	}

	// 2. Rate tracking
	pps, bps := e.ratelimit.Allow(pi.SrcIP, packetSize)

	// 3. Get recent ports for port scan detection
	recentPorts := e.conntrack.GetRecentDestPorts(pi.SrcIP)

	// 4. Build OPA input
	tcpState := ""
	if pi.Protocol == "TCP" {
		tcpState = flow.TCPState.String()
	}
	input := opa.BuildInput(pi, pps, bps, flow.Established, tcpState, recentPorts)

	// 5. OPA evaluation
	if e.eval == nil {
		if e.failClosed {
			e.packetsBlocked++
			reason := "evaluator unavailable — blocked for safety"
			slog.Warn("blocked", "reason", reason, "src", pi.SrcIP, "dst", pi.DstIP,
				"protocol", pi.Protocol, "port", pi.DstPort)
			e.recordBlock(pi, reason)
			return &opa.Result{Allowed: false, Reason: reason}
		}
		e.packetsAllowed++
		return &opa.Result{Allowed: true}
	}

	result, err := e.eval.Evaluate(input)
	if err != nil {
		if e.failClosed {
			e.packetsBlocked++
			reason := fmt.Sprintf("OPA error: %v — blocked for safety", err)
			slog.Warn("blocked", "reason", reason, "src", pi.SrcIP, "dst", pi.DstIP,
				"protocol", pi.Protocol, "port", pi.DstPort)
			e.recordBlock(pi, reason)
			return &opa.Result{Allowed: false, Reason: reason}
		}
		e.packetsAllowed++
		return &opa.Result{Allowed: true}
	}

	// 6. Audit-only mode overrides blocks (but still logs them)
	if !result.Allowed && e.auditOnly {
		slog.Warn("[AUDIT] would block", "reason", result.Reason, "src", pi.SrcIP,
			"dst", pi.DstIP, "protocol", pi.Protocol, "port", pi.DstPort)
		e.packetsAllowed++
		return &opa.Result{Allowed: true}
	}

	if result.Allowed {
		e.packetsAllowed++
	} else {
		e.packetsBlocked++
		slog.Warn("blocked", "reason", result.Reason, "src", pi.SrcIP, "dst", pi.DstIP,
			"protocol", pi.Protocol, "port", pi.DstPort)
		e.recordBlock(pi, result.Reason)
	}

	return result
}

// packetHandler is the NFQUEUE callback.
func (e *Engine) packetHandler(attr nfqueue.Attribute) int {
	if attr.Payload == nil || attr.PacketID == nil {
		return 0
	}

	pi, err := packet.ParsePacket(*attr.Payload)
	if err != nil {
		return 0
	}

	result := e.evaluatePacket(pi, len(*attr.Payload))
	if result.Allowed {
		return 0
	}
	return 1
}

// Run starts the NFQUEUE listener on the given queue number.
func (e *Engine) Run(queueNum uint16) error {
	ctx, cancel := context.WithCancel(context.Background())
	e.ctx = ctx
	e.cancel = cancel

	cfg := nfqueue.Config{
		NfQueue:      queueNum,
		MaxPacketLen: 65535,
		MaxQueueLen:  1024,
		Copymode:     nfqueue.NfQnlCopyPacket,
	}

	nf, err := nfqueue.Open(&cfg)
	if err != nil {
		cancel()
		return fmt.Errorf("opening NFQUEUE %d: %w", queueNum, err)
	}

	e.running = true

	if err := nf.Register(ctx, func(attr nfqueue.Attribute) int {
		return e.packetHandler(attr)
	}); err != nil {
		nf.Close()
		e.running = false
		cancel()
		return fmt.Errorf("registering NFQUEUE handler: %w", err)
	}

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				e.conntrack.Expire()
				e.ratelimit.Cleanup(5 * time.Minute)
			}
		}
	}()

	<-ctx.Done()
	nf.Close()
	e.running = false
	return nil
}

// Stop gracefully shuts down the NFQUEUE listener.
func (e *Engine) Stop() {
	if e.cancel != nil {
		e.cancel()
	}
}
