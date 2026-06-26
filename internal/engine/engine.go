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
	"log"
	"time"

	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/opa"
	"github.com/monch1962/l3-firewall/internal/packet"
	"github.com/monch1962/l3-firewall/internal/ratelimit"

	"github.com/florianl/go-nfqueue"
)

// Verdict constants returned from evaluatePacket.
const (
	VerdictAccept = iota
	VerdictDrop
)

// Engine is the core firewall evaluation pipeline.
type Engine struct {
	eval      opa.Evaluator
	conntrack *conntrack.Table
	ratelimit *ratelimit.Limiter
	auditOnly bool
	failClosed bool

	// Stats counters
	packetsProcessed int64
	packetsAllowed   int64
	packetsBlocked   int64

	// NFQUEUE lifecycle
	ctx    context.Context
	cancel context.CancelFunc
}

// New creates a firewall engine with the given components.
func New(eval opa.Evaluator, ct *conntrack.Table, rl *ratelimit.Limiter, failClosed, auditOnly bool) *Engine {
	return &Engine{
		eval:       eval,
		conntrack:  ct,
		ratelimit:  rl,
		failClosed: failClosed,
		auditOnly:  auditOnly,
	}
}

// Stats returns current packet counters.
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

// evaluatePacket runs the full firewall evaluation pipeline on a parsed packet.
// Returns the OPA result (Allowed + Reason).
// This function is safe to export for testing.
func (e *Engine) evaluatePacket(pi *packet.PacketInfo, packetSize int) *opa.Result {
	e.packetsProcessed++

	// 1. Connection tracking lookup
	srcIP, dstIP := pi.SrcIP, pi.DstIP
	flow := e.conntrack.LookupOrCreate(srcIP, dstIP, pi.Protocol, pi.SrcPort, pi.DstPort)

	// Track SYN-ACK as established
	if pi.Protocol == "TCP" && pi.TCPFlags.SYN && pi.TCPFlags.ACK {
		flow.SetEstablished()
	}

	// Track destination port for scan detection
	if pi.Protocol == "TCP" || pi.Protocol == "UDP" {
		e.conntrack.RecordDestPort(srcIP, pi.DstPort)
	}

	// 2. Rate tracking
	pps, bps := e.ratelimit.Allow(srcIP, packetSize)

	// 3. Get recent ports for port scan detection
	recentPorts := e.conntrack.GetRecentDestPorts(srcIP)

	// 4. Build OPA input
	input := opa.BuildInput(pi, pps, bps, flow.Established, recentPorts)

	// 5. OPA evaluation
	if e.eval == nil {
		if e.failClosed {
			e.packetsBlocked++
			return &opa.Result{Allowed: false, Reason: "evaluator unavailable — blocked for safety"}
		}
		e.packetsAllowed++
		return &opa.Result{Allowed: true}
	}

	result, err := e.eval.Evaluate(input)
	if err != nil {
		if e.failClosed {
			e.packetsBlocked++
			return &opa.Result{Allowed: false, Reason: fmt.Sprintf("OPA error: %v — blocked for safety", err)}
		}
		e.packetsAllowed++
		return &opa.Result{Allowed: true}
	}

	// 6. Audit-only mode overrides blocks
	if !result.Allowed && e.auditOnly {
		log.Printf("[AUDIT] would block: %s", result.Reason)
		e.packetsAllowed++
		return &opa.Result{Allowed: true}
	}

	if result.Allowed {
		e.packetsAllowed++
	} else {
		e.packetsBlocked++
	}

	return result
}

// packetHandler is the NFQUEUE callback. It processes a single raw packet.
func (e *Engine) packetHandler(attr nfqueue.Attribute) int {
	if attr.Payload == nil || attr.PacketID == nil {
		// Can't process — accept
		return 0
	}

	// Parse the raw packet
	pi, err := packet.ParsePacket(*attr.Payload)
	if err != nil {
		// Can't parse — accept and let upstream handle it
		return 0
	}

	result := e.evaluatePacket(pi, len(*attr.Payload))
	if result.Allowed {
		return 0 // NF_ACCEPT
	}
	return 1 // NF_DROP
}

// Run starts the NFQUEUE listener on the given queue number.
// Blocks until the context is cancelled. Returns an error if the
// NFQUEUE socket cannot be opened (e.g., missing CAP_NET_ADMIN).
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

	// Register the callback
	if err := nf.Register(ctx, func(attr nfqueue.Attribute) int {
		return e.packetHandler(attr)
	}); err != nil {
		nf.Close()
		cancel()
		return fmt.Errorf("registering NFQUEUE handler: %w", err)
	}

	// Periodic cleanup goroutines
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

	// Block until context cancelled
	<-ctx.Done()
	nf.Close()
	return nil
}

// Stop gracefully shuts down the NFQUEUE listener.
func (e *Engine) Stop() {
	if e.cancel != nil {
		e.cancel()
	}
}
