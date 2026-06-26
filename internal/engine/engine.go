// Package engine implements the firewall evaluation pipeline that ties together
// packet parsing, connection tracking, rate limiting, and OPA policy evaluation.
//
// Architecture per packet:
//   raw bytes → gopacket parse → conntrack lookup → rate track →
//   build OPA input → OPA eval → NF_ACCEPT or NF_DROP
package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/monch1962/l3-firewall/internal/audit"
	"github.com/monch1962/l3-firewall/internal/alert"
	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/opa"
	"github.com/monch1962/l3-firewall/internal/packet"
	"github.com/monch1962/l3-firewall/internal/ratelimit"

	"github.com/florianl/go-nfqueue"
)

const maxRecentBlocks = 100
const maxBlockStatsReasons = 256
const maxReasonLength = 1024

// traceIDLength is the number of random bytes used for a trace identifier.
const traceIDLength = 4

// newTraceID returns a short hex trace identifier for correlating log entries.
func newTraceID() string {
	b := make([]byte, traceIDLength)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// BlockLogEntry records a single blocked packet with metadata.
type BlockLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	SrcIP      string    `json:"src_ip"`
	DstIP      string    `json:"dst_ip"`
	Protocol   string    `json:"protocol"`
	SrcPort    uint16    `json:"src_port"`
	DstPort    uint16    `json:"dst_port"`
	Reason     string    `json:"reason"`
	PacketSize int       `json:"packet_size"`
	TraceID    string    `json:"trace_id"`
}

// Engine is the core firewall evaluation pipeline.
type Engine struct {
	eval        opa.Evaluator
	conntrack   *conntrack.Table
	ratelimit   *ratelimit.Limiter
	auditOnly   bool
	failClosed  bool
	running     bool
	auditLogger *audit.Logger // nil = no audit logging
	alertRouter *alert.Router // nil = no alerts

	// Stats counters
	packetsProcessed int64
	packetsAllowed   int64
	packetsBlocked   int64

	// Per-reason block counters for aggregation
	blockStatsMu sync.RWMutex
	blockStats   map[string]int64

	// Recent blocks ring buffer
	recentMu    sync.RWMutex
	recentBlocks []BlockLogEntry

	// NFQUEUE lifecycle
	ctx    context.Context
	cancel context.CancelFunc
}

// New creates a firewall engine with the given components.
// Pass nil for auditLogger or alertRouter to disable those features.
func New(eval opa.Evaluator, ct *conntrack.Table, rl *ratelimit.Limiter, failClosed, auditOnly bool, al *audit.Logger, ar *alert.Router) *Engine {
	return &Engine{
		eval:         eval,
		conntrack:    ct,
		ratelimit:    rl,
		failClosed:   failClosed,
		auditOnly:    auditOnly,
		auditLogger:  al,
		alertRouter:  ar,
		recentBlocks: make([]BlockLogEntry, 0, maxRecentBlocks),
		blockStats:   make(map[string]int64),
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

// BlockStats returns a copy of the per-reason block counters.
func (e *Engine) BlockStats() map[string]int64 {
	e.blockStatsMu.RLock()
	defer e.blockStatsMu.RUnlock()
	result := make(map[string]int64, len(e.blockStats))
	for k, v := range e.blockStats {
		result[k] = v
	}
	return result
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

// recordBlock appends a block log entry and increments the per-reason counter.
// Long reason strings are truncated to maxReasonLength to prevent memory bloat.
func (e *Engine) recordBlock(pi *packet.PacketInfo, reason, traceID string) {
	e.recentMu.Lock()
	defer e.recentMu.Unlock()

	// Truncate long reason strings
	if len(reason) > maxReasonLength {
		reason = reason[:maxReasonLength]
	}

	entry := BlockLogEntry{
		Timestamp:  time.Now(),
		SrcIP:      pi.SrcIP,
		DstIP:      pi.DstIP,
		Protocol:   pi.Protocol,
		SrcPort:    pi.SrcPort,
		DstPort:    pi.DstPort,
		Reason:     reason,
		PacketSize: pi.PacketSize,
		TraceID:    traceID,
	}
	if len(e.recentBlocks) >= maxRecentBlocks {
		e.recentBlocks = e.recentBlocks[1:]
	}
	e.recentBlocks = append(e.recentBlocks, entry)

	// Per-reason counter (capped to prevent memory exhaustion)
	e.blockStatsMu.Lock()
	if len(e.blockStats) < maxBlockStatsReasons {
		e.blockStats[reason]++
	}
	e.blockStatsMu.Unlock()
}

// logAudit writes a structured audit event if the audit logger is configured.
func (e *Engine) logAudit(eventType, traceID string, pi *packet.PacketInfo, reason string) {
	if e.auditLogger == nil {
		return
	}
	e.auditLogger.Log(audit.AuditEvent{
		Timestamp:  time.Now(),
		Type:       eventType,
		TraceID:    traceID,
		SrcIP:      pi.SrcIP,
		DstIP:      pi.DstIP,
		Protocol:   pi.Protocol,
		SrcPort:    pi.SrcPort,
		DstPort:    pi.DstPort,
		PacketSize: pi.PacketSize,
		Reason:     reason,
	})
}

// fireAlert dispatches an alert via the alert router if configured.
func (e *Engine) fireAlert(alertType alert.AlertType, message string) {
	if e.alertRouter != nil {
		e.alertRouter.Send(alert.AlertEvent{
			Type:      alertType,
			Message:   message,
			Source:    "engine",
			Timestamp: time.Now(),
		})
	}
}

// evaluatePacket runs the full firewall evaluation pipeline on a parsed packet.
// Returns the OPA result (Allowed + Reason). Panics are recovered and
// returned as blocked results (fail-closed).
func (e *Engine) evaluatePacket(pi *packet.PacketInfo, packetSize int) (result *opa.Result) {
	defer func() {
		if rec := recover(); rec != nil {
			e.packetsProcessed++
			e.packetsBlocked++
			result = &opa.Result{
				Allowed: false,
				Reason:  fmt.Sprintf("internal error: %v", rec),
			}
			slog.Error("panic in evaluatePacket", "panic", fmt.Sprintf("%v", rec))
		}
	}()

	e.packetsProcessed++

	// Generate a trace ID for correlating log entries across the pipeline
	tid := newTraceID()

	// 1. Connection tracking with TCP state machine
	var flow *conntrack.Flow
	var flowLimited bool
	if pi.Protocol == "TCP" {
		flow = e.conntrack.UpdateTCPState(pi.SrcIP, pi.DstIP, pi.Protocol,
			pi.SrcPort, pi.DstPort,
			pi.TCPFlags.SYN, pi.TCPFlags.ACK, pi.TCPFlags.RST, pi.TCPFlags.FIN)
		if flow == nil {
			flowLimited = true
		}
	} else {
		flow = e.conntrack.LookupOrCreate(pi.SrcIP, pi.DstIP, pi.Protocol, pi.SrcPort, pi.DstPort)
		if flow == nil {
			flowLimited = true
		}
	}

	// Connection limit exceeded — block immediately
	if flowLimited {
		e.packetsBlocked++
		reason := "connection limit exceeded for source IP"
		slog.Warn("blocked", "reason", reason, "src", pi.SrcIP, "dst", pi.DstIP,
			"protocol", pi.Protocol, "port", pi.DstPort, "trace_id", tid)
		e.recordBlock(pi, reason, tid)
		e.logAudit("packet_block", tid, pi, reason)
		e.fireAlert(alert.AlertConnLimit, reason+" src="+pi.SrcIP)
		return &opa.Result{Allowed: false, Reason: reason}
	}

	// Track destination port for scan detection
	if pi.Protocol == "TCP" || pi.Protocol == "UDP" {
		e.conntrack.RecordDestPort(pi.SrcIP, pi.DstPort)
	}

	// 2. Rate tracking — per-IP and per-destination-port
	pps, bps := e.ratelimit.Allow(pi.SrcIP, packetSize)
	portPPS, portBPS := e.ratelimit.AllowPort(pi.SrcIP, pi.DstPort, packetSize)
	newConnRate := e.conntrack.NewConnectionRate()

	// 3. Get recent ports for port scan detection
	recentPorts := e.conntrack.GetRecentDestPorts(pi.SrcIP)

	// 4. Build OPA input
	tcpState := ""
	if pi.Protocol == "TCP" {
		tcpState = flow.TCPState.String()
	}
	input := opa.BuildInput(pi, pps, bps, flow.Established, tcpState,
		portPPS, portBPS, newConnRate, recentPorts)

	// 5. OPA evaluation
	if e.eval == nil {
		if e.failClosed {
			e.packetsBlocked++
			reason := "evaluator unavailable — blocked for safety"
			slog.Warn("blocked", "reason", reason, "src", pi.SrcIP, "dst", pi.DstIP,
				"protocol", pi.Protocol, "port", pi.DstPort, "trace_id", tid)
			e.recordBlock(pi, reason, tid)
			e.logAudit("packet_block", tid, pi, reason)
			return &opa.Result{Allowed: false, Reason: reason}
		}
		e.packetsAllowed++
		e.logAudit("packet_allow", tid, pi, "")
		return &opa.Result{Allowed: true}
	}

	result, err := e.eval.Evaluate(input)
	if err != nil {
		if e.failClosed {
			e.packetsBlocked++
			reason := fmt.Sprintf("OPA error: %v — blocked for safety", err)
			slog.Warn("blocked", "reason", reason, "src", pi.SrcIP, "dst", pi.DstIP,
				"protocol", pi.Protocol, "port", pi.DstPort, "trace_id", tid)
			e.recordBlock(pi, reason, tid)
			e.logAudit("packet_block", tid, pi, reason)
			e.fireAlert(alert.AlertOPAError, reason)
			return &opa.Result{Allowed: false, Reason: reason}
		}
		e.packetsAllowed++
		e.logAudit("packet_allow", tid, pi, "")
		return &opa.Result{Allowed: true}
	}

	// 6. Audit-only mode overrides blocks (but still logs them)
	if !result.Allowed && e.auditOnly {
		slog.Warn("[AUDIT] would block", "reason", result.Reason, "src", pi.SrcIP,
			"dst", pi.DstIP, "protocol", pi.Protocol, "port", pi.DstPort)
		e.packetsAllowed++
		e.logAudit("audit_block", tid, pi, result.Reason)
		return &opa.Result{Allowed: true}
	}

	if result.Allowed {
		e.packetsAllowed++
		e.logAudit("packet_allow", tid, pi, "")
	} else {
		e.packetsBlocked++
		// Truncate long reason strings
		if len(result.Reason) > maxReasonLength {
			result.Reason = result.Reason[:maxReasonLength]
		}
		slog.Warn("blocked", "reason", result.Reason, "src", pi.SrcIP, "dst", pi.DstIP,
			"protocol", pi.Protocol, "port", pi.DstPort, "trace_id", tid)
		e.recordBlock(pi, result.Reason, tid)
		e.logAudit("packet_block", tid, pi, result.Reason)
	}

	return result
}

// packetHandler is the NFQUEUE callback with panic recovery.
func (e *Engine) packetHandler(attr nfqueue.Attribute) int {
	defer func() {
		if rec := recover(); rec != nil {
			e.packetsProcessed++
			e.packetsAllowed++
			slog.Error("panic recovered in packet handler",
				"panic", fmt.Sprintf("%v", rec))
		}
	}()

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
