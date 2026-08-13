// Package engine implements the firewall evaluation pipeline that ties together
// packet parsing, connection tracking, rate limiting, and OPA policy evaluation.
//
// Architecture per packet:
//
//	raw bytes → gopacket parse → conntrack lookup → rate track →
//	build OPA input → OPA eval → NF_ACCEPT or NF_DROP
package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/monch1962/l3-firewall/internal/alert"
	"github.com/monch1962/l3-firewall/internal/audit"
	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/geoip"
	"github.com/monch1962/l3-firewall/internal/l2filter"
	"github.com/monch1962/l3-firewall/internal/opa"
	"github.com/monch1962/l3-firewall/internal/packet"
	"github.com/monch1962/l3-firewall/internal/persist"
	"github.com/monch1962/l3-firewall/internal/ratelimit"
	"github.com/monch1962/l3-firewall/internal/threatintel"

	"github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"
)

// PcapWriter is the interface for writing blocked packets to pcap files.
// Using an interface allows tests to mock capture failures and panics.
// production.NewWriter returns a *capture.Writer which implements this.
type PcapWriter interface {
	WriteBlock(raw []byte) error
}

const maxRecentBlocks = 100
const maxBlockStatsReasons = 256
const maxReasonLength = 1024

// traceIDLength is the number of random bytes used for a trace identifier.
const traceIDLength = 4

// newTraceID returns a short hex trace identifier for correlating log entries.
func newTraceID() string {
	b := make([]byte, traceIDLength)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read cannot fail on supported platforms (it only
		// returns an error for interface compatibility); treat failure
		// as fatal since trace IDs are required for log correlation.
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
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
	auditLogger *audit.Logger          // nil = no audit logging
	alertRouter *alert.Router          // nil = no alerts
	geoipReader *geoip.Reader          // nil = no GeoIP lookups
	threatIntel *threatintel.Blocklist // nil = no threat intel blocking
	pcapWriter  PcapWriter             // nil = no pcap capture
	statePath   string                 // path for persisting state (empty = no persistence)
	l2Filter    *l2filter.Filter       // nil = no L2 filtering

	// Stats counters. Atomics: incremented on the go-nfqueue callback
	// goroutine (NFQUEUE hot path) and read on the admin API HTTP
	// goroutine (Stats/Running) — plain fields would be a data race
	// (R50, R46 policyVersions class: unauthenticated admin API makes
	// it remotely triggerable).
	packetsProcessed atomic.Int64
	packetsAllowed   atomic.Int64
	packetsBlocked   atomic.Int64

	// Per-reason block counters for aggregation
	blockStatsMu sync.RWMutex
	blockStats   map[string]int64

	// Recent blocks ring buffer
	recentMu     sync.RWMutex
	recentBlocks []BlockLogEntry

	// NFQUEUE lifecycle
	lifecycleMu sync.RWMutex // guards ctx/cancel (Run vs Stop, R50)
	ctx         context.Context
	cancel      context.CancelFunc
	running     atomic.Bool
}

// New creates a firewall engine with the given components.
// Pass nil for auditLogger or alertRouter to disable those features.
func New(eval opa.Evaluator, ct *conntrack.Table, rl *ratelimit.Limiter, failClosed, auditOnly bool, al *audit.Logger, ar *alert.Router, gr *geoip.Reader, ti *threatintel.Blocklist, pw PcapWriter, stateFile string, l2 *l2filter.Filter) *Engine {
	return &Engine{
		eval:         eval,
		conntrack:    ct,
		ratelimit:    rl,
		failClosed:   failClosed,
		auditOnly:    auditOnly,
		auditLogger:  al,
		alertRouter:  ar,
		geoipReader:  gr,
		threatIntel:  ti,
		pcapWriter:   pw,
		statePath:    stateFile,
		l2Filter:     l2,
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
		PacketsProcessed: e.packetsProcessed.Load(),
		PacketsAllowed:   e.packetsAllowed.Load(),
		PacketsBlocked:   e.packetsBlocked.Load(),
	}
}

// Running returns whether the engine is actively running (NFQUEUE connected).
func (e *Engine) Running() bool {
	return e.running.Load()
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
	if err := e.auditLogger.Log(audit.AuditEvent{
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
	}); err != nil {
		slog.Warn("audit log write failed", "error", err)
	}
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
			e.packetsProcessed.Add(1)
			e.packetsBlocked.Add(1)
			result = &opa.Result{
				Allowed: false,
				Reason:  fmt.Sprintf("internal error: %v", rec),
			}
			slog.Error("panic in evaluatePacket", "panic", fmt.Sprintf("%v", rec))
		}
	}()

	e.packetsProcessed.Add(1)

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
		e.packetsBlocked.Add(1)
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

	// 3. L2 filtering — MAC address check
	if e.l2Filter != nil {
		if ok, reason := e.l2Filter.MACAllowed(pi.SrcMAC); !ok {
			e.packetsBlocked.Add(1)
			slog.Warn("blocked", "reason", reason, "src", pi.SrcIP, "mac", pi.SrcMAC,
				"protocol", pi.Protocol, "trace_id", tid)
			e.recordBlock(pi, reason, tid)
			e.logAudit("packet_block", tid, pi, reason)
			return &opa.Result{Allowed: false, Reason: reason}
		}
	}

	// 4. Rate tracking — per-IP and per-destination-port
	pps, bps := e.ratelimit.Allow(pi.SrcIP, packetSize)
	portPPS, portBPS := e.ratelimit.AllowPort(pi.SrcIP, pi.DstPort, packetSize)

	// 4a. Enforce the configured per-IP rate limits (--rate-limit-pps/-bps).
	// The flags previously only populated Limiter fields that nothing ever
	// read — the operator's limit was silently ignored and only OPA's
	// hardcoded policy threshold applied (R40.4). Mirror the connection-limit
	// block: hard deny regardless of audit-only mode.
	if e.ratelimit.ExceedsLimit(pps, bps) {
		e.packetsBlocked.Add(1)
		reason := fmt.Sprintf("per-IP rate limit exceeded: %.0f pps / %.0f bps", pps, bps)
		slog.Warn("blocked", "reason", reason, "src", pi.SrcIP, "dst", pi.DstIP,
			"protocol", pi.Protocol, "port", pi.DstPort, "trace_id", tid)
		e.recordBlock(pi, reason, tid)
		e.logAudit("packet_block", tid, pi, reason)
		return &opa.Result{Allowed: false, Reason: reason}
	}

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

	// 5. Threat intel check (if blocklist is configured)
	if e.threatIntel != nil && e.threatIntel.Contains(pi.SrcIP) {
		e.packetsBlocked.Add(1)
		reason := "source IP in threat intelligence blocklist"
		slog.Warn("blocked", "reason", reason, "src", pi.SrcIP, "dst", pi.DstIP,
			"protocol", pi.Protocol, "port", pi.DstPort, "trace_id", tid)
		e.recordBlock(pi, reason, tid)
		e.logAudit("packet_block", tid, pi, reason)
		return &opa.Result{Allowed: false, Reason: reason}
	}

	// 6. GeoIP lookup (if GeoIP database is configured)
	if e.geoipReader != nil {
		input.Geo = opa.GeoInfo{
			SrcCountry: e.geoipReader.LookupCountry(pi.SrcIP),
			DstCountry: e.geoipReader.LookupCountry(pi.DstIP),
		}
	}

	// 6. OPA evaluation
	if e.eval == nil {
		if e.failClosed {
			e.packetsBlocked.Add(1)
			reason := "evaluator unavailable — blocked for safety"
			slog.Warn("blocked", "reason", reason, "src", pi.SrcIP, "dst", pi.DstIP,
				"protocol", pi.Protocol, "port", pi.DstPort, "trace_id", tid)
			e.recordBlock(pi, reason, tid)
			e.logAudit("packet_block", tid, pi, reason)
			return &opa.Result{Allowed: false, Reason: reason}
		}
		e.packetsAllowed.Add(1)
		e.logAudit("packet_allow", tid, pi, "")
		return &opa.Result{Allowed: true}
	}

	result, err := e.eval.Evaluate(input)
	if err != nil {
		if e.failClosed {
			e.packetsBlocked.Add(1)
			reason := fmt.Sprintf("OPA error: %v — blocked for safety", err)
			slog.Warn("blocked", "reason", reason, "src", pi.SrcIP, "dst", pi.DstIP,
				"protocol", pi.Protocol, "port", pi.DstPort, "trace_id", tid)
			e.recordBlock(pi, reason, tid)
			e.logAudit("packet_block", tid, pi, reason)
			e.fireAlert(alert.AlertOPAError, reason)
			return &opa.Result{Allowed: false, Reason: reason}
		}
		e.packetsAllowed.Add(1)
		e.logAudit("packet_allow", tid, pi, "")
		return &opa.Result{Allowed: true}
	}

	// 6. Audit-only mode overrides blocks (but still logs them)
	if !result.Allowed && e.auditOnly {
		slog.Warn("[AUDIT] would block", "reason", result.Reason, "src", pi.SrcIP,
			"dst", pi.DstIP, "protocol", pi.Protocol, "port", pi.DstPort)
		e.packetsAllowed.Add(1)
		e.logAudit("audit_block", tid, pi, result.Reason)
		return &opa.Result{Allowed: true}
	}

	if result.Allowed {
		e.packetsAllowed.Add(1)
		e.logAudit("packet_allow", tid, pi, "")
	} else {
		e.packetsBlocked.Add(1)
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
// Uses named return so that a panic in post-decision cleanup (e.g.,
// pcap WriteBlock) still returns 1 (NF_DROP / block) instead of
// the zero value 0 (NF_ACCEPT / allow), preventing fail-open bypass.
func (e *Engine) packetHandler(attr nfqueue.Attribute) (ret int) {
	defer func() {
		if rec := recover(); rec != nil {
			e.packetsProcessed.Add(1)
			e.packetsAllowed.Add(1)
			slog.Error("panic recovered in packet handler",
				"panic", fmt.Sprintf("%v", rec))
			ret = 1 // fail-closed: blocked packets stay blocked on panic
		}
	}()

	if attr.Payload == nil {
		// A packet with no payload is the most uninspectable case of all —
		// it cannot be policy-checked, so it must be dropped like any other
		// unparseable packet. R40 made parse errors fail-closed (ret=1) but
		// left this nil-payload branch returning 0 (NF_ACCEPT): an
		// uninspectable packet silently passed every policy layer (R49 —
		// nil-payload fail-open sibling).
		e.packetsProcessed.Add(1)
		e.packetsBlocked.Add(1)
		slog.Warn("packet with nil payload dropped (fail-closed): nothing to inspect")
		return 1
	}

	pi, err := packet.ParsePacket(*attr.Payload)
	if err != nil {
		// Fail-closed: an unparseable packet cannot be policy-checked, so it
		// must be dropped, not passed. Round 10 made panics in this path
		// fail-closed (ret=1) but parse errors still returned 0 (NF_ACCEPT),
		// silently bypassing every policy layer for malformed/truncated
		// packets (R40.3).
		e.packetsProcessed.Add(1)
		e.packetsBlocked.Add(1)
		slog.Warn("unparseable packet dropped (fail-closed)", "error", err)
		return 1
	}

	result := e.evaluatePacket(pi, len(*attr.Payload))
	if result.Allowed {
		return 0
	}
	// Capture blocked packet to pcap if enabled
	if e.pcapWriter != nil {
		if err := e.pcapWriter.WriteBlock(*attr.Payload); err != nil {
			slog.Warn("pcap write failed", "error", err)
		}
	}
	return 1
}

// verdictSender is the minimal kernel-verdict surface the queue hook
// needs. *nfqueue.Nfqueue satisfies it implicitly; tests inject a fake
// recording what the firewall actually delivers (R49).
type verdictSender interface {
	SetVerdict(id uint32, verdict int) error
}

// handleQueuePacket is the go-nfqueue hook body, extracted from Run()
// so the verdict-delivery contract is testable (R49).
//
// go-nfqueue v1.3.2 contract (verified in the library's own integration
// tests and ExampleNfqueue_RegisterWithErrorFunc): the hook MUST call
// nf.SetVerdict(*attr.PacketID, verdict) itself — the hook's return value
// is RECEIVE-LOOP CONTROL, not a verdict (`if ret := fn(m); ret != 0 {
// return }` stops the socketCallback loop). Before R49 the hook returned
// the 0/1 decision without ever sending a verdict: the kernel was never
// told to accept/drop anything (queue saturated → all traffic dropped),
// and the first blocked packet (ret=1) killed the receive loop. R49 fixes
// both: every decision is delivered via SetVerdict, and the loop only
// stops when a verdict genuinely cannot be delivered.
func (e *Engine) handleQueuePacket(nf verdictSender, attr nfqueue.Attribute) int {
	if attr.PacketID == nil {
		// A verdict cannot be delivered without the packet ID. Stop the
		// receive loop (library contract: non-zero stops).
		slog.Error("nfqueue: attribute missing PacketID — cannot deliver verdict")
		return 1
	}

	decision := e.packetHandler(attr)

	verdict := nfqueue.NfAccept
	if decision != 0 {
		verdict = nfqueue.NfDrop
	}
	if err := nf.SetVerdict(*attr.PacketID, verdict); err != nil {
		slog.Warn("nfqueue: failed to send verdict", "packet_id", *attr.PacketID, "verdict", verdict, "error", err)
		return 1
	}
	return 0 // keep the receive loop alive
}

// saveState persists the engine's block stats to a JSON file.
func (e *Engine) saveState() {
	if e.statePath == "" {
		return
	}
	e.blockStatsMu.RLock()
	stats := make(map[string]int64, len(e.blockStats))
	for k, v := range e.blockStats {
		stats[k] = v
	}
	e.blockStatsMu.RUnlock()
	if err := persist.SaveState(e.statePath, &persist.EngineState{BlockStats: stats}); err != nil {
		slog.Warn("failed to persist state", "path", e.statePath, "error", err)
	}
}

// restoreState loads previously persisted state into the engine.
func (e *Engine) restoreState() {
	if e.statePath == "" {
		return
	}
	state, err := persist.LoadState(e.statePath)
	if err != nil {
		slog.Warn("failed to load persisted state", "path", e.statePath, "error", err)
		return
	}
	if state == nil || len(state.BlockStats) == 0 {
		return
	}
	e.blockStatsMu.Lock()
	for k, v := range state.BlockStats {
		if len(e.blockStats) < maxBlockStatsReasons {
			e.blockStats[k] = v
		}
	}
	e.blockStatsMu.Unlock()
	slog.Info("restored block stats from state file", "count", len(state.BlockStats))
}

// setLifecycle records the run context/cancel func so Stop() can
// cancel the NFQUEUE loop. Guarded by lifecycleMu: Run() assigns on
// the main goroutine while the signal-handler goroutine may call
// Stop() concurrently — a plain field would race (R50).
func (e *Engine) setLifecycle(ctx context.Context, cancel context.CancelFunc) {
	e.lifecycleMu.Lock()
	e.ctx = ctx
	e.cancel = cancel
	e.lifecycleMu.Unlock()
}

// Run starts the NFQUEUE listener on the given queue number.
func (e *Engine) Run(queueNum uint16) error {
	// Restore state from previous run
	e.restoreState()

	ctx, cancel := context.WithCancel(context.Background())
	e.setLifecycle(ctx, cancel)

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

	e.running.Store(true)

	if err := nf.RegisterWithErrorFunc(ctx, func(attr nfqueue.Attribute) int {
		// The hook return value is receive-loop control, NOT the verdict
		// (go-nfqueue v1.3.2): handleQueuePacket delivers the decision to
		// the kernel via SetVerdict and returns 0 to keep the loop alive
		// (R49 — before the fix the kernel was never verdicted and the
		// first blocked packet terminated the receive loop).
		return e.handleQueuePacket(nf, attr)
	}, func(err error) int {
		// Mirror the error semantics of the deprecated nf.Register:
		// transient netlink errors (timeouts) continue processing,
		// everything else stops the receive loop.
		if opError, ok := err.(*netlink.OpError); ok {
			if opError.Timeout() || opError.Temporary() {
				return 0
			}
		}
		slog.Error("nfqueue: receive error", "error", err)
		return 1
	}); err != nil {
		nf.Close()
		e.running.Store(false)
		cancel()
		return fmt.Errorf("registering NFQUEUE handler: %w", err)
	}

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				e.saveState()
				return
			case <-ticker.C:
				e.conntrack.Expire()
				e.ratelimit.Cleanup(5 * time.Minute)
				e.saveState()
			}
		}
	}()

	<-ctx.Done()
	nf.Close()
	e.running.Store(false)
	return nil
}

// Stop gracefully shuts down the NFQUEUE listener.
func (e *Engine) Stop() {
	e.lifecycleMu.RLock()
	cancel := e.cancel
	e.lifecycleMu.RUnlock()
	if cancel != nil {
		cancel()
	}
}
