// Package conntrack provides connection state tracking for L3 firewall.
//
// Tracks 5-tuple flows (src_ip, dst_ip, protocol, src_port, dst_port) with
// per-protocol idle timeouts (TCP=300s, UDP=30s, ICMP=5s), connection state,
// packet counts, age tracking, and per-source destination-port recording
// for port scan detection.
package conntrack

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// TCPState represents the TCP connection state in the finite state machine.
type TCPState int

// TCP state machine constants.
const (
	TCPSynSent     TCPState = iota // SYN sent, awaiting SYN-ACK
	TCPSynReceived                 // SYN received, awaiting ACK
	TCPEstablished                 // Connection established
	TCPFinWait1                    // FIN sent, awaiting FIN-ACK
	TCPFinWait2                    // FIN-ACK received, awaiting FIN
	TCPClosing                     // Both sides have sent FIN
	TCPTimeWait                    // All packets sent, waiting for timeout
	TcpCloseWait                   // Received FIN, waiting for app close
	TCPClosed                      // Connection closed
)

// String returns a human-readable TCP state name.
func (s TCPState) String() string {
	switch s {
	case TCPSynSent:
		return "SYN_SENT"
	case TCPSynReceived:
		return "SYN_RECEIVED"
	case TCPEstablished:
		return "ESTABLISHED"
	case TCPFinWait1:
		return "FIN_WAIT_1"
	case TCPFinWait2:
		return "FIN_WAIT_2"
	case TCPClosing:
		return "CLOSING"
	case TCPTimeWait:
		return "TIME_WAIT"
	case TcpCloseWait:
		return "CLOSE_WAIT"
	case TCPClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

// Config controls the connection table behaviour.
type Config struct {
	MaxEntries       int           // Max flows before eviction (oldest first)
	MaxFlowsPerSrcIP int           // Max concurrent flows per source IP (0 = unlimited)
	IdleTimeout      time.Duration // TCP flow idle timeout
	UDPTimeout       time.Duration // UDP flow idle timeout
	ICMPTimeout      time.Duration // ICMP flow idle timeout
	PortScanWindow   int           // Max recent destination ports to track per source IP
	PortScanMaxPorts int           // Max unique ports recorded per source IP
}

// DefaultConfig returns sensible defaults for production use.
func DefaultConfig() Config {
	return Config{
		MaxEntries:       65536,
		IdleTimeout:      300 * time.Second,
		UDPTimeout:       30 * time.Second,
		ICMPTimeout:      5 * time.Second,
		PortScanWindow:   10,
		PortScanMaxPorts: 100,
	}
}

// Stats holds cumulative connection tracking counters.
type Stats struct {
	Hits              int64 // Existing flow found
	Created           int64 // New flow created
	Expired           int64 // Flow expired by timeout
	Evicted           int64 // Flow evicted due to max entries
	FlowLimitExceeded int64 // Flow creation blocked by per-source limit
}

// Flow represents a single tracked connection with state and metrics.
type Flow struct {
	SrcIP       string
	DstIP       string
	Protocol    string
	SrcPort     uint16
	DstPort     uint16
	Established bool
	TCPState    TCPState // TCP FSM state (zero for non-TCP)
	Packets     int64
	created     time.Time
	lastSeen    time.Time
}

// AgeMs returns the flow age in milliseconds.
func (f *Flow) AgeMs() int64 {
	return time.Since(f.created).Milliseconds()
}

// LastSeenMs returns milliseconds since the flow was last active.
func (f *Flow) LastSeenMs() int64 {
	return time.Since(f.lastSeen).Milliseconds()
}

// SetEstablished marks the flow as having completed TCP handshake.
func (f *Flow) SetEstablished() {
	f.Established = true
	f.lastSeen = time.Now()
}

// touch updates the last-seen timestamp and increments packet count.
func (f *Flow) touch() {
	f.Packets++
	f.lastSeen = time.Now()
}

// flowKey uniquely identifies a 5-tuple connection.
type flowKey struct {
	srcIP    string
	dstIP    string
	protocol string
	srcPort  uint16
	dstPort  uint16
}

// normalizeIP canonicalizes an IP string so IPv4-mapped IPv6 addresses
// ("::ffff:10.0.0.1") share keys with their IPv4 form ("10.0.0.1").
// flows, srcFlowCount and srcPorts are keyed by these strings; without
// normalization one logical source splits across keys — bypassing the
// per-source flow limit, splitting port-scan history, and leaving flows
// that can never be deleted via the other key form (R40.5; R10 class).
func normalizeIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	return parsed.String()
}

func (k flowKey) String() string {
	return fmt.Sprintf("%s:%d-%s:%d/%s", k.srcIP, k.srcPort, k.dstIP, k.dstPort, k.protocol)
}

// Table is a thread-safe connection tracking table.
type Table struct {
	mu       sync.RWMutex
	flows    map[flowKey]*Flow
	cfg      Config
	stats    Stats
	srcPorts map[string][]uint16 // srcIP -> recent dest ports for scan detection
	// New connection rate tracking — per source IP, bucketed by second.
	// Pre-R77 the tracker was a TABLE-GLOBAL []time.Time capped at 10000
	// entries: (a) the cap aliased any sustained new-conn rate >= 1000/s to
	// exactly 1000.0 (10000 entries / 10s window), so the shipped
	// deny-override rule deny_new_conn_rate (l3.rego RULE 13, fires only on
	// input.rate.new_conns_per_sec > 1000 — max_new_connections_per_second
	// := 1000) could never fire in the production binary no matter how fast
	// the flood; and (b) the rate was GLOBAL — every packet from every
	// source inherited the aggregate new-conn rate of all sources, while
	// opa.BuildInput documents the field as "New connections/sec from this
	// source" and the policy comment says "Per-IP new connection rate
	// limit". Fixed one-second bucket rings per source (10 slots) report
	// any rate without aliasing and attribute it to the right source;
	// entries are pruned in decrFlowCountLocked (the R39 choke point that
	// also prunes srcPorts) so spoofed one-flow sources cannot accumulate.
	newConns map[string]*newConnRate // srcIP -> per-second bucket ring
	rateMu   sync.Mutex
	// Per-source flow count tracking
	srcFlowCount map[string]int // srcIP -> number of active flows
}

// connRateWindowSecs is the number of one-second buckets in a per-source
// new-connection rate tracker. 10 buckets cover the same 10-second window the
// pre-R77 global slice measured ("new connections per second over the last 10
// seconds").
const connRateWindowSecs = 10

// newConnRate counts new connections from one source IP in fixed one-second
// buckets. Slots are indexed by second % connRateWindowSecs; a slot whose
// stored second differs from the write second holds a count from >= 10
// seconds ago (the same residue recurs every 10s) and is safely overwritten.
// Fixed memory (connRateWindowSecs int64s) per active source regardless of
// connection rate — no cap to alias against, unlike the pre-R77 global
// timestamp slice (R77).
type newConnRate struct {
	secs   [connRateWindowSecs]int64 // unix second each slot holds
	counts [connRateWindowSecs]int64 // connections recorded in that second
}

// record counts one new connection from the source at the given time.
func (r *newConnRate) record(now time.Time) {
	sec := now.Unix()
	i := sec % connRateWindowSecs
	if r.secs[i] != sec {
		r.secs[i] = sec
		r.counts[i] = 0
	}
	r.counts[i]++
}

// rate returns new connections per second averaged over the window: the sum
// of bucket counts whose second is within the last connRateWindowSecs seconds
// (>= now-9, i.e. strictly newer than now-10) divided by the window width.
// Bucket counts are int64 — unbounded per second, so a sustained flood of any
// rate reports a value above the policy threshold instead of saturating at it
// (R77).
func (r *newConnRate) rate(now time.Time) float64 {
	sec := now.Unix()
	var sum int64
	for i := 0; i < connRateWindowSecs; i++ {
		if r.secs[i] != 0 && r.secs[i] > sec-connRateWindowSecs {
			sum += r.counts[i]
		}
	}
	return float64(sum) / float64(connRateWindowSecs)
}

// NewTable creates a connection tracking table with the given configuration.
func NewTable(cfg Config) *Table {
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 65536
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 300 * time.Second
	}
	if cfg.UDPTimeout <= 0 {
		cfg.UDPTimeout = 30 * time.Second
	}
	if cfg.ICMPTimeout <= 0 {
		cfg.ICMPTimeout = 5 * time.Second
	}
	// Default the port-scan tracking bounds like every other field (R76):
	// cmd/server/main.go constructs its Config with ONLY MaxEntries and the
	// idle timeouts — no CLI flags exist for the scan fields — so a zero
	// PortScanMaxPorts previously made RecordDestPort's cap check
	// `len(ports) >= 0` short-circuit forever: srcPorts never filled,
	// GetRecentDestPorts returned nil, and OPA input connection.recent_ports
	// stayed empty on every packet. The shipped deny-override policy enables
	// port-scan blocking by default (l3.rego deny_port_scan, threshold 20),
	// so that rule could never fire in the production binary — moderate
	// scans were silently allowed (R40.4-class dropped control; the other
	// target-package constructors — capture.NewWriter, l2filter.NewFilter,
	// syncer.New — all default their config fields, NewTable was the lone
	// asymmetric exception). Zero now means "default", matching the
	// established convention for MaxEntries and the timeouts above.
	if cfg.PortScanMaxPorts <= 0 {
		cfg.PortScanMaxPorts = 100
	}
	return &Table{
		flows:        make(map[flowKey]*Flow),
		cfg:          cfg,
		srcPorts:     make(map[string][]uint16),
		srcFlowCount: make(map[string]int),
		newConns:     make(map[string]*newConnRate),
	}
}

// Len returns the number of tracked flows.
func (t *Table) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.flows)
}

// Stats returns a copy of the cumulative stats counters.
func (t *Table) Stats() Stats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.stats
}

// idleTimeoutFor returns the appropriate idle timeout for a given protocol.
func (t *Table) idleTimeoutFor(protocol string) time.Duration {
	switch protocol {
	case "UDP":
		return t.cfg.UDPTimeout
	case "ICMP":
		return t.cfg.ICMPTimeout
	default:
		return t.cfg.IdleTimeout
	}
}

// LookupOrCreate finds an existing flow by 5-tuple or creates a new one.
// Returns the flow with its packet counter already incremented.
// Returns nil if the per-source flow limit has been exceeded.
func (t *Table) LookupOrCreate(srcIP, dstIP, protocol string, srcPort, dstPort uint16) *Flow {
	srcIP = normalizeIP(srcIP)
	dstIP = normalizeIP(dstIP)
	key := flowKey{srcIP, dstIP, protocol, srcPort, dstPort}

	t.mu.Lock()
	defer t.mu.Unlock()

	if f, ok := t.flows[key]; ok {
		f.touch()
		t.stats.Hits++
		return f
	}

	// Check per-source flow limit
	if t.reachedFlowLimitLocked(srcIP) {
		t.stats.FlowLimitExceeded++
		return nil
	}

	// Evict if at capacity
	if len(t.flows) >= t.cfg.MaxEntries {
		t.evictOneLocked()
		t.stats.Evicted++
	}

	f := &Flow{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: protocol,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Packets:  1,
		created:  time.Now(),
		lastSeen: time.Now(),
	}

	// Set initial TCP state based on protocol and flags
	if protocol == "TCP" {
		f.TCPState = TCPSynSent
	}

	t.flows[key] = f
	t.stats.Created++
	t.incrFlowCountLocked(srcIP)

	// Track new connection for this source's rate calculation (R77)
	t.recordNewConn(srcIP)

	return f
}

// recordNewConn records a new connection timestamp for rate calculation,
// attributed to the source IP that opened it (R77 — the pre-R77 tracker was
// table-global, so one source's flood was reported to every packet of every
// source and the per-source policy rule could never attribute correctly).
// Callers pass the normalized srcIP (already canonicalized by the flow-key
// methods).
func (t *Table) recordNewConn(srcIP string) {
	t.rateMu.Lock()
	defer t.rateMu.Unlock()
	now := time.Now()
	r := t.newConns[srcIP]
	if r == nil {
		r = &newConnRate{}
		t.newConns[srcIP] = r
	}
	r.record(now)
}

// NewConnectionRate returns the number of new connections per second from the
// given source IP (over the last 10 seconds). Per-source attribution (R77):
// opa.BuildInput documents Rate.NewConnsPerSec as "New connections/sec from
// this source" and the policy's deny_new_conn_rate is a per-IP limit, but the
// pre-R77 implementation summed a TABLE-GLOBAL timestamp slice — every packet
// carried the aggregate new-conn rate of all sources, and the 10000-entry cap
// aliased sustained floods at exactly 1000.0 conn/s so the rule's strict
// `> 1000` could never fire. Bucketed per-source counting reports any rate
// without aliasing and attributes it to the source that owns it. Returns 0 for
// an unknown source (or when srcIP does not parse).
func (t *Table) NewConnectionRate(srcIP string) float64 {
	srcIP = normalizeIP(srcIP)
	t.rateMu.Lock()
	defer t.rateMu.Unlock()
	r := t.newConns[srcIP]
	if r == nil {
		return 0
	}
	return r.rate(time.Now())
}

// UpdateTCPState finds or creates a flow and transitions its TCP state based on
// the given TCP flags. This implements a simplified TCP FSM sufficient for
// firewall state tracking. Returns the flow.
func (t *Table) UpdateTCPState(srcIP, dstIP, protocol string, srcPort, dstPort uint16, syn, ack, rst, fin bool) *Flow {
	srcIP = normalizeIP(srcIP)
	dstIP = normalizeIP(dstIP)
	key := flowKey{srcIP, dstIP, protocol, srcPort, dstPort}

	t.mu.Lock()
	defer t.mu.Unlock()

	var isNew bool
	f, ok := t.flows[key]
	if !ok {
		// Check per-source flow limit before creating
		if t.reachedFlowLimitLocked(srcIP) {
			t.stats.FlowLimitExceeded++
			return nil
		}
		if len(t.flows) >= t.cfg.MaxEntries {
			t.evictOneLocked()
			t.stats.Evicted++
		}
		isNew = true
		f = &Flow{
			SrcIP: srcIP, DstIP: dstIP, Protocol: protocol,
			SrcPort: srcPort, DstPort: dstPort,
			Packets: 1, created: time.Now(), lastSeen: time.Now(),
		}
		t.flows[key] = f
		t.stats.Created++
		t.incrFlowCountLocked(srcIP)
		t.recordNewConn(srcIP)
	} else {
		f.touch()
		t.stats.Hits++
	}

	switch {
	case rst:
		// RST closes the connection regardless of state
		f.TCPState = TCPClosed
		f.Established = false

	case syn && ack && !fin:
		// SYN-ACK transitions from SYN_SENT to ESTABLISHED
		if f.TCPState == TCPSynSent {
			f.TCPState = TCPEstablished
			f.Established = true
		}

	case syn && !ack && !fin:
		// SYN from the other direction transitions to SYN_RECEIVED
		if f.TCPState == TCPSynSent {
			f.TCPState = TCPSynReceived
		}

	case fin && ack:
		// FIN-ACK
		switch f.TCPState {
		case TCPSynSent, TCPSynReceived:
			// Server-side FIN+ACK on a reverse-path flow that hasn't seen SYN yet.
			// This is part of an existing bidirectional connection closing.
			f.TCPState = TCPFinWait1
		case TCPEstablished:
			f.TCPState = TCPFinWait1
		case TCPFinWait1:
			f.TCPState = TCPFinWait2
		case TCPFinWait2:
			f.TCPState = TCPTimeWait
		case TcpCloseWait:
			f.TCPState = TCPClosed
			f.Established = false
		}

	case fin && !ack:
		// Plain FIN
		switch f.TCPState {
		case TCPEstablished:
			f.TCPState = TCPFinWait1
		case TCPFinWait1:
			f.TCPState = TCPClosing
		}

	case ack && !syn && !fin && !rst:
		// ACK (data or handshake continuation)
		switch f.TCPState {
		case TCPSynSent:
			f.TCPState = TCPEstablished
			f.Established = true
		case TCPFinWait1:
			f.TCPState = TCPFinWait2
		case TCPClosing:
			f.TCPState = TCPTimeWait
		case TCPTimeWait:
			f.TCPState = TCPClosed
			f.Established = false
		}
	}

	// Also set via other side's perspective
	if isNew && protocol == "TCP" && !syn && !rst && !fin {
		// Non-SYN, non-FIN, non-RST flow started from the server side (e.g., pure ACK)
		f.TCPState = TCPSynReceived
	}

	return f
}

// Delete removes a flow by 5-tuple and decrements the per-source flow count.
func (t *Table) Delete(srcIP, dstIP, protocol string, srcPort, dstPort uint16) {
	srcIP = normalizeIP(srcIP)
	dstIP = normalizeIP(dstIP)
	key := flowKey{srcIP, dstIP, protocol, srcPort, dstPort}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.flows[key]; ok {
		delete(t.flows, key)
		t.decrFlowCountLocked(srcIP)
	}
}

// Expire removes flows that have been idle longer than their protocol-specific timeout.
// Returns the number of expired flows.
func (t *Table) Expire() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	var expired []flowKey
	for key, f := range t.flows {
		timeout := t.idleTimeoutFor(f.Protocol)
		if now.Sub(f.lastSeen) > timeout {
			expired = append(expired, key)
		}
	}
	for _, key := range expired {
		delete(t.flows, key)
		t.decrFlowCountLocked(key.srcIP)
	}
	t.stats.Expired += int64(len(expired))
	return len(expired)
}

// evictionSampleSize bounds the eviction scan in evictOneLocked. Scanning
// the entire flow map for the oldest entry is O(n) work executed under the
// write lock in the packet hot path — an attacker churning spoofed 5-tuples
// at capacity forces a full-map scan per packet, amplifying CPU by the map
// size (R40.6; same class as the rate-limiter eviction fixed in R40.2).
// Sampling a small random subset keeps eviction amortized O(1) while still
// removing an old flow.
const evictionSampleSize = 16

// evictOneLocked removes the single oldest flow from a bounded random
// sample of the map. Must be called with t.mu held.
func (t *Table) evictOneLocked() {
	var oldestKey flowKey
	var oldestTime time.Time
	first := true
	scanned := 0
	for key, f := range t.flows {
		if scanned >= evictionSampleSize {
			break
		}
		scanned++
		if first || f.lastSeen.Before(oldestTime) {
			oldestKey = key
			oldestTime = f.lastSeen
			first = false
		}
	}
	if !first {
		delete(t.flows, oldestKey)
		t.decrFlowCountLocked(oldestKey.srcIP)
	}
}

// RecordDestPort records a destination port for a source IP, used for port
// scan detection. Duplicate ports are deduplicated.
func (t *Table) RecordDestPort(srcIP string, dstPort uint16) {
	t.mu.Lock()
	defer t.mu.Unlock()

	srcIP = normalizeIP(srcIP)
	ports := t.srcPorts[srcIP]
	for _, p := range ports {
		if p == dstPort {
			return
		}
	}
	if len(ports) >= t.cfg.PortScanMaxPorts {
		return
	}
	t.srcPorts[srcIP] = append(ports, dstPort)
}

// GetRecentDestPorts returns the recorded destination ports for a source IP.
// Returns nil if no ports have been recorded.
func (t *Table) GetRecentDestPorts(srcIP string) []uint16 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	srcIP = normalizeIP(srcIP)
	ports := t.srcPorts[srcIP]
	if len(ports) == 0 {
		return nil
	}
	result := make([]uint16, len(ports))
	copy(result, ports)
	return result
}

// reachedFlowLimitLocked checks if the source IP has reached its per-source flow
// limit. Must be called with t.mu held (read or write).
func (t *Table) reachedFlowLimitLocked(srcIP string) bool {
	if t.cfg.MaxFlowsPerSrcIP <= 0 {
		return false
	}
	return t.srcFlowCount[srcIP] >= t.cfg.MaxFlowsPerSrcIP
}

// incrFlowCountLocked increments the flow count for a source IP.
// Must be called with t.mu write lock held.
func (t *Table) incrFlowCountLocked(srcIP string) {
	t.srcFlowCount[srcIP]++
}

// decrFlowCountLocked decrements the flow count for a source IP and cleans up
// the entry if it reaches zero. Must be called with t.mu write lock held.
// Also prunes the srcPorts port-scan history: port-scan tracking is only
// meaningful while the source has active flows. Without this prune, srcPorts
// grows unboundedly — every unique (possibly spoofed) srcIP leaves a permanent
// entry, enabling memory exhaustion over the firewall's lifetime (R39).
// The per-source new-connection rate tracker (newConns) is pruned in the same
// choke point: a source whose last flow died is not actively connecting, so
// its rate history is stale by definition — retaining it would let spoofed
// one-flow sources accumulate map entries forever (R77, the R39 companion-map
// rule applied to the R77 per-source tracker).
func (t *Table) decrFlowCountLocked(srcIP string) {
	t.srcFlowCount[srcIP]--
	if t.srcFlowCount[srcIP] <= 0 {
		delete(t.srcFlowCount, srcIP)
		delete(t.srcPorts, srcIP)
		t.rateMu.Lock()
		delete(t.newConns, srcIP)
		t.rateMu.Unlock()
	}
}

// GetSrcFlowCount returns the number of active flows for a given source IP.
func (t *Table) GetSrcFlowCount(srcIP string) int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.srcFlowCount[srcIP]
}
