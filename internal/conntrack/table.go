// Package conntrack provides connection state tracking for L3 firewall.
//
// Tracks 5-tuple flows (src_ip, dst_ip, protocol, src_port, dst_port) with
// per-protocol idle timeouts (TCP=300s, UDP=30s, ICMP=5s), connection state,
// packet counts, age tracking, and per-source destination-port recording
// for port scan detection.
package conntrack

import (
	"fmt"
	"sync"
	"time"
)

// TCPState represents the TCP connection state in the finite state machine.
type TCPState int

// TCP state machine constants.
const (
	TCPSynSent      TCPState = iota // SYN sent, awaiting SYN-ACK
	TCPSynReceived                  // SYN received, awaiting ACK
	TCPEstablished                  // Connection established
	TCPFinWait1                     // FIN sent, awaiting FIN-ACK
	TCPFinWait2                     // FIN-ACK received, awaiting FIN
	TCPClosing                      // Both sides have sent FIN
	TCPTimeWait                     // All packets sent, waiting for timeout
	TcpCloseWait                    // Received FIN, waiting for app close
	TCPClosed                       // Connection closed
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
	Hits    int64 // Existing flow found
	Created int64 // New flow created
	Expired int64 // Flow expired by timeout
	Evicted int64 // Flow evicted due to max entries
}

// Flow represents a single tracked connection with state and metrics.
type Flow struct {
	SrcIP       string
	DstIP       string
	Protocol    string
	SrcPort     uint16
	DstPort     uint16
	Established bool
	TCPState    TCPState  // TCP FSM state (zero for non-TCP)
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
	// New connection rate tracking
	newConns     []time.Time
	rateMu       sync.Mutex
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
	return &Table{
		flows:    make(map[flowKey]*Flow),
		cfg:      cfg,
		srcPorts: make(map[string][]uint16),
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
func (t *Table) LookupOrCreate(srcIP, dstIP, protocol string, srcPort, dstPort uint16) *Flow {
	key := flowKey{srcIP, dstIP, protocol, srcPort, dstPort}

	t.mu.Lock()
	defer t.mu.Unlock()

	if f, ok := t.flows[key]; ok {
		f.touch()
		t.stats.Hits++
		return f
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

	// Track new connection timestamp for rate calculation
	t.recordNewConn()

	return f
}

// recordNewConn records a new connection timestamp for rate calculation.
func (t *Table) recordNewConn() {
	t.rateMu.Lock()
	defer t.rateMu.Unlock()
	now := time.Now()
	t.newConns = append(t.newConns, now)
	// Prune timestamps older than 10 seconds
	cutoff := now.Add(-10 * time.Second)
	start := 0
	for i, ts := range t.newConns {
		if ts.After(cutoff) {
			start = i
			break
		}
	}
	t.newConns = t.newConns[start:]
	// Cap slice length
	if len(t.newConns) > 10000 {
		t.newConns = t.newConns[len(t.newConns)-10000:]
	}
}

// NewConnectionRate returns the number of new connections per second (over last 10 seconds).
func (t *Table) NewConnectionRate() float64 {
	t.rateMu.Lock()
	defer t.rateMu.Unlock()
	now := time.Now()
	cutoff := now.Add(-10 * time.Second)
	count := 0
	for _, ts := range t.newConns {
		if ts.After(cutoff) {
			count++
		}
	}
	return float64(count) / 10.0
}

// UpdateTCPState finds or creates a flow and transitions its TCP state based on
// the given TCP flags. This implements a simplified TCP FSM sufficient for
// firewall state tracking. Returns the flow.
func (t *Table) UpdateTCPState(srcIP, dstIP, protocol string, srcPort, dstPort uint16, syn, ack, rst, fin bool) *Flow {
	key := flowKey{srcIP, dstIP, protocol, srcPort, dstPort}

	t.mu.Lock()
	defer t.mu.Unlock()

	var isNew bool
	f, ok := t.flows[key]
	if !ok {
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
		t.recordNewConn()
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

// Delete removes a flow by 5-tuple.
func (t *Table) Delete(srcIP, dstIP, protocol string, srcPort, dstPort uint16) {
	key := flowKey{srcIP, dstIP, protocol, srcPort, dstPort}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.flows, key)
}

// expireBefore removes flows that have been idle longer than the given duration.
// This is exposed for testing. Use Expire() for production with config-based timeouts.
func (t *Table) expireBefore(idle time.Duration) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	var expired []flowKey
	for key, f := range t.flows {
		if now.Sub(f.lastSeen) > idle {
			expired = append(expired, key)
		}
	}
	for _, key := range expired {
		delete(t.flows, key)
	}
	t.stats.Expired += int64(len(expired))
	return len(expired)
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
	}
	t.stats.Expired += int64(len(expired))
	return len(expired)
}

// evictOneLocked removes the single oldest flow. Must be called with t.mu held.
func (t *Table) evictOneLocked() {
	var oldestKey flowKey
	var oldestTime time.Time
	first := true
	for key, f := range t.flows {
		if first || f.lastSeen.Before(oldestTime) {
			oldestKey = key
			oldestTime = f.lastSeen
			first = false
		}
	}
	if !first {
		delete(t.flows, oldestKey)
	}
}

// RecordDestPort records a destination port for a source IP, used for port
// scan detection. Duplicate ports are deduplicated.
func (t *Table) RecordDestPort(srcIP string, dstPort uint16) {
	t.mu.Lock()
	defer t.mu.Unlock()

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
	ports := t.srcPorts[srcIP]
	if len(ports) == 0 {
		return nil
	}
	result := make([]uint16, len(ports))
	copy(result, ports)
	return result
}
