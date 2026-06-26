// Package conntrack provides TCP connection state tracking for L3 firewall.
//
// Tracks 5-tuple flows (src_ip, dst_ip, protocol, src_port, dst_port) with
// connection state (NEW / ESTABLISHED), packet counts, age tracking, and
// per-source destination-port recording for port scan detection.
package conntrack

import (
	"fmt"
	"sync"
	"time"
)

// Config controls the connection table behaviour.
type Config struct {
	MaxEntries      int           // Max flows before eviction (oldest first)
	IdleTimeout     time.Duration // Flow idle timeout before expiry
	PortScanWindow  int           // Max recent destination ports to track per source IP
	PortScanMaxPorts int          // Max unique ports recorded per source IP
}

// DefaultConfig returns sensible defaults for production use.
func DefaultConfig() Config {
	return Config{
		MaxEntries:       65536,
		IdleTimeout:      300 * time.Second,
		PortScanWindow:   10,  // seconds worth of history
		PortScanMaxPorts: 100, // max unique ports per source
	}
}

// Flow represents a single tracked connection with state and metrics.
type Flow struct {
	SrcIP       string
	DstIP       string
	Protocol    string
	SrcPort     uint16
	DstPort     uint16
	Established bool
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
	// Per-source dest port tracking for scan detection
	srcPorts map[string][]uint16 // srcIP -> recent dest ports
}

// NewTable creates a connection tracking table with the given configuration.
func NewTable(cfg Config) *Table {
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 65536
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 300 * time.Second
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

// LookupOrCreate finds an existing flow by 5-tuple or creates a new one.
// Returns the flow with its packet counter already incremented.
func (t *Table) LookupOrCreate(srcIP, dstIP, protocol string, srcPort, dstPort uint16) *Flow {
	key := flowKey{srcIP, dstIP, protocol, srcPort, dstPort}

	t.mu.Lock()
	defer t.mu.Unlock()

	if f, ok := t.flows[key]; ok {
		f.touch()
		return f
	}

	// Evict if at capacity
	if len(t.flows) >= t.cfg.MaxEntries {
		t.evictOneLocked()
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
	t.flows[key] = f
	return f
}

// Delete removes a flow by 5-tuple.
func (t *Table) Delete(srcIP, dstIP, protocol string, srcPort, dstPort uint16) {
	key := flowKey{srcIP, dstIP, protocol, srcPort, dstPort}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.flows, key)
}

// Expire removes flows that have been idle longer than the configured timeout.
// Returns the number of expired flows.
func (t *Table) Expire() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	var expired []flowKey
	for key, f := range t.flows {
		if now.Sub(f.lastSeen) > t.cfg.IdleTimeout {
			expired = append(expired, key)
		}
	}
	for _, key := range expired {
		delete(t.flows, key)
	}
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
	// Deduplicate
	for _, p := range ports {
		if p == dstPort {
			return
		}
	}
	// Cap at max
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
