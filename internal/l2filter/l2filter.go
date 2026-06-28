// Package l2filter provides Layer 2 security: MAC address filtering,
// ARP spoofing detection, and DHCP snooping.
package l2filter

import (
	"fmt"
	"strings"
	"sync"
)

// Config controls L2 filtering behaviour.
type Config struct {
	AllowedMACs     []string // MAC addresses allowed to send traffic (empty = allow all)
	BlockedMACs     []string // MAC addresses blocked (empty = none blocked)
	EnableARPCheck  bool     // enable ARP spoofing detection
	EnableDHCPCheck bool     // enable DHCP snooping
}

// Filter provides MAC-based access control and L2 attack detection.
type Filter struct {
	mu          sync.RWMutex
	cfg         Config
	allowedMACs map[string]bool // normalized MAC -> true
	blockedMACs map[string]bool // normalized MAC -> true
	arpTable    map[string]string // IP -> MAC binding (from DHCP snooping)
}

// NewFilter creates an L2 filter.
func NewFilter(cfg Config) *Filter {
	f := &Filter{
		cfg:         cfg,
		allowedMACs: make(map[string]bool),
		blockedMACs: make(map[string]bool),
		arpTable:    make(map[string]string),
	}
	for _, m := range cfg.AllowedMACs {
		f.allowedMACs[normalizeMAC(m)] = true
	}
	for _, m := range cfg.BlockedMACs {
		f.blockedMACs[normalizeMAC(m)] = true
	}
	return f
}

// normalizeMAC normalizes a MAC address to lowercase with no separators.
func normalizeMAC(mac string) string {
	return strings.NewReplacer(":", "", "-", "", ".", "", " ", "").
		Replace(strings.ToLower(mac))
}

// MACAllowed checks if a source MAC is allowed. If AllowedMACs is empty, all are
// allowed unless the MAC is in BlockedMACs.
func (f *Filter) MACAllowed(srcMAC string) (bool, string) {
	if f == nil {
		return true, ""
	}
	f.mu.RLock()
	defer f.mu.RUnlock()

	norm := normalizeMAC(srcMAC)

	// Check blocked list first
	if f.blockedMACs[norm] {
		return false, fmt.Sprintf("blocked MAC: %s", srcMAC)
	}

	// If allowlist is empty, all are allowed (including empty MAC)
	if len(f.allowedMACs) == 0 {
		return true, ""
	}

	// If allowlist is set, empty MAC is denied
	if norm == "" {
		return false, "empty MAC not in allowlist"
	}

	// Check allowlist
	if !f.allowedMACs[norm] {
		return false, fmt.Sprintf("MAC not in allowlist: %s", srcMAC)
	}

	return true, ""
}

// RecordDHCP snoops a DHCP ACK to build an IP→MAC binding.
// Returns true if the binding was recorded or updated.
func (f *Filter) RecordDHCP(ip, mac string) bool {
	if f == nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	norm := normalizeMAC(mac)
	f.arpTable[ip] = norm
	return true
}

// CheckARP verifies that the given IP→MAC binding matches our known table.
// If the IP is not in the table, it's recorded (learning mode).
// Returns (allowed, reason).
func (f *Filter) CheckARP(ip, mac string) (bool, string) {
	if f == nil {
		return true, ""
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	norm := normalizeMAC(mac)
	if norm == "" || ip == "" {
		return true, ""
	}

	knownMAC, exists := f.arpTable[ip]
	if !exists {
		// Learn new binding
		f.arpTable[ip] = norm
		return true, ""
	}

	if knownMAC != norm {
		return false, fmt.Sprintf("ARP spoofing detected: IP %s changed from %s to %s", ip, knownMAC, mac)
	}

	return true, ""
}
