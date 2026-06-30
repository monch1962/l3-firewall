// Package threatintel provides IP reputation blocklist management with
// automatic fetching and periodic refresh from external URLs.
package threatintel

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// maxBlocklistEntries prevents memory exhaustion from a very large blocklist.
const maxBlocklistEntries = 500000

// maxFeedResponseSize limits the response body from a threat intel feed to
// prevent memory exhaustion attacks (50MB).
const maxFeedResponseSize = 50 * 1024 * 1024

// Blocklist holds a set of blocked IPs and CIDR networks, refreshed from
// external threat intelligence feeds.
type Blocklist struct {
	mu     sync.RWMutex
	ips    map[string]struct{} // exact IP entries
	nets   []*net.IPNet        // CIDR network entries
	stopCh chan struct{}
}

// NewBlocklist creates an empty blocklist.
func NewBlocklist() *Blocklist {
	return &Blocklist{
		ips:    make(map[string]struct{}),
		stopCh: make(chan struct{}),
	}
}

// Add inserts an IP or CIDR into the blocklist. Supports both exact IPs
// (e.g. "10.0.0.1") and CIDR notation (e.g. "10.0.0.0/24").
func (bl *Blocklist) Add(entry string) {
	if bl == nil {
		return
	}
	bl.mu.Lock()
	defer bl.mu.Unlock()

	// Check total cap
	if len(bl.ips)+len(bl.nets) >= maxBlocklistEntries {
		return
	}

	if strings.Contains(entry, "/") {
		_, ipnet, err := net.ParseCIDR(entry)
		if err == nil {
			bl.nets = append(bl.nets, ipnet)
		}
	} else {
		ip := net.ParseIP(entry)
		if ip != nil {
			bl.ips[ip.String()] = struct{}{}
		}
	}
}

// Contains checks if the given IP is in the blocklist (exact or within a CIDR).
func (bl *Blocklist) Contains(ipStr string) bool {
	if bl == nil {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	bl.mu.RLock()
	defer bl.mu.RUnlock()

	// Check exact match
	if _, ok := bl.ips[ip.String()]; ok {
		return true
	}

	// Check CIDR match
	for _, n := range bl.nets {
		if n.Contains(ip) {
			return true
		}
	}

	return false
}

// Remove deletes an entry from the blocklist.
func (bl *Blocklist) Remove(entry string) {
	if bl == nil {
		return
	}
	bl.mu.Lock()
	defer bl.mu.Unlock()

	if strings.Contains(entry, "/") {
		_, ipnet, err := net.ParseCIDR(entry)
		if err == nil {
			for i, n := range bl.nets {
				if n.String() == ipnet.String() {
					bl.nets = append(bl.nets[:i], bl.nets[i+1:]...)
					return
				}
			}
		}
	} else {
		ip := net.ParseIP(entry)
		if ip != nil {
			delete(bl.ips, ip.String())
		}
	}
}

// Len returns the number of blocked entries.
func (bl *Blocklist) Len() int {
	if bl == nil {
		return 0
	}
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	return len(bl.ips) + len(bl.nets)
}

// DataForOPA returns a map suitable for OPA's data store.
// Keys are IP strings, values are true.
func (bl *Blocklist) DataForOPA() map[string]interface{} {
	if bl == nil {
		return nil
	}
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	result := make(map[string]interface{}, len(bl.ips)+len(bl.nets))
	for ip := range bl.ips {
		result[ip] = true
	}
	for _, n := range bl.nets {
		result[n.String()] = true
	}
	return result
}

// FetchFromURL fetches a blocklist from the given URL and adds all entries.
// Returns the number of new entries added. Supports one-IP/CIDR-per-line format.
// Lines starting with # are comments and are ignored.
func (bl *Blocklist) FetchFromURL(url string) (int, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return 0, fmt.Errorf("fetching blocklist %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("blocklist %s returned status %d", url, resp.StatusCode)
	}

	return bl.parseReader(io.LimitReader(resp.Body, maxFeedResponseSize))
}

// parseReader reads IP/CIDR entries from a reader and adds them to the blocklist.
func (bl *Blocklist) parseReader(r io.Reader) (int, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		bl.Add(line)
		count++
	}

	return count, scanner.Err()
}

// StartRefresher launches a background goroutine that periodically fetches
// blocklists from the given URLs. Returns a channel; close it to stop.
func (bl *Blocklist) StartRefresher(urls []string, interval time.Duration) chan struct{} {
	if bl == nil || len(urls) == 0 {
		return nil
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-bl.stopCh:
				return
			case <-ticker.C:
				for _, url := range urls {
					count, err := bl.FetchFromURL(url)
					if err != nil {
						slog.Warn("threat intel refresh failed", "url", url, "error", err)
					} else {
						slog.Info("threat intel refreshed", "url", url, "entries", count)
					}
				}
			}
		}
	}()
	return bl.stopCh
}
