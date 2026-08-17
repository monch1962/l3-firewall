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
	mu      sync.RWMutex
	ips     map[string]struct{} // exact IP entries
	nets    []*net.IPNet        // CIDR network entries
	netKeys map[string]struct{} // canonical CIDR string -> present (R45 dedup)
	stopCh  chan struct{}
}

// NewBlocklist creates an empty blocklist.
func NewBlocklist() *Blocklist {
	return &Blocklist{
		ips:     make(map[string]struct{}),
		netKeys: make(map[string]struct{}),
		stopCh:  make(chan struct{}),
	}
}

// Add inserts an IP or CIDR into the blocklist. Supports both exact IPs
// (e.g. "10.0.0.1") and CIDR notation (e.g. "10.0.0.0/24").
// IPv4-mapped IPv6 addresses (e.g. "::ffff:10.0.0.1") are normalized
// to their IPv4 form via To4() so they match bare IPv4 entries.
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
			// Dedup on the canonical form: StartRefresher re-fetches the
			// same feed every interval and old entries are never cleared,
			// so a stable CIDR list re-appends every network each cycle.
			// Without dedup the nets slice grows monotonically until the
			// cap fills with DUPLICATES — newly discovered threats are then
			// silently dropped by the cap check and Contains() scans tens
			// of thousands of duplicate networks per packet (R45 — CIDR
			// duplicate accumulation).
			key := ipnet.String()
			if _, dup := bl.netKeys[key]; dup {
				return
			}
			bl.netKeys[key] = struct{}{}
			bl.nets = append(bl.nets, ipnet)
		}
	} else {
		ip := net.ParseIP(entry)
		if ip != nil {
			// Normalize IPv4-mapped IPv6 to IPv4 form for consistent matching
			if ip4 := ip.To4(); ip4 != nil {
				bl.ips[ip4.String()] = struct{}{}
			} else {
				bl.ips[ip.String()] = struct{}{}
			}
		}
	}
}

// Contains checks if the given IP is in the blocklist (exact or within a CIDR).
// IPv4-mapped IPv6 addresses (e.g. "::ffff:10.0.0.1") are normalized to IPv4
// to match entries added in bare IPv4 form.
func (bl *Blocklist) Contains(ipStr string) bool {
	if bl == nil {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	// Normalize IPv4-mapped IPv6 to IPv4 form for consistent matching
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
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
			key := ipnet.String()
			for i, n := range bl.nets {
				if n.String() == key {
					bl.nets = append(bl.nets[:i], bl.nets[i+1:]...)
					delete(bl.netKeys, key)
					return
				}
			}
		}
	} else {
		ip := net.ParseIP(entry)
		if ip != nil {
			// Normalize IPv4-mapped IPv6 to IPv4 form, matching Add()'s key.
			// On Go < 1.23 IP.String() preserves the mapped form and the
			// delete would miss the normalized key, leaving an entry that
			// can never be removed via its mapped alias (R41 — R10's
			// Add/Remove consistency lesson applied to Remove).
			if ip4 := ip.To4(); ip4 != nil {
				delete(bl.ips, ip4.String())
			} else {
				delete(bl.ips, ip.String())
			}
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
	client := &http.Client{
		Timeout: 30 * time.Second,
		// Do not follow redirects to prevent SSRF attacks where a malicious
		// feed server redirects to internal services (e.g., cloud metadata
		// endpoints, internal APIs). Threat intel feeds should serve content
		// directly; redirects are not expected.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
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

// maxFeedLineSize caps the length of a single feed line. Blocklist
// entries are IPs/CIDRs — anything longer is not a plausible entry and is
// skipped (R54). 1MB is generous (IPv6-CIDR lines are <100 bytes).
const maxFeedLineSize = 1024 * 1024

// parseReader reads IP/CIDR entries from a reader and adds them to the blocklist.
// Lines longer than maxFeedLineSize are skipped with a warning, not fatal:
// bufio.Scanner (pre-R54) aborted the ENTIRE parse on ErrTooLong, so a
// malicious/compromised feed server needed only one 2MB line to discard
// every other entry in the response and permanently kill each refresh —
// newly discovered threats were silently never added (R54).
func (bl *Blocklist) parseReader(r io.Reader) (int, error) {
	br := bufio.NewReaderSize(r, maxFeedLineSize)

	count := 0
	for {
		line, err := br.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			// Overlong line: not a plausible entry. Drain the remainder of
			// the line in bounded chunks (never buffering it whole) and
			// continue with the next line.
			for err == bufio.ErrBufferFull {
				_, err = br.ReadSlice('\n')
			}
			slog.Warn("threat intel: skipping overlong feed line", "max", maxFeedLineSize)
			if err == io.EOF {
				return count, nil
			}
			if err != nil {
				return count, err
			}
			continue
		}
		if err != nil && err != io.EOF {
			return count, err
		}
		// Trim with the same Unicode-aware semantics as the pre-R54
		// strings.TrimSpace(scanner.Text()) so normal lines parse exactly
		// as before; only the overlong-line handling changes.
		lineStr := strings.TrimSpace(string(line))
		if lineStr == "" || strings.HasPrefix(lineStr, "#") {
			if err == io.EOF {
				return count, nil
			}
			continue
		}
		bl.Add(lineStr)
		count++
		if err == io.EOF {
			return count, nil
		}
	}
}

// StartRefresher launches a background goroutine that periodically fetches
// blocklists from the given URLs. Returns a channel; close it to stop.
// A minimum interval of 1 second is enforced to prevent time.NewTicker panics.
// Each call returns a fresh channel so callers can close it without risking
// a double-close panic on a shared channel.
func (bl *Blocklist) StartRefresher(urls []string, interval time.Duration) chan struct{} {
	if bl == nil || len(urls) == 0 {
		return nil
	}
	// Enforce minimum interval to prevent time.NewTicker(0) panic
	// and excessive refresh rates
	const minInterval = 100 * time.Millisecond
	if interval < minInterval {
		interval = minInterval
		slog.Warn("threat intel refresh interval too small, using minimum", "min", minInterval)
	}
	// Return a fresh stop channel so each caller has their own
	// and double-close by the caller does not affect other goroutines
	stopCh := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-bl.stopCh:
				return
			case <-stopCh:
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
	return stopCh
}
