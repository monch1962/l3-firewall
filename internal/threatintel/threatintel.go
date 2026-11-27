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
	"unicode"
	"unicode/utf8"

	"github.com/monch1962/l3-firewall/internal/redact"
)

// maxBlocklistEntries prevents memory exhaustion from a very large blocklist.
const maxBlocklistEntries = 500000

// maxCIDRNetworks caps the number of DISTINCT CIDR networks stored. R58
// introduced the cap to bound the per-packet scan; R89 removed the scan
// itself (bucketed lookup below), so the cap now only bounds memory.
const maxCIDRNetworks = 65536

// maxFeedResponseSize limits the response body from a threat intel feed to
// prevent memory exhaustion attacks (50MB).
const maxFeedResponseSize = 50 * 1024 * 1024

// netBucket holds every CIDR entry that shares one prefix length within one
// address family. mask is the canonical prefix mask for that length (4 bytes
// for IPv4, 16 for IPv6); nets maps the MASKED network bytes to the entry.
//
// R89: before bucketing, Contains() scanned the whole network list on every
// packet. R58 capped that list at 65536 distinct networks and accepted the
// residual as "~0.8ms worst case" — but the scan runs on the single-goroutine
// NFQUEUE receive loop, so the cap replaced "unbounded" with "still
// catastrophic": measured 295 µs per Contains() at the cap, i.e. a throughput
// ceiling of a few thousand packets per second, which a 1 Gbps link exceeds
// by two orders of magnitude (queue overflow → the kernel drops ALL traffic).
// Membership in a set of prefixes is a hash probe per distinct PREFIX LENGTH
// (≤33 for IPv4, ≤129 for IPv6) — a property of the address family, never of
// how many networks the feed carries. Add/Remove pay one map operation each.
type netBucket struct {
	mask net.IPMask
	nets map[string]*net.IPNet
}

// netBucketSlots is the number of prefix lengths per family (0..32, 0..128).
const (
	v4BucketSlots = 33
	v6BucketSlots = 129
)

// Blocklist holds a set of blocked IPs and CIDR networks, refreshed from
// external threat intelligence feeds.
type Blocklist struct {
	mu       sync.RWMutex
	ips      map[string]struct{} // exact IP entries
	nets4    [v4BucketSlots]*netBucket
	nets6    [v6BucketSlots]*netBucket
	netKeys  map[string]struct{} // canonical CIDR string -> present (R45 dedup)
	netCount int                 // stored networks across both families
	stopCh   chan struct{}

	// One-shot warning latches, guarded by mu. Every silent-drop path in
	// Add warns ONCE per process: a hostile feed can carry thousands of
	// offending lines per refresh, so an unlatched warning would be a
	// log-flood vector of its own (the R54 overlong-line posture). The
	// latch is what makes the drop observable at all (R82.2).
	capWarned    bool // total entry cap reached — new intelligence dropped
	netCapWarned bool // distinct-CIDR cap reached (R58)
	familyWarned bool // whole-address-family entry rejected (R82)
}

// NewBlocklist creates an empty blocklist.
func NewBlocklist() *Blocklist {
	return &Blocklist{
		ips:     make(map[string]struct{}),
		netKeys: make(map[string]struct{}),
		stopCh:  make(chan struct{}),
	}
}

// wholeFamilyNet reports whether the parsed network matches every address
// of an address family, i.e. it asserts "everything is hostile".
//
// This is the shape an IPv4-mapped IPv6 CIDR collapses into. Go's
// net.IPNet.Contains normalises an IPv4 source with To4() and then compares
// the masked 4-byte tail (networkNumberAndMask rewrites a 16-byte mask to
// its last 4 bytes when the network address is mapped), so
//
//	::ffff:0:0/96  ->  canonical "0.0.0.0/0"  -> matches EVERY IPv4 source
//
// A blocklist entry spelled that way is common in the wild — it is the
// canonical "the IPv4-mapped space" entry that SSRF/deny lists use to mean
// "IPv4-mapped literals only" — and here it silently blackholes the whole
// IPv4 plane from ONE feed line (R82.1; same whole-family false-block class
// as R79.1). No threat-intel entry can meaningfully assert "all addresses";
// a firewall-wide block belongs in the policy, where it is explicit and
// auditable. Mapped entries that DO name IPv4 addresses
// (::ffff:a.b.c.d/(96+N)) are unaffected: their effective v4 prefix is N>0.
func wholeFamilyNet(ipnet *net.IPNet) bool {
	ones, bits := ipnet.Mask.Size()
	if ones == 0 {
		// 0.0.0.0/0 or ::/0.
		return true
	}
	if bits == 128 && ones == 96 && ipnet.IP.To4() != nil {
		// The IPv4-mapped space itself: /96 in the mapped range is a /0
		// once the network address is normalised to 4 bytes.
		return true
	}
	return false
}

// bucketFor resolves the bucket that holds (or would hold) ipnet, together
// with the masked-network key used inside it. With create=false it returns
// (nil, nil) when no entry with that prefix length exists, so lookups and
// removals never allocate.
//
// The IPv4-mapped special case mirrors net.IPNet.Contains exactly: when the
// MASKED network address is IPv4-mapped, Go truncates the 16-byte mask to its
// last 4 bytes and compares 4-byte addresses, so ::ffff:a.b.c.d/(96+N) is a
// v4 network with prefix N (R82). Any other 16-byte mask keeps 16-byte
// comparison, and a v4 source can never match it.
func (bl *Blocklist) bucketFor(ipnet *net.IPNet, create bool) (*netBucket, string) {
	mask := ipnet.Mask
	network := ipnet.IP
	if len(mask) == net.IPv6len {
		if v4 := network.To4(); v4 != nil {
			mask = mask[12:]
			network = v4
		}
	}
	ones, bits := mask.Size()
	if ones <= 0 || len(network) != len(mask) {
		// ones == 0 is the whole-family shape rejected by wholeFamilyNet;
		// a length mismatch cannot be produced by ParseCIDR.
		return nil, ""
	}
	var slot **netBucket
	switch {
	case bits == 32 && len(mask) == net.IPv4len && ones <= 32:
		slot = &bl.nets4[ones]
	case bits == 128 && len(mask) == net.IPv6len && ones <= 128:
		slot = &bl.nets6[ones]
	default:
		return nil, ""
	}
	masked := make([]byte, len(mask))
	for i := range mask {
		masked[i] = network[i] & mask[i]
	}
	if *slot == nil {
		if !create {
			return nil, ""
		}
		*slot = &netBucket{mask: net.CIDRMask(ones, bits), nets: make(map[string]*net.IPNet)}
	}
	return *slot, string(masked)
}

// matchNets reports whether ip (4-byte or 16-byte, already normalised) falls
// inside any stored network. Cost is one masked probe per occupied prefix
// length — independent of the number of networks stored (R89).
func (bl *Blocklist) matchNets(ip net.IP) bool {
	if len(ip) == net.IPv4len {
		var key [net.IPv4len]byte
		for ones := 1; ones < v4BucketSlots; ones++ {
			b := bl.nets4[ones]
			if b == nil {
				continue
			}
			for i := 0; i < net.IPv4len; i++ {
				key[i] = ip[i] & b.mask[i]
			}
			if _, ok := b.nets[string(key[:])]; ok {
				return true
			}
		}
		return false
	}
	var key [net.IPv6len]byte
	for ones := 1; ones < v6BucketSlots; ones++ {
		b := bl.nets6[ones]
		if b == nil {
			continue
		}
		for i := 0; i < net.IPv6len; i++ {
			key[i] = ip[i] & b.mask[i]
		}
		if _, ok := b.nets[string(key[:])]; ok {
			return true
		}
	}
	return false
}

// Add inserts an IP or CIDR into the blocklist. Supports both exact IPs
// (e.g. "10.0.0.1") and CIDR notation (e.g. "10.0.0.0/24").
// IPv4-mapped IPv6 addresses (e.g. "::ffff:10.0.0.1") are normalized
// to their IPv4 form via To4() so they match bare IPv4 entries.
//
// Returns true when this call is what made the entry present, false when
// the entry was rejected (unparseable, whole-address-family, list at
// capacity) or was already present. Callers use the bool to report an
// honest "new entries" count: the pre-R82 signal-free Add let a feed that
// had filled the cap keep logging a healthy refresh while the deny plane
// silently stopped consuming new threat intelligence (R82.2 — the R40.4
// silently-dropped-control doctrine applied to the threat-intel plane).
func (bl *Blocklist) Add(entry string) bool {
	if bl == nil {
		return false
	}
	// R98: normalise ONCE at the single ingest point. Add is the only way an
	// entry reaches the deny plane, so stripping format characters HERE means
	// every present and future caller (a feed line, a static config list, a
	// direct API call) is covered — not just the feed reader (R85/R89:
	// centralise in the component that owns the text). Stripping before the
	// lock keeps the critical section unchanged.
	entry = normalizeEntry(entry)
	bl.mu.Lock()
	defer bl.mu.Unlock()

	// Check total cap
	if len(bl.ips)+bl.netCount >= maxBlocklistEntries {
		if !bl.capWarned {
			bl.capWarned = true
			slog.Warn("threat intel: blocklist at capacity — new entries are being dropped",
				"cap", maxBlocklistEntries, "entries", len(bl.ips)+bl.netCount)
		}
		return false
	}

	if strings.Contains(entry, "/") {
		_, ipnet, err := net.ParseCIDR(entry)
		if err != nil {
			return false
		}
		if wholeFamilyNet(ipnet) {
			if !bl.familyWarned {
				bl.familyWarned = true
				slog.Warn("threat intel: rejecting whole-address-family entry",
					"entry", entry, "canonical", ipnet.String())
			}
			return false
		}
		// Dedup on the canonical form: StartRefresher re-fetches the
		// same feed every interval and old entries are never cleared,
		// so a stable CIDR list re-inserts every network each cycle.
		// Without dedup the index grows monotonically until the cap
		// fills with DUPLICATES — newly discovered threats are then
		// silently dropped by the cap check (R45 — CIDR duplicate
		// accumulation).
		key := ipnet.String()
		if _, dup := bl.netKeys[key]; dup {
			return false
		}
		// Distinct-network cap (R58): bounds stored memory. Since R89 the
		// lookup cost no longer depends on this count (matchNets probes one
		// bucket per occupied prefix length), so the cap is a budget in
		// bytes/IPNet allocations only.
		if bl.netCount >= maxCIDRNetworks {
			if !bl.netCapWarned {
				bl.netCapWarned = true
				slog.Warn("threat intel: CIDR network cap reached — new networks are being dropped",
					"cap", maxCIDRNetworks)
			}
			return false
		}
		bucket, maskedKey := bl.bucketFor(ipnet, true)
		if bucket == nil {
			// Unreachable for ParseCIDR output (wholeFamilyNet already
			// rejects the prefix lengths bucketFor declines); never store an
			// entry the lookup cannot find.
			return false
		}
		if _, dup := bucket.nets[maskedKey]; dup {
			// A different spelling of a network already stored (e.g. the
			// IPv4-mapped alias of a v4 CIDR): it matches exactly the same
			// packets, so record nothing new and keep netCount == len(netKeys).
			return false
		}
		bucket.nets[maskedKey] = ipnet
		bl.netKeys[key] = struct{}{}
		bl.netCount++
		return true
	}

	ip := net.ParseIP(entry)
	if ip == nil {
		return false
	}
	// Normalize IPv4-mapped IPv6 to IPv4 form for consistent matching
	var key string
	if ip4 := ip.To4(); ip4 != nil {
		key = ip4.String()
	} else {
		key = ip.String()
	}
	if _, dup := bl.ips[key]; dup {
		return false
	}
	bl.ips[key] = struct{}{}
	return true
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

	// Check CIDR match — one masked probe per occupied prefix length, so the
	// cost is a property of the address family, not of the feed size (R89).
	return bl.matchNets(ip)
}

// Remove deletes an entry from the blocklist.
func (bl *Blocklist) Remove(entry string) {
	if bl == nil {
		return
	}
	// R99: every mutation of the key space must apply the SAME transform as
	// Add. Add strips the Unicode Cf class (R98), so it stores the canonical
	// form of a spelling net.ParseIP would reject; Remove used the raw string,
	// so an indicator ingested from a BOM/ZWSP-prefixed feed line could never
	// be removed with the spelling the feed supplied — a silently
	// un-removable deny entry (the R41 Add/Remove consistency rule, which R98
	// re-broke for its own class one round later). Remove has no production
	// caller today; the next one must not inherit the asymmetry.
	entry = normalizeEntry(entry)
	bl.mu.Lock()
	defer bl.mu.Unlock()

	if strings.Contains(entry, "/") {
		_, ipnet, err := net.ParseCIDR(entry)
		if err != nil {
			return
		}
		key := ipnet.String()
		if _, ok := bl.netKeys[key]; !ok {
			return
		}
		// Locate the bucket exactly as Add placed the entry (same masked
		// bytes, same prefix length) — no scan of the stored networks.
		bucket, maskedKey := bl.bucketFor(ipnet, false)
		if bucket == nil {
			// Unreachable while the index invariant holds; leave the key so
			// the caller's view of the blocklist does not silently diverge.
			return
		}
		delete(bucket.nets, maskedKey)
		delete(bl.netKeys, key)
		bl.netCount--
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
	return len(bl.ips) + bl.netCount
}

// DataForOPA returns a map suitable for OPA's data store.
// Keys are IP strings, values are true.
func (bl *Blocklist) DataForOPA() map[string]interface{} {
	if bl == nil {
		return nil
	}
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	result := make(map[string]interface{}, len(bl.ips)+bl.netCount)
	for ip := range bl.ips {
		result[ip] = true
	}
	for _, b := range bl.nets4 {
		if b == nil {
			continue
		}
		for _, n := range b.nets {
			result[n.String()] = true
		}
	}
	for _, b := range bl.nets6 {
		if b == nil {
			continue
		}
		for _, n := range b.nets {
			result[n.String()] = true
		}
	}
	return result
}

// FetchFromURL fetches a blocklist from the given URL and adds all entries.
// Returns the number of new entries added. Supports one-IP/CIDR-per-line format.
// Lines starting with # are comments and are ignored.
//
// The URL is trimmed first: this is the function that turns a config string
// into an HTTP request, and net/http refuses a URL with a leading space
// ("first path segment in URL cannot contain colon") or a control character.
// The comma-separated flag value is written by humans
// ("--threat-intel-url https://a/feed, https://b/feed") and a templated value
// can carry a trailing newline, so padding is expected input, not a mistake —
// closing the class here protects the startup loop, the refresher and every
// future caller at once (R93).
func (bl *Blocklist) FetchFromURL(url string) (int, error) {
	url = strings.TrimSpace(url)
	if url == "" {
		return 0, fmt.Errorf("fetching blocklist: empty URL")
	}
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

// ParseURLList splits a comma-separated feed list (the --threat-intel-url
// flag value) into its entries, trimming surrounding whitespace and dropping
// blank entries.
//
// It exists because the flag is written the way a human writes a list —
// "--threat-intel-url https://a/feed, https://b/feed" — and net/http cannot
// parse a URL with a leading space ("first path segment in URL cannot contain
// colon"). cmd/server used to trim each entry only for the startup fetch and
// hand the RAW split slice to StartRefresher, so every entry after the first
// failed on every periodic refresh for the life of the process: the blocklist
// loaded once at boot and then never saw new intelligence again, while the log
// said "threat intel enabled" (R93 — the R40.4 silently-degraded-control class
// on the deny plane). Both the startup loop and the refresher now take their
// entries from here, and blank entries are dropped so an all-blank list starts
// no goroutine at all.
func ParseURLList(raw string) []string {
	return normalizeURLList(strings.Split(raw, ","))
}

// normalizeURLList applies the one per-entry rule to a URL list: trim, drop
// blank. Reached from ParseURLList (the flag), from StartRefresher (a caller's
// slice) and — for the single-string case — from FetchFromURL, so the class is
// closed at every door with one implementation (R85/R89: centralise, do not
// patch each consumer).
func normalizeURLList(urls []string) []string {
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		if u = strings.TrimSpace(u); u != "" {
			out = append(out, u)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// normalizeEntry is the single ingestion transform every mutation of the
// blocklist key space applies — Add (which stores an entry) and Remove (which
// deletes it). Centralised so the two can never drift: R41 established the
// rule for IPv4-mapped forms (Add and Contains normalised, Remove did not),
// and R98's Cf strip was added to Add alone, re-creating exactly that
// asymmetry one round later (R99). Keep it the ONLY place an entry string is
// transformed.
func normalizeEntry(entry string) string {
	return stripFormatChars(entry)
}

// stripFormatChars removes Unicode FORMAT characters (category Cf) from an
// entry or feed line.
//
// strings.TrimSpace strips White_Space only; Cf is a different category, so a
// UTF-8 BOM (U+FEFF) prefixed to an indicator survived the trim and made
// net.ParseIP reject the whole line (R98). The class also includes ZWSP
// (U+200B), ZWNJ/ZWJ (U+200C/U+200D), the word joiner (U+2060) and the bidi
// embedding/override controls — all invisible, none meaningful in an IP or
// CIDR. Removing them before parsing means a feed cannot hide an indicator
// behind an invisible character, and a legitimate BOM-prefixed feed keeps
// every entry.
//
// This runs once per feed line (and once per Add), on a path that must keep up
// with a 50 MB feed, so the common case is a plain ASCII byte scan: every Cf
// codepoint is non-ASCII (the lowest, U+00AD SOFT HYPHEN, encodes as 2 bytes),
// which means an all-ASCII string can never contain one. Only a string with a
// high byte pays for rune decoding — no closure, no allocation otherwise.
func stripFormatChars(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return strings.Map(func(r rune) rune {
				if unicode.Is(unicode.Cf, r) {
					return -1
				}
				return r
			}, s)
		}
	}
	return s
}

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
		// R98: strip Unicode FORMAT characters (category Cf) before trimming.
		// strings.TrimSpace removes White_Space (Zs/Zl/Zp) only, so a UTF-8
		// BOM (U+FEFF, category Cf) in front of an indicator — routine for
		// feeds written by Windows tooling and some exporters — left the line
		// as "\ufeff203.0.113.7", which net.ParseIP rejects: the FIRST
		// indicator of every refresh was dropped with no warning while the
		// refresh still reported a healthy count. The same shape hides one
		// chosen entry per cycle (R82.2 on the deny plane). Stripping the
		// whole Cf class also covers ZWSP (U+200B), ZWNJ/ZWJ (U+200C/D) and
		// the bidi overrides, not just the one character a test happened to
		// use (R16 doctrine: filter the class, not the example).
		lineStr := strings.TrimSpace(stripFormatChars(string(line)))
		if lineStr == "" || strings.HasPrefix(lineStr, "#") {
			if err == io.EOF {
				return count, nil
			}
			continue
		}
		// Count only entries that were actually STORED (R82.2): Add
		// reports false for duplicates, rejected entries and a list at
		// capacity, so the reported count is new intelligence rather than
		// lines parsed. Pre-R82 a cap-filled blocklist logged a healthy
		// "refreshed entries=N" on every cycle while dropping all of them.
		if bl.Add(lineStr) {
			count++
		}
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
	if bl == nil {
		return nil
	}
	// Normalise ONCE at the top (R93): a caller's slice is just as likely to
	// carry padding as the flag string was, and a padded entry would fail
	// every refresh forever. An all-blank list starts no goroutine at all
	// rather than a permanent doomed fetch loop that also reads as "the
	// refresher is running".
	urls = normalizeURLList(urls)
	if len(urls) == 0 {
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
						// R88: the refresher runs for the life of the process,
						// so this is the line that actually leaks. A feed URL is
						// a bearer credential (?auth_key=…), and the error text
						// carries it twice — FetchFromURL wraps it and net/http
						// repeats it inside *url.Error. Both must be redacted
						// here, not only in cmd/server's startup loop (R87).
						slog.Warn("threat intel refresh failed",
							"url", redact.URL(url),
							"error", redact.ScrubIn(err.Error(), url))
					} else {
						slog.Info("threat intel refreshed", "url", redact.URL(url), "entries", count)
					}
				}
			}
		}
	}()
	return stopCh
}
