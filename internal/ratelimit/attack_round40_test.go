package ratelimit

import (
	"fmt"
	"testing"
	"time"
)

// ── R40.1: IPv4-mapped IPv6 aliases split per-IP rate budgets ──────
// Bucket keys are built from the raw source-IP string. The same logical
// source can be addressed as "10.0.0.1" (IPv4) and "::ffff:10.0.0.1"
// (IPv4-mapped IPv6), producing two distinct keys — and two independent
// EWMA rate budgets — for one attacker. Each representation stays under
// the OPA rate threshold while the combined traffic exceeds it (R10 class:
// IPv4-mapped IPv6 bypass, re-applied to the rate limiter key space).
func TestAttack_IPv4MappedAlias_SplitsRateBudget(t *testing.T) {
	l := NewLimiter(0, 0)

	l.Allow("10.0.0.1", 100)
	l.Allow("::ffff:10.0.0.1", 100)

	if n := l.Len(); n != 1 {
		t.Errorf("IPv4-mapped alias created %d rate buckets for one source IP; want 1 (same budget)", n)
	}

	// Same check for the per-destination-port key space.
	l2 := NewLimiter(0, 0)
	l2.AllowPort("10.0.0.1", 80, 100)
	l2.AllowPort("::ffff:10.0.0.1", 80, 100)
	if n := l2.Len(); n != 1 {
		t.Errorf("IPv4-mapped alias created %d port buckets for one source IP:port; want 1", n)
	}
}

// ── R40.2: O(n) eviction scan amplifies CPU in the packet hot path ──
// When the bucket map is at MaxEntries, every new-key insertion scans the
// ENTIRE map under the write lock to find the oldest entry. An attacker
// churning unique (spoofed srcIP, dstPort) keys forces a full-map scan on
// every packet — O(n) work in the NFQUEUE hot path, serializing all
// rate-limit processing (the mutex is held during the scan).
//
// The ratio of insert-at-capacity cost to insert-into-empty-map cost is
// machine-independent: pre-fix it scales with the map size (~40k), post-fix
// it is bounded by the eviction sample size (~16).
func TestAttack_EvictionScan_CPUAmplification(t *testing.T) {
	const capacity = 40000
	const churnKeys = 5000

	l := NewLimiter(0, 0)
	l.MaxEntries = capacity
	for i := 0; i < capacity; i++ {
		l.Allow(fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff), 64)
	}

	// Baseline: cost of inserting churnKeys into an empty map (no eviction).
	empty := NewLimiter(0, 0)
	t0 := time.Now()
	for k := 0; k < churnKeys; k++ {
		empty.Allow(fmt.Sprintf("192.168.%d.%d", k>>8, k&0xff), 64)
	}
	baseline := time.Since(t0)
	if baseline <= 0 {
		baseline = time.Nanosecond
	}

	// Attack: keep inserting NEW keys while at capacity — each triggers an
	// eviction. Pre-fix every eviction scans all `capacity` entries.
	t1 := time.Now()
	for k := 0; k < churnKeys; k++ {
		l.Allow(fmt.Sprintf("192.168.%d.%d", k>>8, k&0xff), 64)
	}
	churn := time.Since(t1)

	ratio := float64(churn) / float64(baseline)
	t.Logf("baseline=%v churn=%v ratio=%.1f (capacity=%d)", baseline, churn, ratio, capacity)
	if ratio > 500 {
		t.Errorf("insert-at-capacity cost %.0fx an empty-map insert — O(n) eviction scan under write lock in hot path", ratio)
	}
}

// ── R40.2 companion: eviction must keep the map bounded under churn ──
// The eviction fix must not regress the R2/R4 memory cap: after sustained
// churn at capacity, the bucket count stays <= MaxEntries.
func TestAttack_EvictionKeepsMapBounded(t *testing.T) {
	const capacity = 1000
	l := NewLimiter(0, 0)
	l.MaxEntries = capacity
	for i := 0; i < capacity; i++ {
		l.Allow(fmt.Sprintf("10.0.%d.%d", i>>8, i&0xff), 64)
	}
	for k := 0; k < 5000; k++ {
		l.Allow(fmt.Sprintf("192.168.%d.%d", k>>8, k&0xff), 64)
	}
	if n := l.Len(); n > capacity {
		t.Errorf("bucket map grew to %d entries (cap %d) under churn — memory cap broken", n, capacity)
	}
}
