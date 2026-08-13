package engine

import (
	"context"
	"sync"
	"testing"
)

// ── R50: Engine stats counters + running flag data race ──────────
// The NFQUEUE hot path (go-nfqueue's internal callback goroutine →
// packetHandler → evaluatePacket) increments packetsProcessed /
// packetsAllowed / packetsBlocked with plain non-atomic `++` on
// int64 fields, and Run() writes the plain `running` bool. The
// admin API HTTP goroutine reads all four via Stats()/Running()
// on every /admin/health and /admin/stats request.
//
// With the default configuration (no --admin-token / --admin-read-
// token) the admin API is UNAUTHENTICATED (R46), so any network
// peer can race the counters while traffic flows: a remotely
// triggerable data race (R46 policyVersions class).
//
// No prior round exercised this: every prior test calls
// evaluatePacket or Stats() from a single goroutine, so `-race`
// stays green while production races. This test drives the hot
// path concurrently with the admin reads.
func TestAttack_ConcurrentStatsReadDuringHotPath(t *testing.T) {
	eng := newTestEngine(t)
	pi := buildTestPacket("10.0.1.100", "10.0.2.50", 44001, 443, true, false)

	var wg sync.WaitGroup

	// NFQUEUE callback goroutine: the hot path. Simulates go-nfqueue's
	// internal receive loop invoking packetHandler on its own goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			eng.evaluatePacket(pi, 64)
		}
	}()

	// Admin API goroutine: reads the counters on every stats request.
	for i := 0; i < 2000; i++ {
		s := eng.Stats()
		_ = s.PacketsProcessed + s.PacketsAllowed + s.PacketsBlocked
		_ = eng.Running()
	}

	wg.Wait()
}

// ── R50: running flag race between Run() and Running() ─────────────
// Run() writes e.running on the main goroutine; admin handlers read
// it concurrently via Running(). The write is a plain bool store with
// no synchronization — a torn/stale read is a data race (visible to
// -race and undefined under the Go memory model).
func TestAttack_ConcurrentRunningFlagRace(t *testing.T) {
	eng := newTestEngine(t)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		// Simulate Run() flipping the lifecycle flag while the admin
		// server is serving /admin/health.
		for i := 0; i < 2000; i++ {
			eng.running.Store(i%2 == 0)
		}
	}()

	for i := 0; i < 2000; i++ {
		_ = eng.Running()
	}

	wg.Wait()
}

// ── R50: cancel/ctx lifecycle race between Run() and Stop() ────────
// Run() writes e.ctx/e.cancel on the main goroutine while the signal
// handler goroutine calls Stop() (cmd/server/main.go) which reads
// e.cancel. A SIGTERM arriving during Run's startup window races the
// field write; if Stop() reads nil, the cancel is never invoked and
// Run() blocks forever at <-ctx.Done() — a shutdown hang (R42/R46
// no-deadline class, same plain-field race as the counters).
func TestAttack_ConcurrentStopDuringRunStartup(t *testing.T) {
	eng := newTestEngine(t)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		// Simulate Run() assigning the lifecycle fields on the main
		// goroutine while the signal handler calls Stop().
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		for i := 0; i < 2000; i++ {
			eng.setLifecycle(ctx, cancel)
		}
	}()

	for i := 0; i < 2000; i++ {
		eng.Stop()
	}

	wg.Wait()
}
