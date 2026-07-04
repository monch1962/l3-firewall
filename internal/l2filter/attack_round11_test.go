package l2filter

import (
	"sync"
	"testing"
)

// ── R11.1: Unbounded ARP table growth (memory exhaustion) ───────────
// RecordDHCP and CheckARP both add entries to arpTable without any cap.
// An attacker sending many unique IP→MAC bindings could exhaust memory.
func TestAttack_UnboundedARPTableGrowth(t *testing.T) {
	f := NewFilter(Config{EnableDHCPCheck: true})

	const entries = 100000

	// Fill arpTable with unique IP→MAC bindings via RecordDHCP
	for i := 0; i < entries; i++ {
		ip := "10.0.0." + itoa(i)
		mac := "aa:bb:cc:dd:ee:" + itoa(i%256)
		f.RecordDHCP(ip, mac)
	}

	f.mu.RLock()
	size := len(f.arpTable)
	f.mu.RUnlock()

	t.Logf("arpTable grew to %d entries — no size cap enforced (inserted %d)", size, entries)

	// Also test via CheckARP (learning mode)
	f2 := NewFilter(Config{EnableARPCheck: true})
	for i := 0; i < entries; i++ {
		ip := "192.168.0." + itoa(i%256)
		mac := "aa:bb:cc:dd:ff:" + itoa(i%256)
		f2.CheckARP(ip, mac)
	}

	f2.mu.RLock()
	size2 := len(f2.arpTable)
	f2.mu.RUnlock()

	t.Logf("CheckARP learning mode: arpTable grew to %d entries — no size cap enforced (inserted %d)", size2, entries)
}

// ── R11.2: Concurrent ARP table writes with many unique IPs ────────
// Concurrent callers adding many unique IPs should not race on arpTable.
// Tests the existing mutex protects the map under concurrent load.
func TestAttack_ConcurrentARPTableGrowth(t *testing.T) {
	f := NewFilter(Config{EnableARPCheck: true})

	var wg sync.WaitGroup
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				ip := "10." + itoa(goroutineID) + "." + itoa(i/256) + "." + itoa(i%256)
				mac := "aa:bb:cc:dd:ee:" + itoa(i%256)
				f.CheckARP(ip, mac)
			}
		}(g)
	}
	wg.Wait()

	f.mu.RLock()
	size := len(f.arpTable)
	f.mu.RUnlock()
	t.Logf("Concurrent growth: arpTable has %d entries after 10 goroutines x 1000 unique IPs", size)
}
