package l2filter

import (
	"sync"
	"testing"
)

// ── R11.1: ARP table growth bounded by MaxARPEntries ───────────────
// R11 documented unbounded growth; R12 added the cap (defaultMaxARPEntries).
// R41: converted to a hard assertion proving the cap is enforced — the old
// "no size cap enforced" log described pre-R12 behavior and was stale.
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

	if size > f.maxARP {
		t.Errorf("arpTable grew to %d entries — cap (%d) not enforced (inserted %d)", size, f.maxARP, entries)
	} else {
		t.Logf("FIXED (R12): arpTable capped at %d entries (max %d, inserted %d)", size, f.maxARP, entries)
	}

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

	if size2 > f2.maxARP {
		t.Errorf("CheckARP learning mode: arpTable grew to %d entries — cap (%d) not enforced", size2, f2.maxARP)
	} else {
		t.Logf("FIXED (R12): CheckARP learning capped at %d entries (max %d)", size2, f2.maxARP)
	}
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
