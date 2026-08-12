package threatintel

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// ── R9.17: StartRefresher with zero interval panics ────────────────────
// time.NewTicker(0) panics with "non-positive interval for NewTicker".
// If someone passes 0 as the interval (or a negative value), the ticker
// panics, crashing the process.
func TestAttack_StartRefresherZeroInterval(t *testing.T) {
	bl := NewBlocklist()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("10.0.0.1\n"))
	}))
	defer server.Close()

	recovered := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				recovered = true
			}
		}()
		stopCh := bl.StartRefresher([]string{server.URL}, 0)
		if stopCh != nil {
			defer close(stopCh)
		}
	}()

	if recovered {
		t.Error("StartRefresher with 0 interval panicked — needs minimum interval guard for time.NewTicker")
	} else {
		t.Log("StartRefresher with 0 interval did not panic")
	}

	// Also test with negative interval
	recovered = false
	func() {
		defer func() {
			if r := recover(); r != nil {
				recovered = true
			}
		}()
		stopCh := bl.StartRefresher([]string{server.URL}, -1*time.Second)
		if stopCh != nil {
			defer close(stopCh)
		}
	}()

	if recovered {
		t.Error("StartRefresher with negative interval panicked — needs minimum interval guard")
	} else {
		t.Log("StartRefresher with negative interval did not panic")
	}
}

// ── R9.18: StartRefresher double-close prevention ─────────────────────
// StartRefresher now returns a fresh channel per call. If the caller closes
// their own channel twice, Go still panics (cannot close a raw channel
// twice), but the fix ensures multiple StartRefresher calls don't share
// the same internal stopCh. Each goroutine has its own stop channel so
// closing one doesn't affect others.
func TestAttack_StartRefresherDoubleClosePanic(t *testing.T) {
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("10.0.0.1\n"))
	}))
	defer server1.Close()
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("10.0.0.2\n"))
	}))
	defer server2.Close()

	bl := NewBlocklist()

	// Two StartRefresher calls return different channels
	stopCh1 := bl.StartRefresher([]string{server1.URL}, 100*time.Millisecond)
	stopCh2 := bl.StartRefresher([]string{server2.URL}, 100*time.Millisecond)

	if stopCh1 == nil {
		t.Fatal("StartRefresher returned nil stopCh1")
	}
	if stopCh2 == nil {
		t.Fatal("StartRefresher returned nil stopCh2")
	}
	if stopCh1 == stopCh2 {
		t.Error("StartRefresher returned the same channel twice — should return fresh channel per call")
	}

	// Close each once — should not panic
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("first close panicked: %v", r)
			}
		}()
		close(stopCh1)
	}()

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("first close panicked: %v", r)
			}
		}()
		close(stopCh2)
	}()

	t.Log("Two StartRefresher calls returned different channels — closing each once did not panic")
}

// ── R9.19: FetchFromURL with no timeout on slow server ─────────────────
// FetchFromURL creates an HTTP client with 30s timeout, but the HTTP
// transport's TLS handshake or response header timeout could still hang
// for 30s. This is by design, but we verify it doesn't hang forever.
func TestAttack_FetchFromURLSlowServer(t *testing.T) {
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a slow response — delay before first byte
		time.Sleep(50 * time.Millisecond)
		w.Write([]byte("10.0.0.1\n"))
	}))
	defer slowServer.Close()

	bl := NewBlocklist()
	done := make(chan struct{})
	go func() {
		_, err := bl.FetchFromURL(slowServer.URL)
		if err != nil {
			t.Logf("FetchFromURL from slow server: %v", err)
		} else {
			t.Log("FetchFromURL completed from slow server")
		}
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(5 * time.Second):
		t.Error("FetchFromURL hung on slow server — timeout not enforced")
	}
}

// ── R9.20: Concurrent Add and Contains with CIDR ───────────────────────
// Adding CIDR entries while concurrently checking Contains should not race.
func TestAttack_ConcurrentAddCIDRAndContains(t *testing.T) {
	bl := NewBlocklist()
	bl.Add("10.0.0.0/8")

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ip := "10.0." + itoa(n%256) + "." + itoa((n*7)%256)
			bl.Contains(ip)
		}(i)
	}

	// Add more CIDRs concurrently
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			cidr := "192.168." + itoa(n) + ".0/24"
			bl.Add(cidr)
		}(i)
	}

	wg.Wait()
	t.Log("Concurrent Add CIDR and Contains completed without race")
}

// ── R9.21: Contains with IPv6 in a mixed IPv4/IPv6 blocklist ──────────
// Ensure IPv6 addresses can be added and checked correctly.
func TestAttack_ContainsIPv6(t *testing.T) {
	bl := NewBlocklist()

	// Add an IPv6 address
	bl.Add("2001:db8::1")
	bl.Add("fe80::1")

	// Check IPv6
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"exact IPv6 match", "2001:db8::1", true},
		{"explicit IPv6", "2001:0db8:0000:0000:0000:0000:0000:0001", true},
		{"not present", "2001:db8::2", false},
		{"link-local match", "fe80::1", true},
		{"link-local not present", "fe80::2", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bl.Contains(tt.ip)
			if got != tt.want {
				t.Errorf("Contains(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

// ── R9.22: DataForOPA snapshot reflects current state even after adds ──
// DataForOPA acquires a read lock and copies data. After release, the
// returned map is a snapshot (already tested in R6.20).
func TestAttack_DataForOPASnapshotWithCIDR(t *testing.T) {
	bl := NewBlocklist()
	bl.Add("10.0.0.0/8")

	data := bl.DataForOPA()
	if len(data) != 1 {
		t.Errorf("expected 1 entry in snapshot, got %d", len(data))
	}

	// Modify the blocklist
	bl.Add("192.168.0.0/16")

	// Snapshot must not include the new CIDR
	if _, exists := data["192.168.0.0/16"]; exists {
		t.Error("DataForOPA snapshot includes CIDR added after snapshot was taken")
	}
	t.Log("DataForOPA snapshot correctly excludes CIDR added after snapshot")
}
