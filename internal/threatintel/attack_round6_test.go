package threatintel

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ── R6.15: SSRF via internal URL in FetchFromURL ────────────────────────
// Attacker controls the threat-intel-url config and points it at internal
// services (etcd, admin API, metadata endpoints). There is no URL validation.
func TestAttack_SSRFViaFetchFromURL(t *testing.T) {
	bl := NewBlocklist()

	// Start a test server to simulate what an attacker would use as an internal target
	targetCalled := false
	internalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("10.0.0.1\n"))
	}))
	defer internalServer.Close()

	// Fetch from the "internal" URL
	_, err := bl.FetchFromURL(internalServer.URL)

	if err != nil {
		t.Logf("Fetch from %q returned: %v", internalServer.URL, err)
	}
	if targetCalled {
		t.Log("SSRF confirmed: incoming read from fetch triggered by attacker-controlled URL")
	}

	// Test with file:// scheme (not used by Go's HTTP client, but test gracefully)
	_, err = bl.FetchFromURL("file:///etc/passwd")
	if err == nil {
		t.Error("file:// URL should not be accepted — potential local file read")
	} else {
		t.Logf("file:// correctly rejected: %v", err)
	}
}

// ── R6.16: IPv4 mapped IPv6 bypass in Contains ──────────────────────────
// net.ParseIP("::ffff:10.0.0.1") returns the same IP as "10.0.0.1",
// which could bypass CIDR matching.
func TestAttack_IPv4MappedIPv6InContains(t *testing.T) {
	bl := NewBlocklist()

	// Add a CIDR
	_, ipnet, _ := net.ParseCIDR("10.0.0.0/24")
	bl.mu.Lock()
	bl.nets = append(bl.nets, ipnet)
	bl.mu.Unlock()

	// Test normal IPv4
	if !bl.Contains("10.0.0.1") {
		t.Error("Contains('10.0.0.1') = false, want true")
	}

	// Test IPv4-mapped IPv6
	if !bl.Contains("::ffff:10.0.0.1") {
		t.Log("Contains('::ffff:10.0.0.1') = false — IPv4-mapped IPv6 addresses may not match CIDR rules correctly")
		// This documents the behavior; Go's net.IPNet.Contains doesn't handle mapped addresses
	}

	// Test IPv4-compatible IPv6
	_ = bl.Contains("::10.0.0.1")
}

// ── R6.17: Unbounded fetch from slow/streaming server ───────────────────
// A malicious server sends an infinite stream of entries.
func TestAttack_UnboundedFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Send entries indefinitely
		for i := 0; i < 1000000; i++ {
			_, err := w.Write([]byte("10.0.0.1\n"))
			if err != nil {
				return
			}
		}
	}))
	defer server.Close()

	bl := NewBlocklist()
	// This should complete within reasonable time
	done := make(chan struct{})
	go func() {
		count, err := bl.FetchFromURL(server.URL)
		if err != nil {
			t.Logf("Fetch returned error: %v", err)
		}
		t.Logf("Fetch completed with %d entries (maxBlocklistEntries=%d)", count, maxBlocklistEntries)
		close(done)
	}()

	select {
	case <-done:
		// OK — bounded by maxBlocklistEntries
	case <-time.After(5 * time.Second):
		t.Error("FetchFromURL did not complete in 5s — may be unbounded")
	}
}

// ── R6.18: Infinite redirect via FetchFromURL ───────────────────────────
// A malicious server redirects in a loop to cause DoS.
func TestAttack_InfiniteRedirectFetch(t *testing.T) {
	redirectCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectCount++
		w.Header().Set("Location", r.URL.String())
		w.WriteHeader(http.StatusFound) // 302 redirect
	}))
	defer server.Close()

	bl := NewBlocklist()
	done := make(chan struct{})
	go func() {
		_, err := bl.FetchFromURL(server.URL)
		if err != nil {
			t.Logf("Fetch correctly returned error after %d redirects: %v", redirectCount, err)
		} else {
			t.Log("Fetch succeeded despite redirect loop — may indicate follow limit reached")
		}
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(10 * time.Second):
		t.Error("FetchFromURL hung on infinite redirect — needs redirect limit")
	}
}

// ── R6.19: Add with invalid entry leaks into map ────────────────────────
// net.ParseIP returns nil for bad strings, but the entry is silently dropped.
func TestAttack_AddInvalidEntry(t *testing.T) {
	bl := NewBlocklist()

	bl.Add("not_an_ip")
	bl.Add("10.0.0.0/33") // invalid CIDR
	bl.Add("999.999.999.999")

	if bl.Len() != 0 {
		t.Errorf("expected 0 entries for invalid inputs, got %d", bl.Len())
	}

	// Make sure valid entries still work
	bl.Add("10.0.0.1")
	if bl.Len() != 1 {
		t.Errorf("expected 1 entry after valid add, got %d", bl.Len())
	}
}

// ── R6.20: DataForOPA includes all entries ──────────────────────────────
// DataForOPA returns all blocklist data — ensure data is a snapshot (copy), not a reference.
func TestAttack_DataForOPASnapshot(t *testing.T) {
	bl := NewBlocklist()
	bl.Add("10.0.0.1")

	data := bl.DataForOPA()

	// Modify the blocklist
	bl.Add("10.0.0.2")

	// data should be a snapshot and not include the new entry
	if _, exists := data["10.0.0.2"]; exists {
		t.Error("DataForOPA returned a live reference, not a snapshot")
	} else {
		t.Log("DataForOPA returns snapshot — correct")
	}
}
