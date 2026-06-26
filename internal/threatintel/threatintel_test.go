package threatintel

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestNewBlocklist(t *testing.T) {
	bl := NewBlocklist()
	if bl == nil {
		t.Fatal("NewBlocklist returned nil")
	}
	if bl.Len() != 0 {
		t.Errorf("initial Len = %d, want 0", bl.Len())
	}
}

func TestAddContains(t *testing.T) {
	bl := NewBlocklist()
	bl.Add("10.0.0.1")
	if !bl.Contains("10.0.0.1") {
		t.Error("Contains('10.0.0.1') = false, want true")
	}
	if bl.Contains("10.0.0.2") {
		t.Error("Contains('10.0.0.2') = true, want false")
	}
	if bl.Len() != 1 {
		t.Errorf("Len = %d, want 1", bl.Len())
	}
}

func TestAddDuplicate(t *testing.T) {
	bl := NewBlocklist()
	bl.Add("10.0.0.1")
	bl.Add("10.0.0.1")
	if bl.Len() != 1 {
		t.Errorf("Len = %d, want 1 (duplicate not counted)", bl.Len())
	}
}

func TestAddCIDR(t *testing.T) {
	bl := NewBlocklist()
	bl.Add("10.0.0.0/24")
	if !bl.Contains("10.0.0.1") {
		t.Error("Contains('10.0.0.1') = false, want true (within 10.0.0.0/24)")
	}
	if bl.Contains("10.0.1.1") {
		t.Error("Contains('10.0.1.1') = true, want false (outside 10.0.0.0/24)")
	}
}

func TestRemove(t *testing.T) {
	bl := NewBlocklist()
	bl.Add("10.0.0.1")
	bl.Remove("10.0.0.1")
	if bl.Contains("10.0.0.1") {
		t.Error("Contains after Remove = true, want false")
	}
	if bl.Len() != 0 {
		t.Errorf("Len after Remove = %d, want 0", bl.Len())
	}
}

func TestRemoveNonexistent(t *testing.T) {
	bl := NewBlocklist()
	bl.Remove("10.0.0.1") // should not panic
}

func TestConcurrentAccess(t *testing.T) {
	bl := NewBlocklist()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ip := "10.0.0.1"
			bl.Add(ip)
			bl.Contains(ip)
			bl.Remove(ip)
		}(i)
	}
	wg.Wait()
}

func TestFetchFromURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("10.0.0.1\n10.0.0.2\n192.168.1.0/24\n# comment line\n10.0.0.3\n"))
	}))
	defer server.Close()

	bl := NewBlocklist()
	count, err := bl.FetchFromURL(server.URL)
	if err != nil {
		t.Fatalf("FetchFromURL: %v", err)
	}
	if count != 4 {
		t.Errorf("count = %d, want 4", count)
	}
	if !bl.Contains("10.0.0.1") {
		t.Error("missing 10.0.0.1")
	}
	if !bl.Contains("192.168.1.1") {
		t.Error("missing 192.168.1.1 (CIDR)")
	}
	if bl.Contains("10.0.0.99") {
		// Not in the list
	}
}

func TestFetchFromURLInvalidURL(t *testing.T) {
	bl := NewBlocklist()
	_, err := bl.FetchFromURL("http://nonexistent.example.invalid/blocklist.txt")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestFetchFromURLServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	bl := NewBlocklist()
	_, err := bl.FetchFromURL(server.URL)
	if err == nil {
		t.Error("expected error for 500 status")
	}
}

func TestStartRefresherInterval(t *testing.T) {
	callCount := 0
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()
		w.Write([]byte("10.0.0.1\n"))
	}))
	defer server.Close()

	bl := NewBlocklist()
	stop := bl.StartRefresher([]string{server.URL}, 50*time.Millisecond)
	defer close(stop)

	time.Sleep(120 * time.Millisecond)
	mu.Lock()
	cc := callCount
	mu.Unlock()

	if cc < 2 {
		t.Errorf("expected at least 2 fetches, got %d", cc)
	}
	if !bl.Contains("10.0.0.1") {
		t.Error("blocklist should contain 10.0.0.1 after refresh")
	}
}

func TestContainsNilBlocklist(t *testing.T) {
	var bl *Blocklist
	if bl.Contains("10.0.0.1") {
		t.Error("nil blocklist should not contain anything")
	}
}

func TestDataForOPA(t *testing.T) {
	bl := NewBlocklist()
	bl.Add("10.0.0.1")
	bl.Add("10.0.0.2")
	bl.Add("192.168.0.0/16")

	data := bl.DataForOPA()
	if data == nil {
		t.Fatal("DataForOPA returned nil")
	}
	if !data["10.0.0.1"].(bool) {
		t.Error("expected 10.0.0.1 in OPA data")
	}
}
