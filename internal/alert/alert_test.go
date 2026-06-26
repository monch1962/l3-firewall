package alert

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestAlertTypeString(t *testing.T) {
	tests := []struct {
		at   AlertType
		want string
	}{
		{AlertBlockRate, "block_rate"},
		{AlertPortScan, "port_scan"},
		{AlertConnLimit, "connection_limit"},
		{AlertOPAError, "opa_error"},
		{AlertRateLimit, "rate_limit"},
		{AlertType(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.at.String(); got != tt.want {
			t.Errorf("AlertType(%d).String() = %q, want %q", tt.at, got, tt.want)
		}
	}
}

func TestNewRouterDefaults(t *testing.T) {
	r := NewRouter(Config{WebhookURL: "http://example.com/hook"})
	if r == nil {
		t.Fatal("NewRouter returned nil")
	}
	if r.cfg.Cooldown != 30*time.Second {
		t.Errorf("Cooldown = %v, want 30s", r.cfg.Cooldown)
	}
}

func TestSendNoWebhookURL(t *testing.T) {
	r := NewRouter(Config{WebhookURL: ""})
	// Should not panic
	r.Send(AlertEvent{Type: AlertBlockRate, Message: "test"})
}

func TestSendFiresWebhook(t *testing.T) {
	var mu sync.Mutex
	var received []byte
	var httpWg sync.WaitGroup
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		received = buf
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		httpWg.Done()
	}))
	defer server.Close()

	r := NewRouter(Config{WebhookURL: server.URL, Cooldown: 10 * time.Millisecond})
	httpWg.Add(1)
	r.Send(AlertEvent{
		Type:      AlertBlockRate,
		Message:   "block rate exceeded: 500 packets/sec",
		Source:    "engine",
		Timestamp: time.Now(),
	})
	httpWg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if received == nil {
		t.Fatal("no webhook was fired")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if payload["type"] != "block_rate" {
		t.Errorf("type = %v, want block_rate", payload["type"])
	}
	if payload["message"] != "block rate exceeded: 500 packets/sec" {
		t.Errorf("message = %v, want 'block rate exceeded...'", payload["message"])
	}
	if payload["source"] != "engine" {
		t.Errorf("source = %v, want engine", payload["source"])
	}
}

func TestCooldownSuppressesDuplicate(t *testing.T) {
	var callCount int
	var mu sync.Mutex
	var httpWg sync.WaitGroup
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		httpWg.Done()
	}))
	defer server.Close()

	r := NewRouter(Config{WebhookURL: server.URL, Cooldown: 5 * time.Second})

	// First send should fire
	httpWg.Add(1)
	r.Send(AlertEvent{Type: AlertBlockRate, Message: "first"})
	httpWg.Wait()

	// Second send (same type, within cooldown) should be suppressed
	r.Send(AlertEvent{Type: AlertBlockRate, Message: "second"})
	time.Sleep(50 * time.Millisecond) // small window for any async activity

	mu.Lock()
	if callCount != 1 {
		t.Errorf("callCount = %d, want 1 (second should be suppressed by cooldown)", callCount)
	}
	mu.Unlock()
}

func TestDifferentTypesNotSuppressed(t *testing.T) {
	var callCount int
	var mu sync.Mutex
	var httpWg sync.WaitGroup
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		httpWg.Done()
	}))
	defer server.Close()

	r := NewRouter(Config{WebhookURL: server.URL, Cooldown: 5 * time.Second})

	httpWg.Add(3)
	r.Send(AlertEvent{Type: AlertBlockRate, Message: "block rate"})
	r.Send(AlertEvent{Type: AlertPortScan, Message: "port scan"})
	r.Send(AlertEvent{Type: AlertConnLimit, Message: "conn limit"})
	httpWg.Wait()

	mu.Lock()
	if callCount != 3 {
		t.Errorf("callCount = %d, want 3 (different types should not be suppressed)", callCount)
	}
	mu.Unlock()
}

func TestSendAsyncDoesNotBlock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond) // slow server
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	r := NewRouter(Config{WebhookURL: server.URL, Cooldown: 0})

	start := time.Now()
	r.Send(AlertEvent{Type: AlertBlockRate, Message: "test"})
	elapsed := time.Since(start)

	if elapsed > 10*time.Millisecond {
		t.Errorf("Send blocked for %v, should return immediately (async)", elapsed)
	}
}

func TestSendNoPanicOnNilRouter(t *testing.T) {
	var r *Router
	r.Send(AlertEvent{Type: AlertBlockRate, Message: "test"}) // should not panic
}

func TestConcurrentSend(t *testing.T) {
	// Use httptest with keep-alive disabled to avoid connection reuse deadlocks
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	r := NewRouter(Config{WebhookURL: server.URL, Cooldown: 0})
	// Disable keep-alive so each POST is a unique connection
	r.client.Transport = &http.Transport{
		DisableKeepAlives: true,
	}

	for i := 0; i < 5; i++ {
		r.Send(AlertEvent{
			Type:    AlertType(i % 3),
			Message: "test",
		})
	}

	// Give async goroutines time to complete their HTTP POSTs
	time.Sleep(500 * time.Millisecond)

	// Pass — the important thing is no panics/data races from concurrent Send()
	// HTTP delivery is best-effort by design
}
