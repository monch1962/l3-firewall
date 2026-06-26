package conntrack

import (
	"sync"
	"testing"
	"time"
)

func TestPerProtocolTimeouts(t *testing.T) {
	cfg := Config{
		MaxEntries:     1000,
		IdleTimeout:    300 * time.Second, // TCP default
		UDPTimeout:     30 * time.Second,
		ICMPTimeout:    5 * time.Second,
		PortScanMaxPorts: 100,
	}
	ct := NewTable(cfg)

	ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "TCP", 44001, 443)
	ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "UDP", 44002, 53)
	ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "ICMP", 0, 0)

	if ct.Len() != 3 {
		t.Errorf("Len = %d, want 3", ct.Len())
	}
}

func TestExpireByProtocolTCP(t *testing.T) {
	cfg := Config{
		MaxEntries:     1000,
		IdleTimeout:    300 * time.Second,
		UDPTimeout:     30 * time.Second,
		ICMPTimeout:    5 * time.Second,
		PortScanMaxPorts: 100,
	}
	ct := NewTable(cfg)
	ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "TCP", 44001, 443)
	// Use Expire() which respects protocol-specific timeout (300s).
	// A just-created TCP flow should not expire.
	expired := ct.Expire()
	if expired != 0 {
		t.Errorf("Expire() expired TCP = %d, want 0 (TCP timeout is 300s)", expired)
	}
}

func TestExpireUDPFast(t *testing.T) {
	cfg := Config{
		MaxEntries:     1000,
		IdleTimeout:    300 * time.Second,
		UDPTimeout:     1 * time.Millisecond,
		ICMPTimeout:    5 * time.Second,
		PortScanMaxPorts: 100,
	}
	ct := NewTable(cfg)
	ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "UDP", 44002, 53)
	time.Sleep(2 * time.Millisecond)
	expired := ct.Expire()
	if expired != 1 {
		t.Errorf("UDP expired = %d, want 1 (UDP timeout is 1ms)", expired)
	}
}

func TestExpireICMPFast(t *testing.T) {
	cfg := Config{
		MaxEntries:     1000,
		IdleTimeout:    300 * time.Second,
		UDPTimeout:     30 * time.Second,
		ICMPTimeout:    1 * time.Millisecond,
		PortScanMaxPorts: 100,
	}
	ct := NewTable(cfg)
	ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "ICMP", 0, 0)
	time.Sleep(2 * time.Millisecond)
	expired := ct.Expire()
	if expired != 1 {
		t.Errorf("ICMP expired = %d, want 1 (ICMP timeout is 1ms)", expired)
	}
}

func TestDefaultTimeouts(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.UDPTimeout != 30*time.Second {
		t.Errorf("UDPTimeout = %v, want 30s", cfg.UDPTimeout)
	}
	if cfg.ICMPTimeout != 5*time.Second {
		t.Errorf("ICMPTimeout = %v, want 5s", cfg.ICMPTimeout)
	}
}

func TestConcurrentNewConnections(t *testing.T) {
	ct := NewTable(DefaultConfig())
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			f := ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "TCP",
				uint16(44000+n), uint16(80+n%10))
			if n%5 == 0 {
				f.SetEstablished()
			}
		}(i)
	}
	wg.Wait()
	if ct.Len() != 50 {
		t.Errorf("Len = %d, want 50", ct.Len())
	}
}

func TestLookupOrCreateStats(t *testing.T) {
	ct := NewTable(DefaultConfig())
	ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "TCP", 44001, 443)
	s := ct.Stats()
	if s.Created != 1 {
		t.Errorf("Created = %d, want 1", s.Created)
	}
	ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "TCP", 44001, 443)
	s = ct.Stats()
	if s.Hits != 1 {
		t.Errorf("Hits = %d, want 1", s.Hits)
	}
	if s.Created != 1 {
		t.Errorf("Created = %d, want 1 (still 1 after hit)", s.Created)
	}
}

func TestExpireStats(t *testing.T) {
	cfg := Config{
		MaxEntries:     1000,
		IdleTimeout:    300 * time.Second,
		UDPTimeout:     30 * time.Second,
		ICMPTimeout:    1 * time.Millisecond,
		PortScanMaxPorts: 100,
	}
	ct := NewTable(cfg)
	ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "ICMP", 0, 0)
	time.Sleep(2 * time.Millisecond)
	ct.Expire()
	s := ct.Stats()
	if s.Expired != 1 {
		t.Errorf("Expired = %d, want 1", s.Expired)
	}
}

func TestNewConnectionRate(t *testing.T) {
	ct := NewTable(DefaultConfig())
	ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "TCP", 44001, 443)
	ct.LookupOrCreate("10.0.1.100", "10.0.2.51", "TCP", 44002, 80)
	ct.LookupOrCreate("10.0.1.100", "10.0.2.52", "TCP", 44003, 443)

	rate := ct.NewConnectionRate()
	if rate <= 0 {
		t.Errorf("NewConnectionRate = %f, want > 0", rate)
	}
}
