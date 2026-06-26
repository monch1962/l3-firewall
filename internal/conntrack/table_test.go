package conntrack

import (
	"sync"
	"testing"
	"time"
)

func TestNewTable(t *testing.T) {
	cfg := Config{
		MaxEntries:  1000,
		IdleTimeout: 60 * time.Second,
	}
	ct := NewTable(cfg)
	if ct == nil {
		t.Fatal("NewTable returned nil")
	}
	if ct.Len() != 0 {
		t.Errorf("Len = %d, want 0", ct.Len())
	}
}

func TestLookupOrCreateNewFlow(t *testing.T) {
	ct := NewTable(DefaultConfig())
	f := ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "TCP", 44001, 443)
	if f == nil {
		t.Fatal("LookupOrCreate returned nil")
	}
	if f.Established {
		t.Error("new flow should not be established")
	}
	if f.Packets != 1 {
		t.Errorf("Packets = %d, want 1", f.Packets)
	}
	if ct.Len() != 1 {
		t.Errorf("Len = %d, want 1", ct.Len())
	}
}

func TestLookupOrCreateDuplicate(t *testing.T) {
	ct := NewTable(DefaultConfig())
	f1 := ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "TCP", 44001, 443)
	f2 := ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "TCP", 44001, 443)

	if f1 != f2 {
		t.Error("LookupOrCreate should return the same flow for duplicate calls")
	}
	if f2.Packets != 2 {
		t.Errorf("Packets = %d, want 2 (after second lookup)", f2.Packets)
	}
}

func TestFlowEstablish(t *testing.T) {
	ct := NewTable(DefaultConfig())
	f := ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "TCP", 44001, 443)
	if f.Established {
		t.Error("flow should not be established initially")
	}
	f.SetEstablished()
	if !f.Established {
		t.Error("flow should be established after SetEstablished()")
	}
}

func TestDeleteFlow(t *testing.T) {
	ct := NewTable(DefaultConfig())
	ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "TCP", 44001, 443)
	if ct.Len() != 1 {
		t.Errorf("Len = %d, want 1", ct.Len())
	}
	ct.Delete("10.0.1.100", "10.0.2.50", "TCP", 44001, 443)
	if ct.Len() != 0 {
		t.Errorf("Len = %d, want 0 after delete", ct.Len())
	}
}

func TestDeleteNonExistentFlow(t *testing.T) {
	ct := NewTable(DefaultConfig())
	// Should not panic
	ct.Delete("1.2.3.4", "5.6.7.8", "TCP", 1, 2)
}

func TestFlowKeyUniqueness(t *testing.T) {
	ct := NewTable(DefaultConfig())
	f1 := ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "TCP", 44001, 443)
	f2 := ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "TCP", 44002, 443)
	f3 := ct.LookupOrCreate("10.0.1.100", "10.0.2.51", "TCP", 44001, 443)

	if f1 == f2 {
		t.Error("different src ports should create different flows")
	}
	if f1 == f3 {
		t.Error("different dst IPs should create different flows")
	}
	if ct.Len() != 3 {
		t.Errorf("Len = %d, want 3", ct.Len())
	}
}

func TestExpireIdleFlows(t *testing.T) {
	ct := NewTable(Config{
		MaxEntries:  1000,
		IdleTimeout: 50 * time.Millisecond,
	})
	ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "TCP", 44001, 443)

	time.Sleep(20 * time.Millisecond)
	expired := ct.Expire()
	if expired != 0 {
		t.Errorf("Expired = %d, want 0 (not yet timed out)", expired)
	}

	time.Sleep(50 * time.Millisecond)
	expired = ct.Expire()
	if expired != 1 {
		t.Errorf("Expired = %d, want 1", expired)
	}
	if ct.Len() != 0 {
		t.Errorf("Len = %d, want 0 after expiry", ct.Len())
	}
}

func TestExpireSkipsActiveFlows(t *testing.T) {
	ct := NewTable(Config{
		MaxEntries:  1000,
		IdleTimeout: 50 * time.Millisecond,
	})
	ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "TCP", 44001, 443)

	time.Sleep(30 * time.Millisecond)
	// Refresh the flow
	ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "TCP", 44001, 443)

	time.Sleep(30 * time.Millisecond)
	expired := ct.Expire()
	if expired != 0 {
		t.Errorf("Expired = %d, want 0 (flow was refreshed)", expired)
	}
}

func TestMaxEntriesEviction(t *testing.T) {
	ct := NewTable(Config{
		MaxEntries:  5,
		IdleTimeout: 60 * time.Second,
	})
	// Create 10 flows — only 5 should stay
	for i := 0; i < 10; i++ {
		ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "TCP",
			uint16(44000+i), uint16(80+i))
	}
	if ct.Len() > 5 {
		t.Errorf("Len = %d, want <= 5", ct.Len())
	}
}

func TestConcurrentAccess(t *testing.T) {
	ct := NewTable(DefaultConfig())
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			f := ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "TCP",
				uint16(44000+n), uint16(80+n%10))
			if n%2 == 0 {
				f.SetEstablished()
			}
		}(i)
	}
	wg.Wait()
	if ct.Len() != 100 {
		t.Errorf("Len = %d, want 100 after concurrent creation", ct.Len())
	}
}

func TestRecordDestPort(t *testing.T) {
	ct := NewTable(DefaultConfig())
	ct.RecordDestPort("10.0.1.100", 22)
	ct.RecordDestPort("10.0.1.100", 23)
	ct.RecordDestPort("10.0.1.100", 25)

	ports := ct.GetRecentDestPorts("10.0.1.100")
	if len(ports) != 3 {
		t.Errorf("Recent ports = %v, want 3", len(ports))
	}
}

func TestRecordDestPortDeduplicates(t *testing.T) {
	ct := NewTable(DefaultConfig())
	ct.RecordDestPort("10.0.1.100", 22)
	ct.RecordDestPort("10.0.1.100", 22)
	ct.RecordDestPort("10.0.1.100", 22)

	ports := ct.GetRecentDestPorts("10.0.1.100")
	if len(ports) != 1 {
		t.Errorf("Recent ports = %v (len=%d), want 1", ports, len(ports))
	}
}

func TestRecordDestPortMaxWindow(t *testing.T) {
	ct := NewTable(Config{
		MaxEntries:           1000,
		IdleTimeout:          60 * time.Second,
		PortScanWindow:       100,
		PortScanMaxPorts:     100,
	})
	// Record more than max ports
	for i := 0; i < 150; i++ {
		ct.RecordDestPort("10.0.1.100", uint16(1+i))
	}
	ports := ct.GetRecentDestPorts("10.0.1.100")
	if len(ports) > 100 {
		t.Errorf("Recent ports = %d, want <= 100", len(ports))
	}
}

func TestGetRecentDestPortsEmpty(t *testing.T) {
	ct := NewTable(DefaultConfig())
	ports := ct.GetRecentDestPorts("10.0.1.100")
	if ports != nil {
		t.Errorf("Expected nil, got %v", ports)
	}
}

func TestFlowAge(t *testing.T) {
	ct := NewTable(DefaultConfig())
	_ = ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "TCP", 44001, 443)
	time.Sleep(5 * time.Millisecond)

	f := ct.LookupOrCreate("10.0.1.100", "10.0.2.50", "TCP", 44001, 443)
	if f.AgeMs() <= 0 {
		t.Errorf("AgeMs = %d, want > 0", f.AgeMs())
	}
}

func TestConfigValidation(t *testing.T) {
	cfg := Config{
		MaxEntries:  0,
		IdleTimeout: 0,
	}
	ct := NewTable(cfg)
	if ct == nil {
		t.Fatal("NewTable should not return nil")
	}
	if ct.Len() != 0 {
		t.Errorf("Len = %d, want 0", ct.Len())
	}
}
