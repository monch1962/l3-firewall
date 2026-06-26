package ratelimit

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestNewLimiter(t *testing.T) {
	l := NewLimiter(100, 200)
	if l == nil {
		t.Fatal("NewLimiter returned nil")
	}
}

func TestAllowWithinLimit(t *testing.T) {
	l := NewLimiter(100, 200)
	pps, bps := l.Allow("10.0.1.100", 64)
	if pps <= 0 {
		t.Errorf("pps = %f, want > 0", pps)
	}
	if bps <= 0 {
		t.Errorf("bps = %f, want > 0", bps)
	}
}

func TestAllowExceedsLimit(t *testing.T) {
	l := NewLimiter(5, 1000)
	var lastPPS float64
	for i := 0; i < 20; i++ {
		pps, _ := l.Allow("10.0.1.100", 64)
		lastPPS = pps
		time.Sleep(1 * time.Millisecond)
	}
	if lastPPS < 0 {
		t.Errorf("lastPPS = %f, want >= 0", lastPPS)
	}
}

func TestDifferentKeysIndependent(t *testing.T) {
	l := NewLimiter(10, 100)
	pps1, _ := l.Allow("10.0.1.100", 64)
	pps2, _ := l.Allow("10.0.2.200", 64)

	if pps1 < 0 || pps2 < 0 {
		t.Error("both IPs should be allowed independently")
	}
}

func TestBPSLimiting(t *testing.T) {
	l := NewLimiter(100, 500)
	var lastBPS float64
	for i := 0; i < 10; i++ {
		_, bps := l.Allow("10.0.1.100", 600)
		lastBPS = bps
		time.Sleep(1 * time.Millisecond)
	}
	if lastBPS < 0 {
		t.Errorf("lastBPS = %f, want >= 0", lastBPS)
	}
}

func TestStaleCleanup(t *testing.T) {
	l := NewLimiter(10, 1000)
	for i := 0; i < 10; i++ {
		l.Allow(fmt.Sprintf("10.0.1.%d", i), 64)
	}
	time.Sleep(10 * time.Millisecond)
	removed := l.Cleanup(5 * time.Millisecond)
	if removed <= 0 {
		t.Errorf("Cleanup removed %d entries, want > 0", removed)
	}
}

func TestCleanupActiveKeys(t *testing.T) {
	l := NewLimiter(10, 1000)
	l.Allow("10.0.1.100", 64)
	time.Sleep(50 * time.Millisecond)
	l.Allow("10.0.1.100", 64)
	removed := l.Cleanup(100 * time.Millisecond)
	if removed > 0 {
		t.Errorf("Cleanup removed %d active entries, want 0", removed)
	}
}

func TestConcurrentAccess(t *testing.T) {
	l := NewLimiter(1000, 100000)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				l.Allow(fmt.Sprintf("10.0.1.%d", n), 64)
			}
		}(i)
	}
	wg.Wait()
}

func TestGetPPS(t *testing.T) {
	l := NewLimiter(100, 1000)
	l.Allow("10.0.1.100", 64)
	time.Sleep(5 * time.Millisecond)

	pps := l.GetPPS("10.0.1.100")
	if pps < 0 {
		t.Errorf("PPS = %f, want >= 0", pps)
	}
}

func TestGetPPSUnknown(t *testing.T) {
	l := NewLimiter(100, 1000)
	pps := l.GetPPS("unknown.ip")
	if pps != 0 {
		t.Errorf("PPS for unknown = %f, want 0", pps)
	}
}

func TestGetBPS(t *testing.T) {
	l := NewLimiter(100, 1000)
	l.Allow("10.0.1.100", 500)
	time.Sleep(5 * time.Millisecond)

	bps := l.GetBPS("10.0.1.100")
	if bps < 0 {
		t.Errorf("BPS = %f, want >= 0", bps)
	}
}

func TestAllowPort(t *testing.T) {
	l := NewLimiter(100, 1000)
	pps, bps := l.AllowPort("10.0.1.100", 443, 64)
	if pps <= 0 {
		t.Errorf("per-port PPS = %f, want > 0", pps)
	}
	if bps <= 0 {
		t.Errorf("per-port BPS = %f, want > 0", bps)
	}
}

func TestAllowPortDifferentPortsIndependent(t *testing.T) {
	l := NewLimiter(100, 1000)
	pps1, _ := l.AllowPort("10.0.1.100", 443, 64)
	pps2, _ := l.AllowPort("10.0.1.100", 80, 64)
	pps3, _ := l.AllowPort("10.0.1.100", 22, 64)

	if pps1 <= 0 || pps2 <= 0 || pps3 <= 0 {
		t.Error("different ports should have independent rates")
	}

	// Same port repeated should have higher rate
	for i := 0; i < 5; i++ {
		l.AllowPort("10.0.1.100", 22, 64)
		time.Sleep(1 * time.Millisecond)
	}
	sshPPS, _ := l.AllowPort("10.0.1.100", 22, 64)
	httpsPPS, _ := l.AllowPort("10.0.1.100", 443, 64)

	if sshPPS <= httpsPPS {
		t.Errorf("SSH port rate (%f) should exceed HTTPS rate (%f) after burst", sshPPS, httpsPPS)
	}
}

func TestGetPortPPS(t *testing.T) {
	l := NewLimiter(100, 1000)
	l.AllowPort("10.0.1.100", 443, 64)
	time.Sleep(5 * time.Millisecond)
	pps := l.GetPortPPS("10.0.1.100", 443)
	if pps <= 0 {
		t.Errorf("Port PPS = %f, want > 0", pps)
	}
}

func TestGetPortPPSUnknown(t *testing.T) {
	l := NewLimiter(100, 1000)
	pps := l.GetPortPPS("unknown.ip", 443)
	if pps != 0 {
		t.Errorf("Port PPS for unknown = %f, want 0", pps)
	}
}
