// Package ratelimit provides per-IP token bucket rate limiting for packets
// and bytes, designed for high-concurrency NFQUEUE usage.
package ratelimit

import (
	"math"
	"sync"
	"time"
)

// bucket tracks rate for a single IP using a token bucket with leaky bucket
// rate calculation.
type bucket struct {
	pps       float64 // exponentially weighted moving average of packets/sec
	bps       float64 // exponentially weighted moving average of bytes/sec
	lastTime  time.Time
}

// rateKey is a limiter key (currently just IP, but could be extended).
type rateKey string

// Limiter provides per-IP packet and byte rate tracking.
// Uses an EWMA (Exponentially Weighted Moving Average) approach so that
// the reported rate smoothly decays after activity stops, rather than
// resetting abruptly.
type Limiter struct {
	mu         sync.RWMutex
	buckets    map[rateKey]*bucket
	ppsLimit   float64 // max packets per second
	bpsLimit   float64 // max bytes per second
	alpha      float64 // EWMA smoothing factor (0..1)
}

// NewLimiter creates a per-IP rate limiter.
// ppsLimit: max packets per second (0 = unlimited)
// bpsLimit: max bytes per second (0 = unlimited)
func NewLimiter(ppsLimit, bpsLimit float64) *Limiter {
	return &Limiter{
		buckets:  make(map[rateKey]*bucket),
		ppsLimit: ppsLimit,
		bpsLimit: bpsLimit,
		alpha:    0.3, // EWMA smoothing factor — higher = faster response
	}
}

// Allow records a packet for the given IP and returns the current PPS and BPS
// for that IP. The caller should compare the returned values against configured
// limits to decide whether to drop the packet.
func (l *Limiter) Allow(ip string, packetSize int) (pps, bps float64) {
	key := rateKey(ip)
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{
			lastTime: now,
		}
		l.buckets[key] = b
	}

	// Calculate time delta in seconds
	dt := now.Sub(b.lastTime).Seconds()
	if dt <= 0 {
		dt = 0.001 // minimum 1ms to avoid division issues
	}
	b.lastTime = now

	// Instantaneous rate for this sample
	instPPS := 1.0 / dt
	instBPS := float64(packetSize) / dt

	// EWMA update
	if b.pps == 0 {
		// First packet — use a conservative starting rate rather than
		// the instantaneous rate which can be absurdly high (1/dt for
		// very small dt).
		b.pps = 1.0
		b.bps = float64(packetSize)
	} else {
		b.pps = l.alpha*instPPS + (1-l.alpha)*b.pps
		b.bps = l.alpha*instBPS + (1-l.alpha)*b.bps
	}

	// Clamp to prevent infinity
	if math.IsInf(b.pps, 0) || b.pps > 1e12 {
		b.pps = 1e12
	}
	if math.IsInf(b.bps, 0) || b.bps > 1e15 {
		b.bps = 1e15
	}

	return b.pps, b.bps
}

// GetPPS returns the current packets-per-second rate for the given IP.
// Returns 0 if the IP has no recorded activity.
func (l *Limiter) GetPPS(ip string) float64 {
	key := rateKey(ip)
	l.mu.RLock()
	defer l.mu.RUnlock()
	if b, ok := l.buckets[key]; ok {
		return b.pps
	}
	return 0
}

// GetBPS returns the current bytes-per-second rate for the given IP.
// Returns 0 if the IP has no recorded activity.
func (l *Limiter) GetBPS(ip string) float64 {
	key := rateKey(ip)
	l.mu.RLock()
	defer l.mu.RUnlock()
	if b, ok := l.buckets[key]; ok {
		return b.bps
	}
	return 0
}

// Cleanup removes buckets that have been idle longer than the given duration.
// Returns the number of entries removed. Should be called periodically
// (e.g. every minute) to prevent memory exhaustion from stale IPs.
func (l *Limiter) Cleanup(idleThreshold time.Duration) int {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	var removed int
	for key, b := range l.buckets {
		if now.Sub(b.lastTime) > idleThreshold {
			delete(l.buckets, key)
			removed++
		}
	}
	return removed
}

// Len returns the number of tracked IPs.
func (l *Limiter) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.buckets)
}
