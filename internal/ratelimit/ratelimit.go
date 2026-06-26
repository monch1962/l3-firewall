// Package ratelimit provides per-IP and per-destination-port rate limiting using
// EWMA (Exponentially Weighted Moving Average) for smooth rate estimation.
package ratelimit

import (
	"fmt"
	"math"
	"sync"
	"time"
)

// rateBucket tracks rate for a single key (IP or IP:port pair).
type rateBucket struct {
	pps      float64
	bps      float64
	lastTime time.Time
}

// rateKey is a generic rate limiter key (IP or IP:port).
type rateKey string

// Limiter provides per-IP and per-destination-port packet and byte rate tracking.
// Uses EWMA so the reported rate smoothly decays after activity stops.
type Limiter struct {
	mu        sync.RWMutex
	buckets   map[rateKey]*rateBucket
	ppsLimit  float64
	bpsLimit  float64
	alpha     float64
}

// NewLimiter creates a rate limiter.
func NewLimiter(ppsLimit, bpsLimit float64) *Limiter {
	return &Limiter{
		buckets:  make(map[rateKey]*rateBucket),
		ppsLimit: ppsLimit,
		bpsLimit: bpsLimit,
		alpha:    0.3,
	}
}

// ipKey returns the per-IP key.
func ipKey(ip string) rateKey {
	return rateKey("ip:" + ip)
}

// portKey returns the per-IP:destination-port key.
func portKey(ip string, dstPort uint16) rateKey {
	return rateKey(fmt.Sprintf("port:%s:%d", ip, dstPort))
}

// updateBucket records a packet in the given bucket and returns the current PPS/BPS.
func (l *Limiter) updateBucket(b *rateBucket, packetSize int, now time.Time) (pps, bps float64) {
	dt := now.Sub(b.lastTime).Seconds()
	if dt <= 0 {
		dt = 0.001
	}
	b.lastTime = now

	instPPS := 1.0 / dt
	instBPS := float64(packetSize) / dt

	if b.pps == 0 {
		b.pps = 1.0
		b.bps = float64(packetSize)
	} else {
		b.pps = l.alpha*instPPS + (1-l.alpha)*b.pps
		b.bps = l.alpha*instBPS + (1-l.alpha)*b.bps
	}

	if math.IsInf(b.pps, 0) || b.pps > 1e12 {
		b.pps = 1e12
	}
	if math.IsInf(b.bps, 0) || b.bps > 1e15 {
		b.bps = 1e15
	}
	return b.pps, b.bps
}

// getOrCreateBucket returns the bucket for a key, creating it if needed.
func (l *Limiter) getOrCreateBucket(key rateKey, now time.Time) *rateBucket {
	b, ok := l.buckets[key]
	if !ok {
		b = &rateBucket{lastTime: now}
		l.buckets[key] = b
	}
	return b
}

// Allow records a packet for the given IP and returns the current PPS and BPS.
func (l *Limiter) Allow(ip string, packetSize int) (pps, bps float64) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.getOrCreateBucket(ipKey(ip), now)
	return l.updateBucket(b, packetSize, now)
}

// AllowPort records a packet for the given IP:destination-port pair and returns
// the current PPS and BPS for that specific port.
func (l *Limiter) AllowPort(ip string, dstPort uint16, packetSize int) (pps, bps float64) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.getOrCreateBucket(portKey(ip, dstPort), now)
	return l.updateBucket(b, packetSize, now)
}

// getBucketPPS is a helper to safely read a bucket's PPS.
func (l *Limiter) getBucketPPS(key rateKey) float64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if b, ok := l.buckets[key]; ok {
		return b.pps
	}
	return 0
}

// getBucketBPS is a helper to safely read a bucket's BPS.
func (l *Limiter) getBucketBPS(key rateKey) float64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if b, ok := l.buckets[key]; ok {
		return b.bps
	}
	return 0
}

// GetPPS returns the packets-per-second rate for the given IP.
func (l *Limiter) GetPPS(ip string) float64 {
	return l.getBucketPPS(ipKey(ip))
}

// GetBPS returns the bytes-per-second rate for the given IP.
func (l *Limiter) GetBPS(ip string) float64 {
	return l.getBucketBPS(ipKey(ip))
}

// GetPortPPS returns the packets-per-second rate for the given IP:port pair.
func (l *Limiter) GetPortPPS(ip string, dstPort uint16) float64 {
	return l.getBucketPPS(portKey(ip, dstPort))
}

// GetPortBPS returns the bytes-per-second rate for the given IP:port pair.
func (l *Limiter) GetPortBPS(ip string, dstPort uint16) float64 {
	return l.getBucketBPS(portKey(ip, dstPort))
}

// Cleanup removes buckets that have been idle longer than the given duration.
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

// Len returns the number of tracked rate entries.
func (l *Limiter) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.buckets)
}
