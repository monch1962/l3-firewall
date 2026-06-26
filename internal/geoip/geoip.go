// Package geoip provides country-level GeoIP lookups using MaxMind's
// GeoLite2 or GeoIP2 databases (.mmdb format).
package geoip

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/oschwald/maxminddb-golang/v2"
)

// geoipRecord mirrors the relevant fields from a MaxMind GeoIP2 response.
type geoipRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// Reader wraps a MaxMind database for country-level GeoIP lookups.
// A nil *Reader is safe to use (returns empty country).
type Reader struct {
	db *maxminddb.Reader
}

// NewReader opens a MaxMind .mmdb database file.
// Returns (nil, nil) if path is empty — callers can pass "" to disable.
func NewReader(path string) (*Reader, error) {
	if path == "" {
		return nil, nil
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening GeoIP database %s: %w", path, err)
	}
	return &Reader{db: db}, nil
}

// Close releases the database resources.
func (r *Reader) Close() error {
	if r == nil || r.db == nil {
		return nil
	}
	return r.db.Close()
}

// LookupCountry returns the ISO 3166-1 alpha-2 country code for the given IP.
// Returns empty string if the IP is not found, the database is nil, or
// the IP address is invalid. Safe for concurrent use.
func (r *Reader) LookupCountry(ipStr string) string {
	if r == nil || r.db == nil {
		return ""
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	// Convert to netip.Addr (required by v2 API)
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return ""
	}

	// Normalize IPv4-mapped IPv6 to IPv4
	addr = addr.Unmap()

	var record geoipRecord
	result := r.db.Lookup(addr)
	if !result.Found() {
		return ""
	}
	if err := result.Decode(&record); err != nil {
		return ""
	}

	return strings.ToUpper(record.Country.ISOCode)
}
