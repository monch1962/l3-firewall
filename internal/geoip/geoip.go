// Package geoip provides country-level GeoIP lookups using MaxMind's
// GeoLite2 or GeoIP2 databases (.mmdb format).
package geoip

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"

	"github.com/oschwald/maxminddb-golang/v2"
)

// maxGeoIPFileSize is the maximum allowed GeoIP database file size (512MB).
// Prevents memory exhaustion from an attacker-influenced --geoip-db path
// pointing at an oversized file (R8 class). GeoLite2/GeoIP2 databases are
// typically 3-100MB; 512MB is a generous upper bound.
const maxGeoIPFileSize = 512 * 1024 * 1024

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
//
// Hardened R38: the file is opened with O_NONBLOCK first (never blocks on
// FIFO/named pipes — startup DoS via attacker-influenced --geoip-db path),
// the file type is checked via f.Stat() on the already-opened fd (no TOCTOU),
// and the size is capped before the database is loaded into memory.
// OpenBytes is used on the verified fd content so the library never
// re-opens the path itself.
func NewReader(path string) (*Reader, error) {
	if path == "" {
		return nil, nil
	}
	// Open with O_NONBLOCK to prevent blocking on FIFO/named pipes.
	// On Linux, O_NONBLOCK has no effect on regular file reads.
	// Checking the type and size on the already-opened fd eliminates the
	// TOCTOU race between a path-based Stat check and a later Open.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("opening GeoIP database %s: %w", path, err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stating GeoIP database %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("GeoIP database path is not a regular file: %s", path)
	}
	if fi.Size() > maxGeoIPFileSize {
		return nil, fmt.Errorf("GeoIP database %s too large: %d bytes (max %d)", path, fi.Size(), maxGeoIPFileSize)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxGeoIPFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading GeoIP database %s: %w", path, err)
	}

	db, err := maxminddb.OpenBytes(data)
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
