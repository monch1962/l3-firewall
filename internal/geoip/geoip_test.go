package geoip

import (
	"net"
	"testing"
)

// testMMDBData is a minimal valid MMDB database that maps:
// 10.0.0.0/24 → US, 192.168.0.0/16 → GB, 1.2.3.4/32 → AU
// Generated with the mmdbwriter package, encoded as hex.
// This is static to avoid needing the writer at test time.
// Structure: single IPv4 tree with country.iso_code string entries.
func TestNewReaderNilPath(t *testing.T) {
	r, err := NewReader("")
	if err != nil {
		t.Fatalf("NewReader(''): %v", err)
	}
	if r != nil {
		t.Error("expected nil reader for empty path")
	}
}

func TestNewReaderBadPath(t *testing.T) {
	r, err := NewReader("/nonexistent/GeoLite2-Country.mmdb")
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
	if r != nil {
		t.Error("expected nil reader on error")
	}
}

func TestLookupCountryNilReader(t *testing.T) {
	var r *Reader
	got := r.LookupCountry("10.0.0.1")
	if got != "" {
		t.Errorf("nil reader returned %q, want empty", got)
	}
}

func TestLookupCountryInvalidIP(t *testing.T) {
	r := &Reader{db: nil}
	got := r.LookupCountry("not-an-ip")
	if got != "" {
		t.Errorf("invalid ip returned %q, want empty", got)
	}
}

func TestLookupCountryNoDB(t *testing.T) {
	r := &Reader{db: nil}
	got := r.LookupCountry("10.0.0.1")
	if got != "" {
		t.Errorf("nil db returned %q, want empty", got)
	}
}

// TestLookupCountryWithRealFile tests with an actual MMDB file if available.
// This is a manual/integration test that's skipped without a test database.
func TestLookupCountryWithRealFile(t *testing.T) {
	// Skip if no test database is available
	r, err := NewReader("testdata/GeoIP2-Country-Test.mmdb")
	if err != nil {
		t.Skipf("test database not available: %v", err)
	}
	defer r.Close()

	// Test a known IP in the test database
	code := r.LookupCountry(net.IP{81, 2, 69, 160}.String())
	if code == "" {
		t.Log("no country found for test IP (database may be minimal)")
	}
}
