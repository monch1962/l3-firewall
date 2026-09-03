package geoip

import (
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

// TestLookupCountryWithRealFile verifies lookup against the committed
// minimal country database (testdata/country-test.mmdb — 8.8.8.0/24 → US,
// 1.1.1.0/24 → GB, generated with the maxmind/mmdbwriter tool and added
// in R71 as the crafted-database asset for the symlink attack tests).
func TestLookupCountryWithRealFile(t *testing.T) {
	r, err := NewReader("testdata/country-test.mmdb")
	if err != nil {
		t.Fatalf("open committed test database: %v", err)
	}
	defer r.Close()

	if code := r.LookupCountry("8.8.8.8"); code != "US" {
		t.Errorf("LookupCountry(8.8.8.8) = %q, want US", code)
	}
	if code := r.LookupCountry("1.1.1.1"); code != "GB" {
		t.Errorf("LookupCountry(1.1.1.1) = %q, want GB", code)
	}
}
