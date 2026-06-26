package l2filter

import (
	"testing"
)

func TestMACAllowedNoRestrictions(t *testing.T) {
	f := NewFilter(Config{})
	if ok, _ := f.MACAllowed("aa:bb:cc:dd:ee:ff"); !ok {
		t.Error("expected all MACs allowed with no restrictions")
	}
}

func TestMACAllowedBlocked(t *testing.T) {
	f := NewFilter(Config{
		BlockedMACs: []string{"aa:bb:cc:dd:ee:ff"},
	})
	if ok, _ := f.MACAllowed("aa:bb:cc:dd:ee:ff"); ok {
		t.Error("expected blocked MAC to be denied")
	}
}

func TestMACNotInAllowlist(t *testing.T) {
	f := NewFilter(Config{
		AllowedMACs: []string{"aa:bb:cc:dd:ee:01"},
	})
	if ok, _ := f.MACAllowed("aa:bb:cc:dd:ee:ff"); ok {
		t.Error("expected unlisted MAC to be denied")
	}
}

func TestMACInAllowlist(t *testing.T) {
	f := NewFilter(Config{
		AllowedMACs: []string{"aa:bb:cc:dd:ee:01"},
	})
	if ok, _ := f.MACAllowed("aa:bb:cc:dd:ee:01"); !ok {
		t.Error("expected allowed MAC to pass")
	}
}

func TestMACNormalization(t *testing.T) {
	f := NewFilter(Config{
		AllowedMACs: []string{"AA:BB:CC:DD:EE:01"},
	})
	if ok, _ := f.MACAllowed("aa:bb:cc:dd:ee:01"); !ok {
		t.Error("expected case-insensitive MAC matching")
	}
}

func TestNilFilter(t *testing.T) {
	var f *Filter
	if ok, _ := f.MACAllowed("aa:bb:cc:dd:ee:ff"); !ok {
		t.Error("nil filter should allow all")
	}
}

func TestCheckARPNewBinding(t *testing.T) {
	f := NewFilter(Config{EnableARPCheck: true})
	allowed, _ := f.CheckARP("10.0.0.1", "aa:bb:cc:dd:ee:01")
	if !allowed {
		t.Error("expected first ARP to be allowed (learning mode)")
	}
}

func TestCheckARPMismatch(t *testing.T) {
	f := NewFilter(Config{EnableARPCheck: true})
	f.CheckARP("10.0.0.1", "aa:bb:cc:dd:ee:01")
	allowed, _ := f.CheckARP("10.0.0.1", "ff:ee:dd:cc:bb:aa")
	if allowed {
		t.Error("expected ARP spoofing detection")
	}
}

func TestCheckARPConsistent(t *testing.T) {
	f := NewFilter(Config{EnableARPCheck: true})
	f.CheckARP("10.0.0.1", "aa:bb:cc:dd:ee:01")
	allowed, _ := f.CheckARP("10.0.0.1", "aa:bb:cc:dd:ee:01")
	if !allowed {
		t.Error("expected consistent ARP to be allowed")
	}
}

func TestRecordDHCP(t *testing.T) {
	f := NewFilter(Config{EnableDHCPCheck: true})
	f.RecordDHCP("10.0.0.1", "aa:bb:cc:dd:ee:01")
	allowed, _ := f.CheckARP("10.0.0.1", "aa:bb:cc:dd:ee:01")
	if !allowed {
		t.Error("expected DHCP-bound MAC to match")
	}
}

func TestMACAllowedEmptyMAC(t *testing.T) {
	f := NewFilter(Config{
		BlockedMACs: []string{"aa:bb:cc:dd:ee:ff"},
	})
	if ok, _ := f.MACAllowed(""); !ok {
		t.Error("expected empty MAC to be allowed")
	}
}
