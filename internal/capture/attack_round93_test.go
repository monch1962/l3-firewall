package capture

import (
	"os"
	"path/filepath"
	"testing"
)

// ── R93.1 (capture integration): hardlink write-through on rotation ────────
//
// The rotation filenames are fully predictable (blocked_00001.pcap, ...), and
// R42 hardened the create open against a symlink (O_NOFOLLOW) while R55 added
// O_NONBLOCK for a planted FIFO — both in securepath.CreateOwnerOnly. A hard
// link is the third shape and no open(2) flag refuses it.
//
// An attacker with write access to --pcap-dir (the standing R42/R45/R55/R63/
// R69 model: a shared volume, or the 0755 directory NewWriter creates) links
// blocked_00001.pcap to a file the firewall's UID can write. The next blocked
// packet rotates, opens the link O_WRONLY|O_TRUNC and the linked file's
// contents are replaced with pcap bytes — the firewall destroys evidence as
// its own UID on the hot path, exactly where it is supposed to be capturing it.
func TestAttack_RotationHardLinkDestroysVictim(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "evidence.dat")
	const secret = "FORENSIC EVIDENCE THAT MUST SURVIVE\n"
	if err := os.WriteFile(victim, []byte(secret), 0o600); err != nil {
		t.Fatalf("seeding victim: %v", err)
	}
	if err := os.Link(victim, filepath.Join(dir, "blocked_00001.pcap")); err != nil {
		t.Fatalf("creating hard link at the first rotation name: %v", err)
	}

	w, err := NewWriter(Config{Dir: dir, MaxFiles: 10, MaxPackets: 100})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	if werr := w.WriteBlock([]byte{0xde, 0xad, 0xbe, 0xef}); werr == nil {
		t.Log("WriteBlock accepted the hard-linked rotation path")
	}

	got, rerr := os.ReadFile(victim)
	if rerr != nil {
		t.Fatalf("victim unreadable after attack: %v", rerr)
	}
	if string(got) != secret {
		t.Errorf("rotation hardlink write-through destroyed %s: got %q, want %q", victim, string(got), secret)
	}
}

// A refused rotation must recover once the planted link is gone: the next
// blocked packet writes a real capture instead of a link target.
func TestAttack_RotationRecoversAfterRefusedHardLink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.dat")
	if err := os.WriteFile(victim, []byte("keep me"), 0o600); err != nil {
		t.Fatalf("seeding victim: %v", err)
	}
	linkPath := filepath.Join(dir, "blocked_00001.pcap")
	if err := os.Link(victim, linkPath); err != nil {
		t.Fatalf("creating hard link: %v", err)
	}
	w, err := NewWriter(Config{Dir: dir, MaxFiles: 10, MaxPackets: 100})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()
	if werr := w.WriteBlock([]byte{0x01, 0x02}); werr == nil {
		t.Fatal("WriteBlock accepted the hard-linked rotation path")
	}
	if err := os.Remove(linkPath); err != nil {
		t.Fatalf("removing planted link: %v", err)
	}
	if werr := w.WriteBlock([]byte{0x03, 0x04}); werr != nil {
		t.Fatalf("WriteBlock after the link was removed: %v", werr)
	}
	fi, err := os.Stat(filepath.Join(dir, "blocked_00001.pcap"))
	if err != nil {
		t.Fatalf("stat rotation file: %v", err)
	}
	if fi.Size() == 0 {
		t.Error("rotation file is empty — capture did not resume")
	}
	if got, _ := os.ReadFile(victim); string(got) != "keep me" {
		t.Errorf("victim content = %q, want %q", string(got), "keep me")
	}
}
