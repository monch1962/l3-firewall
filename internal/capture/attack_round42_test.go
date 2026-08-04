// Red-team security hardening Round 42 — pcap rotation file symlink
// write-through in capture.Writer.
//
// rotateLocked creates each rotation file with os.Create(fname) where
// fname = <dir>/blocked_%05d.pcap. os.Create follows symlinks: an attacker
// with write access to the pcap directory (operator-influenced --pcap-dir,
// e.g. an attacker-writable default location) can pre-create
// blocked_NNNNN.pcap as a symlink to an arbitrary file writable by the
// firewall's UID. The first blocked packet written to that rotation slot
// then TRUNCATES and overwrites the target with pcap bytes — an arbitrary
// file truncate/write primitive in the packet hot path.
//
// This is the same symlink-following class fixed in persist R42 for
// SaveState's .tmp create. R9/R12 hardened capture's size caps and rotation
// cleanup, but the rotation file CREATE was never covered.
//
// R42 FIX: open rotation files with O_NOFOLLOW — a symlink at the rotation
// filename is rejected with ELOOP and the write fails closed (packet not
// captured, target untouched).
package capture

import (
	"os"
	"path/filepath"
	"testing"
)

// ── R42.1: rotateLocked must NOT write through a symlinked rotation file ─
// RED (pre-fix): os.Create follows the symlink, truncates the victim and
// writes the pcap header + packet through it; WriteBlock returns nil.
// GREEN (post-fix): WriteBlock returns an error and the victim is untouched.
func TestAttack_RotateSymlinkWriteThrough(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.pcap")
	orig := "PRECIOUS-PCAP-DATA"
	if err := os.WriteFile(victim, []byte(orig), 0600); err != nil {
		t.Fatal(err)
	}
	// First rotation filename used by rotateLocked.
	rotationFile := filepath.Join(dir, "blocked_00001.pcap")
	if err := os.Symlink(victim, rotationFile); err != nil {
		t.Fatal(err)
	}

	w, err := NewWriter(Config{Dir: dir, MaxFiles: 3, MaxPackets: 2})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	err = w.WriteBlock([]byte("SYMLINK-ATTACK-PACKET"))
	if err == nil {
		t.Error("WriteBlock must reject a symlinked rotation file (returned nil error)")
	}

	b, readErr := os.ReadFile(victim)
	if readErr != nil {
		t.Fatalf("reading victim: %v", readErr)
	}
	if string(b) != orig {
		t.Errorf("SYMLINK WRITE-THROUGH: victim modified: got %q want %q", string(b), orig)
	}
}

// ── R42.2: WriteBlock still works with normal rotation files (regression) ─
// The O_NOFOLLOW flag must not break the normal capture path.
func TestAttack_RotateNormalFileStillWorks(t *testing.T) {
	dir := t.TempDir()

	w, err := NewWriter(Config{Dir: dir, MaxFiles: 3, MaxPackets: 2})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	if err := w.WriteBlock([]byte("NORMAL-PACKET")); err != nil {
		t.Fatalf("WriteBlock failed on normal path: %v", err)
	}
	// Rotation file must exist and contain the pcap header + packet.
	b, err := os.ReadFile(filepath.Join(dir, "blocked_00001.pcap"))
	if err != nil {
		t.Fatalf("reading rotation file: %v", err)
	}
	if len(b) < 24 { // pcap header is 24 bytes
		t.Errorf("rotation file suspiciously small: %d bytes", len(b))
	}
}
