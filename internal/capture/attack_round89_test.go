package capture

import (
	"os"
	"path/filepath"
	"testing"
)

// ── R89.4: pcap evidence is world-readable (R6.13 debt, never fixed) ─────
//
// Round 6 flagged this ("File permission issues", TestAttack_FilePermissions)
// and only t.Logged it: the rotation file is created with mode 0666, so under
// the usual umask it lands as 0644 — readable by EVERY local user and by any
// neighbouring container that mounts the capture directory.
//
// What is inside is the most sensitive artifact the firewall produces: the
// full L2-L4 header of blocked packets, i.e. cleartext-sniffable payloads
// (HTTP requests with credentials, DNS queries, SMTP/Telnet/FTP sessions,
// TLS SNI/SNI-adjacent metadata) plus the addresses of blocked hosts and of
// the firewall's protected subnet. An unprivileged local attacker does not
// need any other capability: a periodic `cat blocked_*.pcap` gives them the
// traffic the firewall was specifically deployed to stop.
//
// Rotation files are created by the firewall for its own use; no other user
// needs to read them, so the mode must be owner-only.
func TestAttack_PcapEvidenceWorldReadable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pcaps")
	w, err := NewWriter(Config{Dir: dir, MaxPackets: 100})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	// A minimal Ethernet/IPv4/TCP frame, as the engine would hand it over.
	frame := []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x08, 0x00,
		0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00,
		0xcb, 0x00, 0x71, 0x09, 0x0a, 0x00, 0x00, 0x01,
		0x1f, 0x90, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00,
	}
	if err := w.WriteBlock(frame); err != nil {
		t.Fatalf("WriteBlock: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}
	if len(entries) == 0 {
		t.Fatal("no pcap file was created")
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatalf("Info(%s): %v", e.Name(), err)
		}
		perm := info.Mode().Perm()
		if perm&0o077 != 0 {
			t.Errorf("%s is accessible outside the firewall's UID (mode %04o) — captured traffic "+
				"(payloads of blocked packets, including cleartext credentials) is readable by any local user",
				e.Name(), perm)
		}
	}
}

// ── R89.4b: a pre-existing pcap file keeps its mode (no silent chmod) ────
// Regression guard for the fix: the rotation open must not depend on the
// file being new. A file created by an older build (0644) that survives into
// the retention window must be tightened on the next rotation open, or the
// retention window keeps serving readable evidence.
func TestAttack_PcapRotationTightensExistingFileMode(t *testing.T) {
	dir := t.TempDir()
	// Pre-create the first rotation file the way a pre-fix build left it.
	first := filepath.Join(dir, "blocked_00001.pcap")
	if err := os.WriteFile(first, nil, 0o644); err != nil {
		t.Fatalf("seeding pre-existing pcap: %v", err)
	}
	if err := os.Chmod(first, 0o644); err != nil { // defeat umask
		t.Fatalf("chmod: %v", err)
	}

	w, err := NewWriter(Config{Dir: dir, MaxPackets: 100})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()
	if err := w.WriteBlock([]byte{0x00, 0x01}); err != nil {
		t.Fatalf("WriteBlock: %v", err)
	}

	info, err := os.Stat(first)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("pre-existing %s left at mode %04o — evidence stays readable outside the firewall's UID", filepath.Base(first), perm)
	}
}
