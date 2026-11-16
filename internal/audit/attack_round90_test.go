package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── R90.1: the audit log is world-readable ──────────────────────────────
//
// openAuditFile has created the log with mode 0644 since R43 (that round
// added O_NOFOLLOW for the symlink class and left the mode alone). The
// default path is /tmp/l3-firewall/audit.log — a world-traversable directory
// in the world-writable /tmp — so the mode is the only thing standing
// between the audit trail and every other local user.
//
// The contents are the firewall's own block record: src_ip, dst_ip, ports,
// protocol and the policy reason ("blocked port 22 (TCP)", "rate limit
// exceeded for source 203.0.113.9"). That is a live map of which hosts are
// being denied and why — and R89 established the doctrine for exactly this
// class of file (persist's state file and capture's pcap were both fixed to
// 0600 via securepath.CreateOwnerOnly), but the third store of the same
// evidence was missed.
//
// World-read needs no write access at all, so none of the symlink/FIFO
// hardening on this exact open (R43/R45/R55/R57) applies to it.
func TestAttack_AuditLogWorldReadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	lg, err := NewLogger(Config{Path: path, MaxSizeMB: 10, MaxBackups: 2})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer func() { _ = lg.Close() }()

	if err := lg.Log(AuditEvent{
		Type:     "packet_block",
		TraceID:  "deadbeef",
		SrcIP:    "203.0.113.9",
		DstIP:    "10.0.0.1",
		Protocol: "TCP",
		DstPort:  22,
		Reason:   "blocked port 22 (TCP)",
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("audit log %s has mode %04o — the blocked-host record (src_ip, dst_ip, port, policy reason) is readable outside the firewall's UID", path, perm)
	}
}

// ── R90.1b: an existing log left world-readable is not tightened ─────────
//
// open(2) ignores its mode argument when the file already exists, so even a
// corrected O_CREATE mode would leave a log created by an older build (or by
// hand, or by an attacker who pre-created the predictable path) readable for
// the rest of the deployment's life. The mode must be forced with fchmod on
// the opened descriptor.
//
// This test also pins that the fix must NOT be implemented with O_TRUNC: the
// audit log is append-only evidence, and truncating it on startup would
// destroy the trail — a far worse defect than the permissions bug. The
// pre-planted line must survive.
func TestAttack_AuditLogTightensExistingMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	const planted = `{"type":"packet_block","src_ip":"198.51.100.7","reason":"planted pre-existing line"}` + "\n"
	if err := os.WriteFile(path, []byte(planted), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil { // WriteFile honours umask; force the exact vulnerable mode
		t.Fatalf("Chmod: %v", err)
	}

	lg, err := NewLogger(Config{Path: path, MaxSizeMB: 10, MaxBackups: 2})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	if err := lg.Log(AuditEvent{Type: "packet_block", SrcIP: "203.0.113.9", Reason: "blocked port 22 (TCP)"}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if err := lg.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("pre-existing audit log left at mode %04o — the evidence stays readable outside the firewall's UID (open(2) ignores the mode argument for an existing file; the mode must be forced on the fd)", perm)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "198.51.100.7") {
		t.Errorf("NewLogger truncated the existing audit trail — a permission fix must not be implemented with O_TRUNC (the audit log is append-only evidence); got %q", string(data))
	}
	if !strings.Contains(string(data), "203.0.113.9") {
		t.Errorf("the new event was not appended after the existing line; got %q", string(data))
	}
}

// ── R90.1c: rotation must inherit the owner-only mode ───────────────────
//
// Rotation opens a NEW file at the same path (rotateLocked → openAuditFile),
// so a fix applied only to NewLogger's first open would leave every rotated
// generation world-readable — and the retained backups are exactly where the
// older (and often more interesting) blocks live.
func TestAttack_AuditRotationStaysOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	// 1MB cap so a handful of events forces rotation.
	lg, err := NewLogger(Config{Path: path, MaxSizeMB: 1, MaxBackups: 3})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer func() { _ = lg.Close() }()

	big := strings.Repeat("A", 64*1024)
	for i := 0; i < 40; i++ {
		if err := lg.Log(AuditEvent{Type: "packet_block", SrcIP: "203.0.113.9", Reason: big}); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	files := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// Rotated generations are named "<path>.<timestamp>" (see
		// rotateLocked), so match on the base name prefix rather than on a
		// ".log" suffix — the suffix filter silently excluded every backup
		// and made this test vacuous on the first run.
		if !strings.HasPrefix(e.Name(), "audit.log") {
			continue
		}
		files++
		info, err := e.Info()
		if err != nil {
			t.Fatalf("Info(%s): %v", e.Name(), err)
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s has mode %04o after rotation — a rotated generation of the audit trail is readable outside the firewall's UID", e.Name(), perm)
		}
	}
	if files < 2 {
		t.Fatalf("rotation did not happen: only %d audit.log* file(s) in %s — the test would be vacuous", files, dir)
	}
}
