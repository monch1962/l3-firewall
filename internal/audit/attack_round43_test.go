// Red-team security hardening Round 43 — symlink write-through in audit.openAuditFile
//
// R42 introduced the O_NOFOLLOW class: CREATE/TRUNC opens must carry
// syscall.O_NOFOLLOW so a symlink planted at an operator-influenced path
// cannot be followed into an arbitrary-file write primitive. R42 fixed
// persist.SaveState (.tmp create) and capture.rotateLocked (pcap rotation
// create) but audit.openAuditFile — which is ALSO a CREATE open
// (O_CREATE|O_WRONLY|O_APPEND) — was never given O_NOFOLLOW: R38 hardened it
// for the FIFO class (O_NONBLOCK + fstat regular-file check), but f.Stat()
// on the opened fd FOLLOWS the symlink target, so a symlink at the audit
// log path (default /tmp/l3-firewall/audit.log — attacker-writable) passes
// the regular-file check and turns the firewall's audit append into an
// arbitrary-file append primitive as the firewall's UID.
package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// ── R43.1: NewLogger must reject a symlink at the log path ──────────
// Attacker with write access to the audit directory (default
// /tmp/l3-firewall — world-writable on many systems) plants
// audit.log -> /etc/passwd. O_CREATE|O_WRONLY|O_APPEND follows the
// symlink, and f.Stat() reports the TARGET's mode (regular), so the
// R38 regular-file check passes. Every Log() call then appends
// attacker-influenced JSON to the victim file.
func TestAttack_NewLoggerRejectsSymlinkAtLogPath(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("precious\n"), 0644); err != nil {
		t.Fatalf("creating victim: %v", err)
	}
	logPath := filepath.Join(dir, "audit.log")
	if err := os.Symlink(victim, logPath); err != nil {
		t.Fatalf("planting symlink: %v", err)
	}

	l, err := NewLogger(Config{Path: logPath})
	if err == nil {
		// Pre-fix: the symlink was followed — log through it to prove the write-through.
		if lerr := l.Log(AuditEvent{Type: "packet_block", SrcIP: "6.6.6.6"}); lerr != nil {
			t.Logf("NewLogger followed symlink (write-through class): %v", lerr)
		}
		l.Close()
	}
	data, rerr := os.ReadFile(victim)
	if rerr != nil {
		t.Fatalf("reading victim: %v", rerr)
	}
	if string(data) != "precious\n" {
		t.Errorf("victim file was modified through the symlink — arbitrary file write as firewall UID (R42 class): got %q", data)
	}
	if err == nil {
		t.Error("NewLogger accepted a symlink at the log path — must reject with error (O_NOFOLLOW)")
	}
}

// ── R43.2: Log() through a symlink must not write the victim ────────
// Direct openAuditFile-level check: even if a caller opens the path,
// appending through a symlink must not touch the target. This is the
// hot-path primitive: the engine calls auditLogger.Log on every packet.
func TestAttack_SymlinkLogPathDoesNotWriteVictim(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep\n"), 0644); err != nil {
		t.Fatalf("creating victim: %v", err)
	}
	logPath := filepath.Join(dir, "audit.log")
	if err := os.Symlink(victim, logPath); err != nil {
		t.Fatalf("planting symlink: %v", err)
	}

	f, err := openAuditFile(logPath)
	if err == nil {
		// Pre-fix: fd refers to the victim; writing appends attacker-influenced JSON.
		_, werr := f.Write([]byte("{\"type\":\"packet_block\"}\n"))
		if werr != nil {
			t.Logf("write through symlink failed: %v", werr)
		}
		f.Close()
	}
	data, rerr := os.ReadFile(victim)
	if rerr != nil {
		t.Fatalf("reading victim: %v", rerr)
	}
	if string(data) != "keep\n" {
		t.Errorf("openAuditFile followed symlink and appended to victim: got %q", data)
	}
	if err == nil {
		t.Error("openAuditFile accepted a symlink — must return error (O_NOFOLLOW)")
	}
}
