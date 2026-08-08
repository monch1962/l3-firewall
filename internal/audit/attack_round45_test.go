package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// ── R45.8: NewLogger audit-log directory symlink write-through ──────
// The default audit path is /tmp/l3-firewall/audit.log — /tmp is
// world-writable, so an attacker can plant /tmp/l3-firewall as a symlink
// to a victim directory BEFORE the firewall starts. NewLogger's
// os.MkdirAll "succeeds" (path exists through the link) and
// openAuditFile's O_NOFOLLOW only protects the FILE component — every
// audit append resolves through the directory symlink into the victim
// directory as the firewall's UID (arbitrary file append/create).
func TestAttack_NewLoggerDirectorySymlinkWriteThrough(t *testing.T) {
	victimDir := t.TempDir()

	parentDir := t.TempDir()
	logDir := filepath.Join(parentDir, "l3-firewall")
	if err := os.Symlink(victimDir, logDir); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	logPath := filepath.Join(logDir, "audit.log")
	_, err := NewLogger(Config{Path: logPath})

	if err == nil {
		t.Error("NewLogger accepted a symlinked log directory — expected rejection")
	}
	if _, statErr := os.Stat(filepath.Join(victimDir, "audit.log")); statErr == nil {
		t.Error("audit.log was created in the victim directory through the symlink")
	}
}

// ── R45.9: NewLogger still works on a genuine directory ─────────────
func TestAttack_NewLoggerRealDirectoryStillWorks(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	l, err := NewLogger(Config{Path: logPath})
	if err != nil {
		t.Fatalf("NewLogger on a real directory failed: %v", err)
	}
	if l == nil {
		t.Fatal("NewLogger returned nil on a real directory")
	}
}
