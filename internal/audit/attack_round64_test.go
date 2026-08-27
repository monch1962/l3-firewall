package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── R64.1: rotation-time directory symlink swap (audit) ─────────────
// R45's securepath walk runs ONCE at NewLogger; every rotation re-resolves
// the log path FRESH (os.Rename of cfg.Path, openAuditFile, and the
// cleanup directory scan). The DEFAULT log directory /tmp/l3-firewall sits
// in world-writable /tmp, so ANY local user can rename it and plant a
// symlink to an arbitrary directory the firewall's UID (typically root)
// can write — at any time during the firewall's run. The next rotation
// then: (1) renames an existing victim audit.log to audit.log.<ts>, (2)
// creates a new audit.log and appends attacker-floodable JSON events into
// the attacker-chosen directory as root, and (3) deletes audit.log.*
// backups there. Without a pre-placed victim file the rename fails AFTER
// l.file.Close() — permanently destroying the audit trail (every
// subsequent event dropped plus a warning-log flood per event). The R45
// construction-time walk does not cover any of this: the swap happens
// after the firewall starts.
func TestAttack_RotateDirectorySymlinkSwapNoWriteThrough(t *testing.T) {
	parentDir := t.TempDir()
	dir := filepath.Join(parentDir, "l3-firewall")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir log dir: %v", err)
	}
	victimDir := t.TempDir()

	logPath := filepath.Join(dir, "audit.log")
	l, err := NewLogger(Config{Path: logPath, MaxSizeMB: 1, MaxBackups: 2})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	// Pre-place a victim file so the rotation rename would succeed through
	// the swapped-in symlink (without it the rename fails — but only after
	// the real fd is already closed, destroying the trail either way).
	victimLog := filepath.Join(victimDir, "audit.log")
	if err := os.WriteFile(victimLog, []byte("victim"), 0o644); err != nil {
		t.Fatalf("write victim file: %v", err)
	}

	// Attacker swaps the configured log directory for a symlink to the
	// victim directory (rename + symlink in the parent, world-writable
	// for the default /tmp/l3-firewall).
	orig := dir + ".orig"
	if err := os.Rename(dir, orig); err != nil {
		t.Fatalf("rename log dir: %v", err)
	}
	if err := os.Symlink(victimDir, dir); err != nil {
		t.Fatalf("plant symlink: %v", err)
	}

	// Flood events past the 1MB rotation threshold.
	reason := strings.Repeat("A", 1000)
	for i := 0; i < 1200; i++ {
		_ = l.Log(AuditEvent{Type: "packet_block", Reason: reason})
	}

	// The victim file must be untouched: no rename-through, no appends.
	data, err := os.ReadFile(victimLog)
	if err != nil {
		t.Fatalf("reading victim file: %v", err)
	}
	if string(data) != "victim" {
		t.Errorf("victim audit.log modified through swapped-in dir symlink: got %.40q", data)
	}
	entries, err := os.ReadDir(victimDir)
	if err != nil {
		t.Fatalf("reading victim dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "audit.log.") {
			t.Errorf("victim audit backup created through swapped-in dir symlink: %s", e.Name())
		}
	}
}

// ── R64.2: regression — real directories still rotate after the check ─
// The R64 fix must not break normal rotation on genuine directories.
func TestAttack_RotateRealDirectoryStillWorks(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	l, err := NewLogger(Config{Path: logPath, MaxSizeMB: 1, MaxBackups: 2})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	reason := strings.Repeat("B", 1000)
	for i := 0; i < 1200; i++ {
		if err := l.Log(AuditEvent{Type: "packet_block", Reason: reason}); err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}
	matches, err := filepath.Glob(logPath + ".*")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) == 0 {
		t.Error("expected at least one rotated backup after 1MB of events")
	}
}
