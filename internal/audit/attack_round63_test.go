// Red-team security hardening Round 63 — audit rotation cleanup:
// unbounded directory scan on rotation.
//
// cleanupLocked() runs when the audit log rotates (every MaxSizeMB of
// events — attacker-triggerable: a sustained blocked-packet flood
// generates audit events, forcing a rotation). The R60 ReadDir fix
// removed glob-metachar expansion but left the scan unbounded:
// os.ReadDir reads the ENTIRE directory into memory and the removal
// loop deletes every matching backup beyond MaxBackups. An attacker
// with write access to the log directory (the DEFAULT
// /tmp/l3-firewall is attacker-writable) plants a large number of
// files, and each rotation pays an O(N) allocation + syscall burst —
// audit.Log runs on the packet hot path, so this stalls the receive
// loop (queue overflow → all traffic dropped, the R55 impact chain).
//
// R63 FIX: bound the scan to a fixed number of directory entries per
// rotation (maxCleanupEntries, via Readdirnames in one bounded chunk):
// memory and syscalls per rotation are O(1) regardless of directory
// contents. Leftover stale backups beyond the window are pruned on
// subsequent rotations (each rotation removes the oldest matches
// first, and the survivors sort inside the window, so cleanup
// converges). An attacker stuffing the directory with files that sort
// before the firewall's own backups can delay cleanup of those backups
// — but that is the attacker's own disk-fill capability, and the
// firewall's per-rotation cost stays bounded either way.
package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// ── R63.1: cleanup must not do unbounded work per rotation ─────────────
// RED (pre-fix): with N attacker-planted matching backups, one rotation
// deletes all but MaxBackups of them — O(N) removals from an O(N)
// directory read on the hot path. GREEN (post-fix): at most
// maxCleanupEntries entries are examined per rotation, so the number
// of removals (and the memory) is bounded regardless of how many files
// the attacker planted.
func TestAttack_CleanupScanBoundedPerRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	// Plant 5000 attacker backups named inside the firewall's rotated
	// namespace. maxCleanupEntries is 4096 — a bounded cleanup can see
	// at most that many entries (and thus can delete at most that many
	// matches minus MaxBackups) in a single rotation.
	planted := 5000
	for i := 0; i < planted; i++ {
		name := fmt.Sprintf("audit.log.%012dZ", i)
		if err := os.WriteFile(filepath.Join(dir, name), []byte("attacker"), 0644); err != nil {
			t.Fatalf("planting %s: %v", name, err)
		}
	}

	l, err := NewLogger(Config{Path: logPath, MaxBackups: 2})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	// Trigger one rotation (rotation is what runs cleanupLocked).
	if err := l.rotateLocked(); err != nil {
		t.Fatalf("rotateLocked: %v", err)
	}

	// Count how many planted files the rotation removed.
	removed := 0
	for i := 0; i < planted; i++ {
		if _, err := os.Stat(filepath.Join(dir, fmt.Sprintf("audit.log.%012dZ", i))); err != nil {
			removed++
		}
	}
	if removed > 4096 {
		t.Errorf("R63 RED: one rotation removed %d attacker-planted files — cleanup scanned/deleted unbounded directory contents; per-rotation work must be bounded", removed)
	}
}

// ── R63.2: the MaxBackups cap is still enforced ────────────────────────
// Regression guard: the bounded scan must preserve the rotation cap for
// the logger's own backups (the R60 contract).
func TestAttack_CleanupOwnBackupsStillCapped(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	l, err := NewLogger(Config{Path: logPath, MaxBackups: 2})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	// Force several rotations so real backups accumulate.
	for i := 0; i < 6; i++ {
		if err := l.rotateLocked(); err != nil {
			t.Fatalf("rotateLocked %d: %v", i, err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	backups := 0
	for _, e := range entries {
		if e.Name() != "audit.log" && len(e.Name()) > len("audit.log.") &&
			e.Name()[:len("audit.log.")] == "audit.log." {
			backups++
		}
	}
	if backups > 2 {
		t.Errorf("expected at most 2 rotated backups after cleanup, got %d", backups)
	}
}
