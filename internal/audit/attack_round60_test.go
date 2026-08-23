// Red-team security hardening Round 60 — glob metacharacter injection into
// audit's rotation-backup cleanup pattern.
//
// cleanupLocked() builds its match pattern from the operator/attacker-
// influenced --audit-log-path: pattern := cfg.Path + ".*". filepath.Glob
// interprets glob metacharacters (*, ?, [) IN the path — a config like
// /base/audit[1].log expands to match /base/audit1.log.* (the literal
// SIBLING namespace), so:
//
//	(1) os.Remove deletes audit1.log.* files the firewall never created
//	    (arbitrary deletion as the firewall's UID), and
//	(2) the firewall's OWN rotated backups (literal /base/audit[1].log.<ts>)
//	    never match the pattern, so cleanup never prunes them and the
//	    MaxBackups cap is defeated — unbounded disk growth. The R57/R59
//	    path guards reject ".." and symlink components but never considered
//	    glob metacharacters in the path (same class as capture R60.1).
//
// R60 FIX: list the log's directory with os.ReadDir and filter by
// base-name prefix instead of globbing — no pattern interpretation.
package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// ── R60.1: rotation cleanup must NOT delete sibling-namespace backups ──
// RED (pre-fix): cfg.Path = /base/audit[1].log makes the glob pattern
// /base/audit[1].log.* match /base/audit1.log.*; with more matches than
// MaxBackups, cleanupLocked os.Removes the oldest of THEM — deleting files
// the firewall never created. GREEN (post-fix): ReadDir + prefix filter
// only sees the literal audit[1].log.* namespace; victims survive.
func TestAttack_CleanupGlobMetacharNoSiblingDeletion(t *testing.T) {
	base := t.TempDir()
	logPath := filepath.Join(base, "audit[1].log") // literal path with glob metachars

	// Victim files in the SIBLING namespace (never created by the logger).
	// Three victims with MaxBackups=1: the vulnerable glob matches all three
	// and deletes the two lexicographically oldest.
	victims := []string{
		"audit1.log.20260101T000000Z",
		"audit1.log.20260102T000000Z",
		"audit1.log.20260103T000000Z",
	}
	for _, v := range victims {
		if err := os.WriteFile(filepath.Join(base, v), []byte("victim"), 0644); err != nil {
			t.Fatalf("write victim: %v", err)
		}
	}

	l, err := NewLogger(Config{Path: logPath, MaxBackups: 1})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	// Trigger a rotation directly (rotation is what runs cleanupLocked).
	if err := l.rotateLocked(); err != nil {
		t.Fatalf("rotateLocked: %v", err)
	}

	// No sibling-namespace victim may be deleted.
	for _, v := range victims {
		if _, err := os.Stat(filepath.Join(base, v)); err != nil {
			t.Errorf("R60 RED: sibling victim %s was deleted by glob metachar expansion (%v)", v, err)
		}
	}
}
