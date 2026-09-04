// Red-team security hardening Round 72 — audit rotation cleanup: the R69
// unsorted-Readdirnames removal class, still present on the audit path.
//
// R69 fixed capture.cleanupLocked: os.File.Readdirnames returns DIRECTORY
// order, not sorted order (empirically: reverse-creation order on tmpfs,
// hash order on ext4), and removal loops that delete the FRONT of the
// unsorted slice destroy the newest files while the oldest survive —
// retention inverted. The audit cleanupLocked carries the identical
// structure AND the identical false comment ("Names are returned in
// sorted order, so the matches found are the OLDEST backups" — the exact
// claim R69 disproved for capture) and was never fixed: R69 scoped the
// capture sort + current-file skip to capture only.
//
// Impact on audit: rotateLocked renames the current audit.log to
// audit.log.<UTC timestamp> FIRST, then runs cleanupLocked. The backup
// created moments earlier by THIS rotation is the NEWEST entry in the
// directory, so on tmpfs (the default audit location /tmp/l3-firewall
// sits on tmpfs on this host — reverse-creation readdir order) it is
// matches[0] — the FIRST file the removal loop deletes when the backup
// count exceeds MaxBackups. Consequences:
//  1. The freshest rotated audit data — the only copy of the events
//     that triggered the rotation — is destroyed at the moment of its
//     creation, on every rotation, with NO attacker involved (pure
//     operator rotation past MaxBackups backups).
//  2. Retention is INVERTED and FROZEN: the surviving MaxBackups are
//     the OLDEST backups; the trail never advances past the first set
//     (each new rotation's backup is deleted while the initial old
//     backups persist forever). Under the standing R42/R45/R60/R63
//     threat model (attacker with write access to the DEFAULT
//     /tmp/l3-firewall), planted old-named backups sort to the END of
//     the reverse-creation list and are never removed while real
//     backups are destroyed — the SIEM/compliance trail is silently
//     gutted of its newest history.
//
// R72 FIX (mirroring R69): sort.Strings(matches) before the removal loop.
// The rotated names (audit.log.<UTC yyyymmddThhmmssZ>) are fixed-width
// and sort lexicographically = chronologically, so after sorting the
// removal targets exactly the oldest backups and the newest MaxBackups
// (including the just-rotated file) survive — the documented "keep only
// MaxBackups most recent" contract (audit.go rotateLocked comment).
package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── R72.1: cleanup must never delete the backup THIS rotation just ─────
// created (the freshest audit data), and must not let planted old-named
// backups survive while real ones are destroyed. RED (pre-fix, on
// reverse-creation-order filesystems such as this host's tmpfs): the
// fresh backup is matches[0] and is removed first; the OLDEST planted
// backup survives — retention inverted.
func TestAttack_CleanupUnsortedRemovalKeepsNewestBackup(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	// Planted old backups (created BEFORE any rotation). Under the
	// standing threat model these are attacker files in the DEFAULT
	// /tmp/l3-firewall dir; their names sort oldest.
	planted := []string{
		"audit.log.20260101T000000Z",
		"audit.log.20260102T000000Z",
		"audit.log.20260103T000000Z",
	}
	for _, name := range planted {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("planted"), 0644); err != nil {
			t.Fatalf("planting %s: %v", name, err)
		}
	}

	l, err := NewLogger(Config{Path: logPath, MaxBackups: 1})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	// One rotation: audit.log is renamed to a fresh timestamped backup
	// (the ONLY real backup — containing the pre-rotation audit events),
	// then cleanupLocked runs.
	if err := l.rotateLocked(); err != nil {
		t.Fatalf("rotateLocked: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var backups []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "audit.log.") {
			backups = append(backups, e.Name())
		}
	}

	// The cap contract (at most MaxBackups files) must hold.
	if len(backups) > 1 {
		t.Fatalf("R72 RED: %d backups remain after cleanup, want <= MaxBackups(1) — retention cap broken", len(backups))
	}
	// The survivor must be the backup THIS rotation created — the
	// freshest audit data — not a planted old file.
	now := time.Now().UTC().Format("20060102T150405Z")
	freshName := "audit.log." + now
	keptFresh := false
	for _, b := range backups {
		if b == freshName {
			keptFresh = true
		}
		for _, p := range planted {
			if b == p {
				t.Errorf("R72 RED: planted OLD backup %s survived cleanup while the fresh rotation backup (%s) was destroyed — the unsorted removal loop deleted the NEWEST match (matches[0] on reverse-creation readdir order); retention is inverted: the newest audit history is silently lost and the oldest stale files persist", p, freshName)
			}
		}
	}
	if !keptFresh {
		t.Errorf("R72 RED: the backup created by this rotation (%s) does not survive cleanup — the freshest rotated audit data was deleted by its own rotation's unsorted removal (front of the slice = newest on this host's tmpfs)", freshName)
	}
}

// ── R72.2: regression guard — partial removal (toRemove < len(matches)) ─
// must remove the OLDEST matches and keep the newest MaxBackups. After
// the R69-style sort, planted old backups are pruned first and the fresh
// backup survives.
func TestAttack_CleanupSortedRemovalKeepsNewestSet(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	planted := []string{
		"audit.log.20260101T000000Z",
		"audit.log.20260102T000000Z",
		"audit.log.20260103T000000Z",
	}
	for _, name := range planted {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("planted"), 0644); err != nil {
			t.Fatalf("planting %s: %v", name, err)
		}
	}

	l, err := NewLogger(Config{Path: logPath, MaxBackups: 2})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	if err := l.rotateLocked(); err != nil {
		t.Fatalf("rotateLocked: %v", err)
	}

	now := time.Now().UTC().Format("20060102T150405Z")
	freshName := "audit.log." + now

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	keptFresh := false
	keptPlanted := 0
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "audit.log.") {
			continue
		}
		if e.Name() == freshName {
			keptFresh = true
		}
		for _, p := range planted {
			if e.Name() == p {
				keptPlanted++
			}
		}
	}
	// 4 matches (3 planted + fresh), MaxBackups=2: exactly 2 must be
	// removed — the two OLDEST planted files. The fresh backup and ONE
	// planted (20260103, the newest planted) survive.
	if !keptFresh {
		t.Errorf("R72 RED: fresh rotation backup destroyed in partial removal — the newest data must survive cleanup (removal must target the OLDEST matches)")
	}
	if keptPlanted != 1 {
		t.Errorf("R72 RED: %d planted backups survived, want 1 (the newest planted) — cleanup removed the WRONG files (unsorted front-of-slice = newest on this host's tmpfs), retention inverted", keptPlanted)
	}
}
