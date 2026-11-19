package persist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── R93.1 (persist integration): hardlink write-through on the state .tmp ──
//
// SaveState writes <state-file>.tmp and renames it into place. R42 hardened
// that open against a symlink (O_NOFOLLOW), R45 against a directory symlink
// and R55 against a FIFO — all pushed into securepath.CreateOwnerOnly. A hard
// link at the SAME predictable path defeats all three: O_NOFOLLOW refuses only
// symbolic links, and a hard link is the inode itself.
//
// An attacker with write access to the state directory (the standing
// R42/R45/R55 threat model) links <state-file>.tmp to a file the firewall's
// UID can write — its own audit log or pcap evidence always qualifies, and any
// co-tenant file owned by the same UID on a shared volume does too. The next
// 60-second saveState tick opens it O_WRONLY|O_TRUNC and the linked file's
// contents are replaced by the state JSON.
func TestAttack_SaveStateHardLinkedTmpDestroysVictim(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "evidence.log")
	const secret = "AUDIT EVIDENCE THAT MUST SURVIVE\n"
	if err := os.WriteFile(victim, []byte(secret), 0o600); err != nil {
		t.Fatalf("seeding victim: %v", err)
	}
	statePath := filepath.Join(dir, "state.json")
	if err := os.Link(victim, statePath+".tmp"); err != nil {
		t.Fatalf("creating hard link at the .tmp path: %v", err)
	}

	err := SaveState(statePath, &EngineState{BlockStats: map[string]int64{"blocked SSH": 3}})
	if err == nil {
		t.Error("SaveState accepted a hard-linked .tmp path and overwrote the linked inode")
	} else if !strings.Contains(err.Error(), "hard") && !strings.Contains(err.Error(), "link") {
		t.Logf("SaveState error (expected a hard-link refusal): %v", err)
	}

	got, rerr := os.ReadFile(victim)
	if rerr != nil {
		t.Fatalf("victim unreadable after attack: %v", rerr)
	}
	if string(got) != secret {
		t.Errorf("hardlink write-through destroyed %s: got %q, want %q", victim, string(got), secret)
	}
}

// The same path must still work normally once no link is planted: a refused
// save must not leave a half-written temp file that blocks the next attempt.
func TestAttack_SaveStateRecoversAfterRefusedHardLink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.dat")
	if err := os.WriteFile(victim, []byte("keep me"), 0o600); err != nil {
		t.Fatalf("seeding victim: %v", err)
	}
	statePath := filepath.Join(dir, "state.json")
	linkPath := statePath + ".tmp"
	if err := os.Link(victim, linkPath); err != nil {
		t.Fatalf("creating hard link: %v", err)
	}
	if err := SaveState(statePath, &EngineState{BlockStats: map[string]int64{"a": 1}}); err == nil {
		t.Fatal("SaveState accepted a hard-linked .tmp path")
	}
	// Operator/administrator removes the planted link.
	if err := os.Remove(linkPath); err != nil {
		t.Fatalf("removing planted link: %v", err)
	}
	if err := SaveState(statePath, &EngineState{BlockStats: map[string]int64{"a": 2}}); err != nil {
		t.Fatalf("SaveState after the link was removed: %v", err)
	}
	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if state == nil || state.BlockStats["a"] != 2 {
		t.Errorf("state not persisted after recovery: %+v", state)
	}
	if got, _ := os.ReadFile(victim); string(got) != "keep me" {
		t.Errorf("victim content = %q, want %q", string(got), "keep me")
	}
}
