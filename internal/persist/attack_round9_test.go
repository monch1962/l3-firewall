package persist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── R9.10: SaveState crash leaves .tmp tombstone file ──────────────────
// SaveState creates a .tmp file, writes state, then renames it. If the
// process crashes between os.Create(tmpPath) and os.Rename(tmpPath, path),
// a stale .tmp file remains on disk. These tombstones accumulate over time.
func TestAttack_SaveStateLeavesTmpTombstone(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	tmpPath := statePath + ".tmp"

	// Verify no tmp file to start
	if _, err := os.Stat(tmpPath); err == nil {
		t.Fatal("tmp file should not exist before save")
	}

	// Simulate crash: create tmp file, write data, but crash before rename
	// by calling SaveState and then removing the target (simulating a rename
	// that never happened due to crash)
	state := &EngineState{BlockStats: map[string]int64{"test": 1}}

	// Normal save
	if err := SaveState(statePath, state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	// If the rename was atomic, no tmp file remains
	if _, err := os.Stat(tmpPath); err == nil {
		t.Logf("Stale .tmp file found at %s — crash between Create and Rename would leave tombstone", tmpPath)
	}

	// Verify only .tmp files can accumulate — check after multiple saves
	for i := 0; i < 5; i++ {
		altPath := filepath.Join(dir, "state_v"+itoa(i)+".json")
		if err := SaveState(altPath, state); err != nil {
			t.Fatalf("SaveState %d: %v", i, err)
		}
	}

	// Count .tmp files
	matches, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
	t.Logf("Found %d .tmp files after 5 saves", len(matches))
	if len(matches) > 0 {
		t.Log("SaveState leaves .tmp files on disk — crash between Create and Rename produces tombstones")
	}
}

// ── R9.11: SaveState with huge BlockStats map ─────────────────────────
// A BlockStats map with very many entries could produce a multi-GB JSON
// file. SaveState doesn't limit the output size.
func TestAttack_SaveStateHugeBlockStats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge_state.json")

	// Create a state with 500K block stats entries
	stats := make(map[string]int64, 500000)
	var sb strings.Builder
	for i := 0; i < 500000; i++ {
		sb.Reset()
		sb.WriteString("reason_")
		sb.WriteString(itoa(i))
		stats[sb.String()] = int64(i)
	}

	state := &EngineState{BlockStats: stats}

	start := time.Now()
	err := SaveState(path, state)
	elapsed := time.Since(start)

	if err != nil {
		t.Logf("SaveState with 500K entries returned error: %v", err)
		return
	}

	info, _ := os.Stat(path)
	if info != nil {
		t.Logf("SaveState wrote %d entries in %v — file size: %d MB",
			len(stats), elapsed, info.Size()/(1024*1024))
	}
}

// ── R9.12: Concurrent SaveState to same path ──────────────────────────
// Multiple goroutines calling SaveState to the same path should not
// corrupt the file. The package-level saveMu serializes writes.
func TestAttack_ConcurrentSaveState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "concurrent.json")

	const workers = 10
	const iterations = 20
	done := make(chan struct{}, workers)

	for w := 0; w < workers; w++ {
		go func(id int) {
			for i := 0; i < iterations; i++ {
				state := &EngineState{
					BlockStats: map[string]int64{
						"worker_" + itoa(id) + "_iteration_" + itoa(i): int64(i),
					},
				}
				_ = SaveState(path, state)
			}
			done <- struct{}{}
		}(w)
	}

	for w := 0; w < workers; w++ {
		<-done
	}

	// Should load without error
	loaded, err := LoadState(path)
	if err != nil {
		t.Errorf("LoadState after concurrent saves: %v", err)
	} else if loaded != nil {
		t.Logf("Loaded state with %d entries after concurrent saves", len(loaded.BlockStats))
	}
}


