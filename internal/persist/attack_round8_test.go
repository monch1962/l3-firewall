package persist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── R8.5: LoadState with huge file — no io.LimitReader ────────────────
// A malicious state file of several GB could exhaust memory during loading.
// LoadState uses json.NewDecoder without any size limit.
func TestAttack_LoadStateHugeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.json")

	// Create a 200MB state file
	var sb strings.Builder
	sb.Grow(200 * 1024 * 1024)
	sb.WriteString(`{"block_stats":{`)
	for i := 0; i < 2000000; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		s := itoa(i)
		sb.WriteString(`"key_`)
		sb.WriteString(s)
		sb.WriteString(`":`)
		sb.WriteString(s)
	}
	sb.WriteString("}}")

	if err := os.WriteFile(path, []byte(sb.String()), 0644); err != nil {
		t.Fatalf("write huge file: %v", err)
	}

	fileInfo, _ := os.Stat(path)
	t.Logf("State file size: %d MB", fileInfo.Size()/(1024*1024))

	// LoadState should reject files above a reasonable size
	done := make(chan struct{})
	var loadErr error
	go func() {
		_, loadErr = LoadState(path)
		close(done)
	}()

	select {
	case <-done:
		if loadErr == nil {
			t.Error("LoadState accepted 200MB file with no error — needs io.LimitReader or size cap")
		} else {
			t.Logf("LoadState correctly rejected huge file: %v", loadErr)
		}
	case <-time.After(5 * time.Second):
		t.Error("LoadState hung on huge file — needs io.LimitReader or hard size cap")
	}
}

// ── R8.6: SaveState path traversal ────────────────────────────────────
// SaveState creates directories and files at the given path without
// validation. An attacker who can control --state-file could write
// files outside the intended directory.
func TestAttack_SaveStatePathTraversal(t *testing.T) {
	dir := t.TempDir()
	traversalPath := filepath.Join(dir, "..", "..", "escape_test", "state.json")
	state := &EngineState{BlockStats: map[string]int64{"test": 1}}

	err := SaveState(traversalPath, state)
	if err != nil {
		t.Logf("SaveState with traversal path returned error: %v", err)
	} else {
		expectedOutside := filepath.Join(dir, "..", "..", "escape_test", "state.json")
		if _, err := os.Stat(expectedOutside); err == nil {
			t.Log("WARNING: SaveState wrote file outside intended directory via path traversal (config input, low risk)")
		}
	}
}

// ── R8.7: LoadState with sparse file ──────────────────────────────────
// A sparse state file reports a large size but uses minimal disk space.
// This could still cause memory exhaustion during loading.
func TestAttack_LoadStateSparseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sparse.json")

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create sparse file: %v", err)
	}
	if _, err := f.Seek(50*1024*1024, 0); err != nil {
		f.Close()
		t.Skip("seek not supported:", err)
	}
	if _, err := f.Write([]byte("}")); err != nil {
		f.Close()
		t.Fatalf("write sparse byte: %v", err)
	}
	f.Close()

	done := make(chan struct{})
	var loadErr error
	go func() {
		_, loadErr = LoadState(path)
		close(done)
	}()

	select {
	case <-done:
		if loadErr == nil {
			t.Error("LoadState accepted 50MB sparse file — needs io.LimitReader")
		} else {
			t.Logf("LoadState correctly rejected sparse file: %v", loadErr)
		}
	case <-time.After(3 * time.Second):
		t.Error("LoadState hung on sparse file — needs io.LimitReader")
	}
}

// ── R8.8: SaveState with nil BlockStats map ───────────────────────────
// SaveState with nil BlockStats serializes as null. On reload, this
// could cause nil map write panic when the caller tries to add entries.
func TestAttack_SaveStateNilBlockStats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nil_stats.json")

	state := &EngineState{BlockStats: nil}
	if err := SaveState(path, state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	loaded, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadState returned nil")
	}

	// The real attack: trying to write to loaded.BlockStats after reloading
	// a nil map causes panic
	if loaded.BlockStats == nil {
		recovered := false
		func() {
			defer func() {
				if r := recover(); r != nil {
					recovered = true
				}
			}()
			// This would panic on nil map assignment
			loaded.BlockStats["new_key"] = 42
		}()

		if recovered {
			t.Error("nil BlockStats after LoadState causes panic on write — SaveState should ensure non-nil map on reload")
		} else {
			t.Log("nil BlockStats map handled without panic after load")
		}
	} else {
		t.Log("LoadState returned non-nil BlockStats map")
	}
}
