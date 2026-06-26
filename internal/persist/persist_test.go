package persist

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	state := &EngineState{
		BlockStats: map[string]int64{
			"blocked SSH":  42,
			"SYN flood":     7,
			"port scan":     3,
		},
	}

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
	if loaded.BlockStats["blocked SSH"] != 42 {
		t.Errorf("blocked SSH = %d, want 42", loaded.BlockStats["blocked SSH"])
	}
	if loaded.BlockStats["SYN flood"] != 7 {
		t.Errorf("SYN flood = %d, want 7", loaded.BlockStats["SYN flood"])
	}
}

func TestLoadStateNoFile(t *testing.T) {
	state, err := LoadState("/nonexistent/state.json")
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if state != nil {
		t.Error("expected nil for missing file")
	}
}

func TestSaveLoadEmptyBlockStats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	if err := SaveState(path, &EngineState{}); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	loaded, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	// Empty block stats map should load without error
	_ = loaded
}

func TestSaveNilPath(t *testing.T) {
	if err := SaveState("", nil); err != nil {
		t.Errorf("SaveState nil: %v", err)
	}
}

func TestLoadEmptyPath(t *testing.T) {
	state, err := LoadState("")
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if state != nil {
		t.Error("expected nil for empty path")
	}
}

func TestCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	os.WriteFile(path, []byte("{corrupt"), 0644)

	_, err := LoadState(path)
	if err == nil {
		t.Error("expected error for corrupt file")
	}
}
