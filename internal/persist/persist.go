// Package persist provides state persistence for firewall components.
package persist

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// saveMu serializes SaveState calls to prevent race conditions on the
// shared temp file path.
var saveMu sync.Mutex

// maxStateFileSize is the maximum allowed state file size (10MB).
// Prevents memory exhaustion from malicious/overly large state files.
const maxStateFileSize = 10 * 1024 * 1024

// EngineState holds the serializable state of the firewall engine.
type EngineState struct {
	BlockStats map[string]int64 `json:"block_stats"`
}

// SaveState writes the engine state to a JSON file atomically.
// Uses a package-level mutex to serialize concurrent calls on the
// shared .tmp file path.
func SaveState(path string, state *EngineState) error {
	saveMu.Lock()
	defer saveMu.Unlock()
	if path == "" || state == nil {
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating state dir: %w", err)
	}
	tmpPath := path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("creating temp state file: %w", err)
	}
	if err := json.NewEncoder(f).Encode(state); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("encoding state: %w", err)
	}
	f.Close()
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("renaming state file: %w", err)
	}
	return nil
}

// LoadState reads the engine state from a JSON file.
// Returns nil if the file does not exist (first run). A size limit of
// maxStateFileSize is enforced to prevent memory exhaustion attacks.
func LoadState(path string) (*EngineState, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("opening state file: %w", err)
	}
	defer f.Close()
	var state EngineState
	if err := json.NewDecoder(io.LimitReader(f, maxStateFileSize+1)).Decode(&state); err != nil {
		return nil, fmt.Errorf("decoding state: %w", err)
	}
	if state.BlockStats == nil {
		state.BlockStats = make(map[string]int64)
	}
	return &state, nil
}
