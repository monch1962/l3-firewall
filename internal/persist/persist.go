// Package persist provides state persistence for firewall components.
package persist

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// EngineState holds the serializable state of the firewall engine.
type EngineState struct {
	BlockStats map[string]int64 `json:"block_stats"`
}

// SaveState writes the engine state to a JSON file atomically.
func SaveState(path string, state *EngineState) error {
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
// Returns nil if the file does not exist (first run).
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
	if err := json.NewDecoder(f).Decode(&state); err != nil {
		return nil, fmt.Errorf("decoding state: %w", err)
	}
	return &state, nil
}
