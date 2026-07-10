// Package persist provides state persistence for firewall components.
package persist

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
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
// shared .tmp file path. Rejects paths with ".." to prevent path
// traversal attacks when --state-file is attacker-influenced.
func SaveState(path string, state *EngineState) error {
	saveMu.Lock()
	defer saveMu.Unlock()
	if path == "" || state == nil {
		return nil
	}
	// Reject path traversal (..) to prevent writing files outside
	// the intended directory.
	if strings.Contains(path, "..") {
		return fmt.Errorf("path traversal rejected: %s", path)
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
		os.Remove(tmpPath) // Clean up temp file on rename failure (e.g., cross-device link)
		return fmt.Errorf("renaming state file: %w", err)
	}
	return nil
}

// LoadState reads the engine state from a JSON file.
// Returns nil if the file does not exist (first run). A size limit of
// maxStateFileSize is enforced to prevent memory exhaustion attacks.
// Non-regular files (named pipes, device files, directories) are
// rejected to prevent blocking on FIFO hangs (DoS via --state-file).
func LoadState(path string) (*EngineState, error) {
	if path == "" {
		return nil, nil
	}
	// Open with O_NONBLOCK to prevent blocking on FIFO/named pipes.
	// On Linux, O_NONBLOCK has no effect on regular file reads, so
	// subsequent JSON decoding works normally. By opening first and
	// checking the file type via f.Stat() on the opened fd, we
	// eliminate the TOCTOU race between an os.Stat(path) check and
	// the subsequent os.Open(path) — an attacker cannot replace the
	// file between the type check and the open, because the type
	// check operates on the already-opened file descriptor.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("opening state file: %w", err)
	}
	defer f.Close()

	// Check file type on the opened fd (no TOCTOU — the fd is already open).
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stating state file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("state path is not a regular file: %s", path)
	}

	var state EngineState
	if err := json.NewDecoder(io.LimitReader(f, maxStateFileSize+1)).Decode(&state); err != nil {
		return nil, fmt.Errorf("decoding state: %w", err)
	}
	if state.BlockStats == nil {
		state.BlockStats = make(map[string]int64)
	}
	return &state, nil
}
