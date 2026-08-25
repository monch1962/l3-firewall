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

	"github.com/monch1962/l3-firewall/internal/securepath"
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
	// Reject symlinks at any directory component of the path: O_NOFOLLOW
	// on the .tmp open below only protects the FINAL component — a symlink
	// planted at the directory path (e.g. --state-file /tmp/state/state.json
	// where /tmp/state -> /victim) is followed by the kernel and every
	// write lands in the victim directory as the firewall's UID (R45 —
	// directory symlink write-through). Must run AFTER MkdirAll: MkdirAll
	// "succeeds" through a planted link, so the walk is the only signal.
	if err := securepath.RejectSymlinkComponents(dir); err != nil {
		return err
	}
	tmpPath := path + ".tmp"
	// Open with O_NOFOLLOW: os.Create would follow a symlink planted at the
	// .tmp path by an attacker with write access to the state directory,
	// truncating and overwriting an arbitrary file writable by the firewall's
	// UID (R42 — symlink write-through). A symlink at the .tmp path is never
	// legitimate; rename over the final path is already symlink-safe.
	// Also O_NONBLOCK: opening an existing FIFO planted at the .tmp path
	// O_WRONLY (without O_NONBLOCK) blocks until a reader appears — the
	// 60-second saveState ticker goroutine would hang forever, and with it
	// the same tick's conntrack.Expire/ratelimit.Cleanup (availability DoS;
	// R55 — the R38 FIFO class applied to the CREATE open, where O_NOFOLLOW
	// alone does not protect). With O_NONBLOCK the FIFO open fails
	// immediately with ENXIO; regular files are unaffected.
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0666)
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
// Paths containing ".." are rejected — the sibling-path mirror of
// SaveState's R13 guard: --state-file is operator-influenced (may come
// from a partially-attacker-edited config), and the same path is WRITTEN
// by SaveState, so an unguarded LoadState lets an attacker-influenced
// path read ANY readable file that parses as EngineState JSON, injecting
// attacker-chosen BlockStats into engine.restoreState and the admin API
// (R59 — the R13 guard covered only the writer; the reader was missed).
func LoadState(path string) (*EngineState, error) {
	if path == "" {
		return nil, nil
	}
	// Reject path traversal (..) to prevent reading files outside the
	// intended directory — mirrors the SaveState guard (R13).
	if strings.Contains(path, "..") {
		return nil, fmt.Errorf("path traversal rejected: %s", path)
	}
	// Reject symlinks at directory components (R62 — the R45 walk
	// mirrored from the writer): SaveState rejects directory symlinks via
	// securepath.RejectSymlinkComponents and final-component symlinks via
	// O_NOFOLLOW on the .tmp create (R42/R45), but the sibling READER of
	// the same path followed symlinks at every component — R11.11 even
	// enshrined the follow behavior as a passing test. An attacker with
	// write access to the state directory (the R42/R45/R55 threat model)
	// plants state.json -> /crafted/state.json; at startup engine.Run →
	// restoreState → LoadState follows the link, and a target that parses
	// as EngineState JSON injects attacker-chosen BlockStats into engine
	// state — served on the default-unauthenticated /admin/block-stats
	// (R46) and re-persisted by the next saveState tick (R59's documented
	// impact chain, which the R59 ".." guard did not close). The walk
	// tolerates non-existent components, so a first run with no state
	// directory still returns (nil, nil) unchanged.
	if err := securepath.RejectSymlinkComponents(filepath.Dir(path)); err != nil {
		return nil, err
	}
	// Open with O_NONBLOCK to prevent blocking on FIFO/named pipes.
	// On Linux, O_NONBLOCK has no effect on regular file reads, so
	// subsequent JSON decoding works normally. By opening first and
	// checking the file type via f.Stat() on the opened fd, we
	// eliminate the TOCTOU race between an os.Stat(path) check and
	// the subsequent os.Open(path) — an attacker cannot replace the
	// file between the type check and the open, because the type
	// check operates on the already-opened file descriptor.
	// O_NOFOLLOW (R62) rejects a symlink planted at the FINAL path
	// component — the R42 create-open guard mirrored to the reader:
	// without it the open follows the link and f.Stat() reports the
	// TARGET's mode, passing the regular-file check while reading
	// attacker-chosen content (the R11.11 follow-symlink behavior).
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
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
