// Package audit provides structured JSON audit logging with automatic file rotation.
//
// Use cases:
//   - SIEM integration via newline-delimited JSON
//   - Compliance audit trail for firewall events
//   - Forensic analysis of blocked/allowed traffic
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/monch1962/l3-firewall/internal/securepath"
)

// Default values for the audit logger configuration.
const (
	DefaultMaxSizeMB  = 100  // 100MB per file
	DefaultMaxBackups = 5    // keep 5 rotated files
	DefaultDirMode    = 0755 // directory permissions
)

// openAuditFile opens the audit log file with the R15 hardened pattern:
// O_NONBLOCK prevents blocking on FIFO/named pipes (startup DoS via an
// attacker-influenced --audit-log path), and the file type is checked via
// f.Stat() on the already-opened fd — no TOCTOU between a Stat and an Open.
// On Linux O_NONBLOCK has no effect on regular file writes, so normal
// append logging is unaffected.
//
// O_NOFOLLOW (R43) rejects a symlink planted at the log path: without it,
// O_CREATE|O_WRONLY|O_APPEND follows the link, and f.Stat() on the opened
// fd reports the TARGET's mode (regular), passing the R38 regular-file
// check — turning every audit append into an arbitrary-file write as the
// firewall's UID (R42 class: persist .tmp and capture rotation were fixed,
// audit was missed). Default path /tmp/l3-firewall/audit.log is
// attacker-writable.
func openAuditFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0644)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("audit log path is not a regular file: %s", path)
	}
	return f, nil
}

// AuditEvent represents a single structured audit log entry.
type AuditEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	Type       string    `json:"type"`                  // "packet_allow", "packet_block", "rate_limit", etc.
	TraceID    string    `json:"trace_id,omitempty"`    // correlation ID
	SrcIP      string    `json:"src_ip,omitempty"`      // source IP address
	DstIP      string    `json:"dst_ip,omitempty"`      // destination IP address
	Protocol   string    `json:"protocol,omitempty"`    // IP protocol
	SrcPort    uint16    `json:"src_port,omitempty"`    // source port
	DstPort    uint16    `json:"dst_port,omitempty"`    // destination port
	PacketSize int       `json:"packet_size,omitempty"` // packet size in bytes
	Reason     string    `json:"reason,omitempty"`      // why the action was taken
}

// Config controls the audit logger behaviour.
type Config struct {
	Path       string // path to the audit log file (default: /var/log/l3-firewall/audit.log)
	MaxSizeMB  int    // max file size in MB before rotation (default: 100)
	MaxBackups int    // max rotated files to keep (default: 5)
}

// Logger writes structured JSON audit events to a rotating file.
type Logger struct {
	mu      sync.Mutex
	file    *os.File
	encoder *json.Encoder
	cfg     Config
	size    int64 // current file size in bytes
	closed  bool
}

// NewLogger creates a new audit logger. If Config.Path is empty, a default is used.
// The default path is relative to avoid requiring root permissions for creation.
func NewLogger(cfg Config) (*Logger, error) {
	if cfg.Path == "" {
		cfg.Path = "/tmp/l3-firewall/audit.log"
	}
	// Reject path traversal (..): filepath.Dir below strips a ".."
	// component before securepath.RejectSymlinkComponents can reject it,
	// but the raw cfg.Path is what openAuditFile opens — the kernel
	// resolves a symlink planted at a component before the ".." and every
	// audit append lands outside the checked directory as the firewall's
	// UID (R57; persist R13 pattern — the ".." class must be rejected at
	// every file-writing consumer, not only persist).
	if strings.Contains(cfg.Path, "..") {
		return nil, fmt.Errorf("path traversal rejected: %s", cfg.Path)
	}
	if cfg.MaxSizeMB <= 0 {
		cfg.MaxSizeMB = DefaultMaxSizeMB
	}
	if cfg.MaxBackups <= 0 {
		cfg.MaxBackups = DefaultMaxBackups
	}

	// Ensure the directory exists
	dir := filepath.Dir(cfg.Path)
	if err := os.MkdirAll(dir, DefaultDirMode); err != nil {
		return nil, fmt.Errorf("creating audit log directory %s: %w", dir, err)
	}
	// Reject symlinks at any directory component of the log path: R43's
	// O_NOFOLLOW in openAuditFile only protects the FINAL component, but a
	// symlink planted at the DIRECTORY path (default /tmp/l3-firewall is
	// attacker-writable) is followed by the kernel — every audit append
	// resolves into the attacker-chosen directory as the firewall's UID
	// (R45 — directory symlink write-through).
	if err := securepath.RejectSymlinkComponents(dir); err != nil {
		return nil, err
	}

	// Open the log file for append (FIFO-hardened — see openAuditFile)
	file, err := openAuditFile(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("opening audit log %s: %w", cfg.Path, err)
	}

	// Get current file size
	fi, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("stating audit log %s: %w", cfg.Path, err)
	}

	return &Logger{
		file:    file,
		encoder: json.NewEncoder(file),
		cfg:     cfg,
		size:    fi.Size(),
	}, nil
}

// Log writes an audit event to the log file. It is safe for concurrent use.
// If the file has exceeded the configured size, it rotates the log first.
func (l *Logger) Log(e AuditEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return fmt.Errorf("audit logger is closed")
	}

	// Check if rotation is needed
	if l.size >= int64(l.cfg.MaxSizeMB)*1024*1024 {
		if err := l.rotateLocked(); err != nil {
			return fmt.Errorf("rotating audit log: %w", err)
		}
	}

	// Encode and write the event
	if err := l.encoder.Encode(e); err != nil {
		return fmt.Errorf("encoding audit event: %w", err)
	}

	l.size += int64(len(fmt.Sprintf("%+v\n", e))) // rough estimate
	return nil
}

// rotateLocked renames the current file and opens a new one.
// Must be called with l.mu held.
func (l *Logger) rotateLocked() error {
	// Re-verify the log directory on EVERY rotation (R64). R45's walk
	// runs once at NewLogger, but rotations re-resolve the log path
	// fresh (os.Rename, openAuditFile, cleanup scan): the DEFAULT dir
	// /tmp/l3-firewall sits in world-writable /tmp, so any local user
	// can rename it and plant a symlink to an arbitrary writable
	// directory at any time during the run — the next rotation then
	// renames/creates/appends/deletes audit.log* files in that directory
	// as the firewall's UID, or (without a pre-placed victim file) fails
	// the rename AFTER the real fd is closed and permanently destroys
	// the audit trail. Mirror persist.SaveState's per-call check;
	// rotation runs once per MaxSizeMB of events, not per event. Must
	// run BEFORE l.file.Close() so a rejected path leaves the logger's
	// real fd intact.
	if err := securepath.RejectSymlinkComponents(filepath.Dir(l.cfg.Path)); err != nil {
		return err
	}
	// Close current file
	if err := l.file.Close(); err != nil {
		return fmt.Errorf("closing current audit log: %w", err)
	}

	// Rename with timestamp suffix
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	rotatedPath := fmt.Sprintf("%s.%s", l.cfg.Path, timestamp)
	if err := os.Rename(l.cfg.Path, rotatedPath); err != nil {
		return fmt.Errorf("renaming audit log: %w", err)
	}

	// Open new file (FIFO-hardened — see openAuditFile)
	file, err := openAuditFile(l.cfg.Path)
	if err != nil {
		return fmt.Errorf("opening new audit log: %w", err)
	}

	l.file = file
	l.encoder = json.NewEncoder(file)
	l.size = 0

	// Cleanup old backups (keep only MaxBackups most recent)
	l.cleanupLocked()

	return nil
}

// maxCleanupEntries bounds the number of directory entries examined per
// rotation (R63). The pre-R63 cleanup read the ENTIRE log directory via
// os.ReadDir: an attacker with write access to the log directory (the
// DEFAULT /tmp/l3-firewall is attacker-writable) plants a large number
// of files, and every rotation (audit.Log runs on the packet hot path)
// pays an O(N) allocation + syscall burst. Readdirnames in one bounded
// chunk caps both memory and syscalls per rotation regardless of
// directory contents; leftover stale backups beyond the window are
// pruned on subsequent rotations (each rotation removes the oldest
// matches first, so cleanup converges).
const maxCleanupEntries = 4096

// cleanupLocked removes old rotated files, keeping only the newest MaxBackups.
// Must be called with l.mu held.
func (l *Logger) cleanupLocked() {
	dir := filepath.Dir(l.cfg.Path)
	base := filepath.Base(l.cfg.Path)
	prefix := base + "."

	// Bounded scan (R63): open the directory and read at most
	// maxCleanupEntries names — os.ReadDir (pre-R63) buffered every
	// entry, so a directory stuffed with attacker files forced an O(N)
	// allocation + scan on every rotation (hot-path DoS).
	// O_NONBLOCK (the R15 pattern): a FIFO swapped in at the directory
	// path would block the plain open forever; with O_NONBLOCK it fails
	// immediately with ENXIO. Directories are unaffected.
	f, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return
	}
	names, _ := f.Readdirnames(maxCleanupEntries)
	f.Close()

	var matches []string
	for _, name := range names {
		if strings.HasPrefix(name, prefix) {
			matches = append(matches, filepath.Join(dir, name))
		}
	}
	if len(matches) <= l.cfg.MaxBackups {
		return
	}

	// Sort BEFORE removal (R72): Readdirnames returns DIRECTORY order —
	// reverse-creation on tmpfs, hash order on ext4 — NOT sorted order
	// as the pre-R72 comment claimed (the R69 finding, which fixed the
	// identical unsorted-front removal in capture.cleanupLocked but was
	// never applied to the audit path). rotateLocked renames the current
	// audit.log to a fresh timestamped backup BEFORE cleanup runs, so on
	// reverse-creation order the fresh backup is matches[0] and the
	// pre-R72 removal loop deleted it first — the newest rotated audit
	// history (the only copy of the events that triggered the rotation)
	// was destroyed at its moment of creation, every rotation, while the
	// OLDEST backups survived forever (retention inverted and frozen).
	// The rotated names (audit.log.<UTC yyyymmddThhmmssZ>) are
	// fixed-width and sort lexicographically = chronologically, so after
	// sorting the removal targets exactly the oldest backups and the
	// newest MaxBackups (including the just-rotated file) survive — the
	// documented "keep only MaxBackups most recent" contract.
	sort.Strings(matches)
	// Remove oldest (first in sorted list) until we're under limit
	toRemove := len(matches) - l.cfg.MaxBackups
	for i := 0; i < toRemove && i < len(matches); i++ {
		os.Remove(matches[i])
	}
}

// Close closes the audit log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	return l.file.Close()
}
