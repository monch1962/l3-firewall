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
	"sync"
	"time"
)

// Default values for the audit logger configuration.
const (
	DefaultMaxSizeMB  = 100  // 100MB per file
	DefaultMaxBackups = 5    // keep 5 rotated files
	DefaultDirMode    = 0755 // directory permissions
)

// AuditEvent represents a single structured audit log entry.
type AuditEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	Type       string    `json:"type"`                 // "packet_allow", "packet_block", "rate_limit", etc.
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

	// Open the log file for append
	file, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
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

	// Open new file
	file, err := os.OpenFile(l.cfg.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
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

// cleanupLocked removes old rotated files, keeping only the newest MaxBackups.
// Must be called with l.mu held.
func (l *Logger) cleanupLocked() {
	pattern := l.cfg.Path + ".*"
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return
	}
	if len(matches) <= l.cfg.MaxBackups {
		return
	}

	// Sort by name (timestamp suffix makes them naturally sortable)
	// Remove oldest (first in alphabetically sorted list) until we're under limit
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
