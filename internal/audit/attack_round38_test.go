// Red-team security hardening Round 38 — FIFO startup DoS in audit.NewLogger
//
// R14 fixed persist.LoadState blocking on FIFO paths (startup DoS via
// attacker-influenced --state-file). R15 hardened it further against TOCTOU.
// The audit logger opens its log file with os.OpenFile(path, O_WRONLY|O_APPEND)
// with NO file-type guard — an attacker who pre-creates a FIFO at the
// --audit-log path (default /tmp/l3-firewall/audit.log is attacker-writable)
// causes NewLogger to block forever, hanging firewall startup.
//
// Same attack class as R14/R15, but on a different integration point
// (audit package had zero attack-test coverage prior to this round).
package audit

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func mkfifo(path string) error {
	return syscall.Mkfifo(path, 0644)
}

// ── R38.1: NewLogger must not block on a FIFO at the log path ────────
// Attacker pre-creates a FIFO at the audit log path. os.OpenFile with
// O_WRONLY on a FIFO with no reader blocks indefinitely → startup hang.
func TestAttack_NewLoggerMustNotBlockOnFIFO(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "audit.log")

	if err := mkfifo(fifoPath); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}

	done := make(chan struct{})
	go func() {
		_, _ = NewLogger(Config{Path: fifoPath})
		close(done)
	}()

	select {
	case <-done:
		t.Log("NewLogger returned on FIFO path — no startup hang")
	case <-time.After(2 * time.Second):
		t.Error("NewLogger blocked on FIFO for 2s — startup DoS (R14/R15 class)")
	}
}

// ── R38.2: NewLogger must reject a FIFO (non-regular) log path ───────
// Once the blocking is fixed, the FIFO path must be rejected with an
// error, not silently opened (opening a FIFO O_WRONLY with O_NONBLOCK
// returns ENXIO on Linux when no reader is present).
func TestAttack_NewLoggerRejectsFIFOPath(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "audit.fifo")

	if err := mkfifo(fifoPath); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}

	done := make(chan struct{})
	var loggerErr error
	go func() {
		_, loggerErr = NewLogger(Config{Path: fifoPath})
		close(done)
	}()

	select {
	case <-done:
		if loggerErr == nil {
			t.Error("NewLogger opened FIFO without error — should reject non-regular file")
		} else {
			t.Logf("NewLogger correctly rejected FIFO: %v", loggerErr)
		}
	case <-time.After(2 * time.Second):
		t.Error("NewLogger blocked on FIFO for 2s — still hanging")
	}
}

// ── R38.3: NewLogger must still work on a regular file (regression) ──
func TestAttack_NewLoggerRegularFileStillWorks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	l, err := NewLogger(Config{Path: path})
	if err != nil {
		t.Fatalf("NewLogger on regular file failed: %v", err)
	}
	defer l.Close()

	if err := l.Log(AuditEvent{Type: "packet_allow", SrcIP: "10.0.0.1"}); err != nil {
		t.Fatalf("Log after regular-file NewLogger failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	if len(data) == 0 {
		t.Error("audit log is empty after Log()")
	}
	t.Log("NewLogger + Log on regular file works — regression OK")
}
