// Red-team security hardening Round 55 — FIFO blocking on the CREATE paths
// of persist.SaveState's .tmp open and capture.rotateLocked's rotation-file
// open (startup/shutdown + hot-path hang DoS).
//
// R14/R15 hardened the READ opens (LoadState) with O_NONBLOCK + fstat, and
// R38 hardened audit's CREATE/APPEND open with O_NONBLOCK for the same
// FIFO class. R42/R43 hardened the persist .tmp and capture rotation
// CREATE opens for the SYMLINK class (O_NOFOLLOW) — but O_NOFOLLOW does
// NOT satisfy the FIFO class: opening an existing FIFO O_WRONLY (without
// O_NONBLOCK) blocks until a reader appears.
//
// An attacker with write access to the state/pcap directory (the same
// threat model as R13/R14/R42 — operator-influenced --state-file /
// --pcap-dir paths, often under attacker-writable /tmp) can plant a FIFO
// at the fully predictable state.json.tmp (persist) or the predictable
// next blocked_%05d.pcap rotation filename (capture):
//
//   - persist: the 60-second saveState ticker goroutine blocks forever
//     inside os.OpenFile(.tmp) → conntrack.Expire() and ratelimit.Cleanup()
//     (same goroutine, same tick) never run again → the flow table fills
//     and new connections start being blocked (availability DoS). The
//     shutdown-path saveState blocks too.
//   - capture: WriteBlock runs in the NFQUEUE packet hot path — a blocked
//     rotation open stalls the receive loop, the queue fills and the
//     kernel drops ALL traffic (total outage).
//
// R55 FIX: add syscall.O_NONBLOCK to both CREATE opens (the audit pattern
// from R38). O_NONBLOCK on a FIFO open with no reader fails immediately
// with ENXIO — an error path, not a hang — and is ignored for regular
// files, so the normal save/rotation path is unaffected.
package persist

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// ── R55.1: SaveState must NOT block on a FIFO planted at the .tmp path ──
// RED (pre-fix): the .tmp create-open (O_WRONLY|O_CREATE|O_TRUNC|O_NOFOLLOW)
// blocks on an existing FIFO waiting for a reader — SaveState hangs, holding
// the package saveMu, so the 60s ticker's saveState (and with it
// conntrack.Expire/ratelimit.Cleanup on the same goroutine) never completes.
// GREEN (post-fix): O_NONBLOCK makes the open fail immediately with ENXIO —
// SaveState returns promptly with an error.
func TestAttack_SaveStateTmpFIFOBlocks(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	fifoPath := statePath + ".tmp"
	if err := syscall.Mkfifo(fifoPath, 0666); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- SaveState(statePath, &EngineState{BlockStats: map[string]int64{"attack": 1}})
	}()

	select {
	case err := <-done:
		// GREEN: returned promptly. Must be an error — a FIFO .tmp is never
		// legitimate and the save must fail closed, not write into a pipe.
		if err == nil {
			t.Error("SaveState must reject a FIFO at the .tmp path (returned nil error)")
		}
	case <-time.After(1 * time.Second):
		// RED: SaveState is blocked in the .tmp open holding the package
		// saveMu. Open the FIFO read-side non-blocking and close it so the
		// stuck writer connects and finishes via EPIPE (an error path that
		// also releases saveMu), keeping the rest of this package's tests
		// runnable after the failure.
		if rd, err := os.OpenFile(fifoPath, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
			rd.Close()
		}
		<-done
		t.Fatal("R55 RED: SaveState blocked on a FIFO at the .tmp path — every 60s save hangs (availability DoS)")
	}
}

// ── R55.2 (companion): failed save is clean — no half-completed state ───
// Same FIFO scenario: the failed save must return an error promptly AND
// leave no state.json behind (the .tmp FIFO must not be renamed over the
// final path). Uses the goroutine+timeout shape so the pre-fix hang is
// observed as a fast RED failure instead of a silent package hang.
func TestAttack_SaveStateTmpFIFOErrorIsClean(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	fifoPath := statePath + ".tmp"
	if err := syscall.Mkfifo(fifoPath, 0666); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- SaveState(statePath, &EngineState{BlockStats: map[string]int64{"a": 1}})
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Error("SaveState must return an error for a FIFO .tmp (got nil)")
		}
		// The FIFO must still be there (not renamed over state.json) and no
		// state.json must exist — the failed save must not half-complete.
		if _, statErr := os.Lstat(fifoPath); statErr != nil {
			t.Errorf("FIFO .tmp missing after failed save: %v", statErr)
		}
		if _, statErr := os.Lstat(statePath); !os.IsNotExist(statErr) {
			t.Errorf("state.json must not exist after failed save (got stat err %v)", statErr)
		}
	case <-time.After(1 * time.Second):
		if rd, err := os.OpenFile(fifoPath, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
			rd.Close()
		}
		<-done
		t.Fatal("R55 RED: SaveState blocked on a FIFO at the .tmp path — every 60s save hangs (availability DoS)")
	}
}
