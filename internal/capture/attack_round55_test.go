// Red-team security hardening Round 55 — FIFO blocking on capture's
// rotation-file CREATE open (packet hot-path hang DoS).
//
// rotateLocked creates each rotation file with O_WRONLY|O_CREATE|O_TRUNC|
// O_NOFOLLOW. The O_NOFOLLOW (R42) rejects the SYMLINK class, but opening
// an existing FIFO at the rotation filename O_WRONLY without O_NONBLOCK
// blocks until a reader appears — and WriteBlock runs in the NFQUEUE
// packet hot path (engine.packetHandler → evaluatePacket → WriteBlock),
// so a planted FIFO at the predictable next blocked_%05d.pcap name
// (attacker with write access to the operator-influenced --pcap-dir, the
// R42 threat model) stalls the receive loop: the queue fills and the
// kernel drops ALL traffic. R38 gave audit's create-open O_NONBLOCK for
// exactly this class; the rotation-file CREATE was never covered.
//
// R55 FIX: add syscall.O_NONBLOCK to the rotation-file open — a FIFO with
// no reader fails immediately with ENXIO (error path, packet simply not
// captured), and regular files are unaffected.
package capture

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// ── R55.1: WriteBlock must NOT block on a FIFO at the rotation filename ──
// RED (pre-fix): rotateLocked's open blocks on the FIFO waiting for a
// reader — WriteBlock hangs in the packet hot path (total traffic freeze
// once the queue fills). GREEN (post-fix): the open fails immediately with
// ENXIO — WriteBlock returns an error promptly.
func TestAttack_RotateFIFOBlocks(t *testing.T) {
	dir := t.TempDir()
	// First rotation filename used by rotateLocked (curFileN 0→1).
	rotationFile := filepath.Join(dir, "blocked_00001.pcap")
	if err := syscall.Mkfifo(rotationFile, 0666); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	w, err := NewWriter(Config{Dir: dir, MaxFiles: 3, MaxPackets: 2})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	done := make(chan error, 1)
	go func() {
		done <- w.WriteBlock([]byte("FIFO-ATTACK-PACKET"))
	}()

	select {
	case err := <-done:
		// GREEN: returned promptly. Must be an error — a FIFO rotation file
		// is never legitimate and the write must fail closed.
		if err == nil {
			t.Error("WriteBlock must reject a FIFO at the rotation filename (returned nil error)")
		}
	case <-time.After(1 * time.Second):
		// RED: WriteBlock is blocked in the rotation open holding w.mu (the
		// deferred w.Close below would deadlock on it). Open the FIFO
		// read-side non-blocking and close it so the stuck writer connects
		// and finishes via EPIPE, releasing w.mu.
		if rd, err := os.OpenFile(rotationFile, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
			rd.Close()
		}
		<-done
		t.Fatal("R55 RED: WriteBlock blocked on a FIFO at the rotation filename — packet hot-path hang (total outage)")
	}
}
