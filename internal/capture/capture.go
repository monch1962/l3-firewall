// Package capture provides on-demand pcap file writing for forensic analysis
// of blocked packets. Uses gopacket's pcapgo writer for standard pcap format.
package capture

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/monch1962/l3-firewall/internal/securepath"
)

// maxPacketSize prevents disk exhaustion from oversized packet writes.
// Standard Ethernet MTU is 1500 bytes; jumbo frames are up to 9000 bytes.
// A 64KB cap covers all realistic packet sizes with margin.
const maxPacketSize = 65536

// maxCleanupEntries bounds the number of directory entries examined per
// rotation (R63). The pre-R63 cleanup read the ENTIRE --pcap-dir via
// os.ReadDir on the NFQUEUE hot path: an attacker with write access to
// the pcap directory plants a large number of files, and every rotation
// pays an O(N) allocation + syscall burst — recurring forever when the
// planted names don't match the cleanup filter. Readdirnames in one
// bounded chunk caps both memory and syscalls per rotation regardless
// of directory contents; leftover stale matches are pruned on
// subsequent rotations.
const maxCleanupEntries = 4096

// Config controls the pcap writer behaviour.
type Config struct {
	Dir        string // directory to write pcap files to (empty = disabled)
	MaxFiles   int    // max pcap files to keep before rotating
	MaxPackets int    // max packets per file before rotating
}

// Writer writes packets to rotating pcap files.
type Writer struct {
	mu       sync.Mutex
	cfg      Config
	curFile  *os.File
	fw       *pcapgo.Writer
	curFileN int
	pktCount int
	closed   bool
}

// NewWriter creates a pcap writer. Returns nil if Dir is empty.
func NewWriter(cfg Config) (*Writer, error) {
	if cfg.Dir == "" {
		return nil, nil
	}
	if cfg.MaxFiles <= 0 {
		cfg.MaxFiles = 10
	}
	if cfg.MaxPackets <= 0 {
		cfg.MaxPackets = 10000
	}
	if err := os.MkdirAll(cfg.Dir, 0755); err != nil {
		return nil, fmt.Errorf("creating pcap dir %s: %w", cfg.Dir, err)
	}
	// Reject symlinks at any directory component of --pcap-dir: R42's
	// O_NOFOLLOW on the rotation file open only protects the FINAL
	// component, but the kernel resolves intermediate directory symlinks
	// before the open — a symlink planted at the pcap dir path makes every
	// blocked_%05d.pcap rotation land in the attacker-chosen directory as
	// the firewall's UID (R45 — directory symlink write-through).
	if err := securepath.RejectSymlinkComponents(cfg.Dir); err != nil {
		return nil, err
	}
	return &Writer{cfg: cfg}, nil
}

// WriteBlock writes a blocked packet to the current pcap file.
// Packets larger than maxPacketSize are rejected to prevent disk exhaustion.
func (w *Writer) WriteBlock(raw []byte) error {
	if w == nil {
		return nil
	}
	if len(raw) > maxPacketSize {
		return fmt.Errorf("packet too large: %d bytes (max %d)", len(raw), maxPacketSize)
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return fmt.Errorf("pcap writer is closed")
	}

	if w.curFile == nil || w.pktCount >= w.cfg.MaxPackets {
		if err := w.rotateLocked(); err != nil {
			return err
		}
	}

	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(raw),
		Length:        len(raw),
	}
	if err := w.fw.WritePacket(ci, raw); err != nil {
		return err
	}
	w.pktCount++
	return nil
}

// rotateLocked closes the current file and opens a new one.
func (w *Writer) rotateLocked() error {
	if w.curFile != nil {
		w.curFile.Close()
		w.curFile = nil
	}

	w.curFileN++
	fname := filepath.Join(w.cfg.Dir, fmt.Sprintf("blocked_%05d.pcap", w.curFileN))
	// Open with O_NOFOLLOW: os.Create would follow a symlink planted at the
	// rotation filename by an attacker with write access to the pcap
	// directory, truncating and overwriting an arbitrary file writable by
	// the firewall's UID on the next blocked packet (R42 — symlink
	// write-through). A symlink at the rotation path is never legitimate.
	// Also O_NONBLOCK: WriteBlock runs in the NFQUEUE packet hot path, and
	// opening an existing FIFO planted at the (predictable) rotation
	// filename O_WRONLY without O_NONBLOCK blocks until a reader appears —
	// stalling the receive loop until the queue fills and the kernel drops
	// ALL traffic (R55 — the R38 FIFO class applied to the CREATE open,
	// where O_NOFOLLOW alone does not protect). With O_NONBLOCK the FIFO
	// open fails immediately with ENXIO (packet simply not captured);
	// regular files are unaffected.
	f, err := os.OpenFile(fname, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0666)
	if err != nil {
		return fmt.Errorf("creating pcap file %s: %w", fname, err)
	}

	// Write pcap header
	fw := pcapgo.NewWriter(f)
	if err := fw.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		f.Close()
		return fmt.Errorf("writing pcap header: %w", err)
	}

	w.curFile = f
	w.fw = fw
	w.pktCount = 0

	// Cleanup old files
	w.cleanupLocked()
	return nil
}

func (w *Writer) cleanupLocked() {
	// Mechanism 1 — direct indexed removal of the firewall's own
	// rotation files (O(1), no directory read): after creating rotation
	// file N (blocked_%05d.pcap, strictly increasing), the file created
	// MaxFiles rotations ago — index N-MaxFiles — is obsolete. The
	// firewall knows the exact names it creates, so its own retention
	// cap is enforced regardless of what else is in the directory (R63).
	oldIdx := w.curFileN - w.cfg.MaxFiles
	if oldIdx >= 1 {
		name := filepath.Join(w.cfg.Dir, fmt.Sprintf("blocked_%05d.pcap", oldIdx))
		if err := os.Remove(name); err != nil && !os.IsNotExist(err) {
			slog.Warn("pcap cleanup: remove failed", "file", name, "error", err)
		}
	}

	// Mechanism 2 — BOUNDED directory scan for stale files the index
	// cannot see: prior-run files with non-sequential names (e.g. old
	// non-padded blocked_0.pcap formats, R9.14) or indices the current
	// run never reaches. Read at most maxCleanupEntries names — the
	// pre-R63 os.ReadDir read the ENTIRE --pcap-dir into memory on every
	// rotation (which runs on the NFQUEUE hot path via WriteBlock), so
	// an attacker with write access to the pcap directory planting N
	// files (matching or not) forced an O(N) allocation + syscall burst
	// per rotation — recurring forever when the planted names don't
	// match the filter (R63). Names come back in sorted order, so the
	// matches found are the oldest — exactly what the removal loop
	// targets; leftovers beyond the window are pruned on later
	// rotations. O_NONBLOCK (the R15 pattern) rejects a FIFO swapped in
	// at the directory path instead of blocking the hot path.
	f, err := os.OpenFile(w.cfg.Dir, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		slog.Warn("pcap cleanup: read dir error", "dir", w.cfg.Dir, "error", err)
		return
	}
	names, _ := f.Readdirnames(maxCleanupEntries)
	f.Close()

	var matches []string
	for _, name := range names {
		if strings.HasPrefix(name, "blocked_") && strings.HasSuffix(name, ".pcap") {
			matches = append(matches, filepath.Join(w.cfg.Dir, name))
		}
	}
	if len(matches) <= w.cfg.MaxFiles {
		return
	}
	for i := 0; i < len(matches)-w.cfg.MaxFiles; i++ {
		os.Remove(matches[i])
	}
}

// Close closes the current pcap file.
func (w *Writer) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	if w.curFile != nil {
		return w.curFile.Close()
	}
	return nil
}
