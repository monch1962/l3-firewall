// Package capture provides on-demand pcap file writing for forensic analysis
// of blocked packets. Uses gopacket's pcapgo writer for standard pcap format.
package capture

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// maxPacketSize prevents disk exhaustion from oversized packet writes.
// Standard Ethernet MTU is 1500 bytes; jumbo frames are up to 9000 bytes.
// A 64KB cap covers all realistic packet sizes with margin.
const maxPacketSize = 65536

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
	f, err := os.Create(fname)
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
	pattern := filepath.Join(w.cfg.Dir, "blocked_*.pcap")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		slog.Warn("pcap cleanup: Glob error", "pattern", pattern, "error", err)
		return
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
