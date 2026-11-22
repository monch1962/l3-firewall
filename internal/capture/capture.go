// Package capture provides on-demand pcap file writing for forensic analysis
// of blocked packets. Uses gopacket's pcapgo writer for standard pcap format.
package capture

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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

// rotateRetryInterval floors the rate of rotation ATTEMPTS after a failure
// (R96.1). Rotation is designed as a once-per-MaxPackets event — R63 bounded
// its cleanup scan on exactly that assumption — but a refused create leaves
// curFile == nil, so without a floor the NEXT blocked packet re-enters the
// whole rotation path (directory symlink walk, open, fstat, fchmod) and fails
// again: a per-packet syscall burst on the NFQUEUE receive goroutine. Measured
// pre-fix: 29 µs per blocked packet (2000 calls = 58 ms). At the documented
// ~83k pps ceiling of a 1 Gbps link that is ~2.4 CPU-seconds of receive-loop
// time per second of traffic — the queue overflows and the kernel drops ALL
// traffic (the R58/R79 outage shape). The trigger sits inside the standing
// threat model (write access to --pcap-dir: a hard link per R93 or a symlink
// per R42 at the predictable rotation name), and a plain disk-full or
// permission change reaches it too. One attempt per interval keeps capture
// self-healing (once the name is freed the next attempt succeeds) while
// bounding the cost of a persistent failure to a single attempt per second.
const rotateRetryInterval = time.Second

// rotationName is the single definition of a rotation file's name. The index
// is zero-padded to five digits; R96.2 shows why the padding width must not be
// relied on for ordering (see sortByRotationIndex).
func rotationName(n int) string {
	return fmt.Sprintf("blocked_%05d.pcap", n)
}

// rotationIndex extracts the numeric rotation index from a blocked_*.pcap base
// name. ok is false for anything that is not exactly one of the firewall's own
// rotation names.
func rotationIndex(path string) (int, bool) {
	base := filepath.Base(path)
	const prefix, suffix = "blocked_", ".pcap"
	if !strings.HasPrefix(base, prefix) || !strings.HasSuffix(base, suffix) {
		return 0, false
	}
	digits := base[len(prefix) : len(base)-len(suffix)]
	if digits == "" {
		return 0, false
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(digits)
	if err != nil {
		return 0, false
	}
	return n, true
}

// sortByRotationIndex orders capture paths OLDEST-FIRST by their NUMERIC
// rotation index, so the retention removal loop deletes the oldest captures.
//
// R69 fixed retention inversion caused by DIRECTORY order (tmpfs reverse
// creation) by sorting before removal — but the sort was `sort.Strings` over
// `blocked_%05d.pcap`, which is numerically ordered only while the index fits
// in five digits. At rotation 100000 the name is "blocked_100000.pcap", and
// '1' < '9' means it sorts BEFORE "blocked_99999.pcap": from then on the
// removal loop deletes the NEWEST captures and keeps the OLDEST — the exact
// R69 harm on the sort key instead of the read order, and 1e9 blocked packets
// reach the boundary (~17 minutes of a 1 Mpps flood), which is precisely when
// the forensic evidence matters. Comparing the parsed index is total and
// stable; names that are not the firewall's own rotation names sort last so a
// foreign file can never displace a real capture from the retention window.
func sortByRotationIndex(paths []string) {
	sort.Slice(paths, func(i, j int) bool {
		ni, oki := rotationIndex(paths[i])
		nj, okj := rotationIndex(paths[j])
		switch {
		case oki && okj:
			return ni < nj
		case oki != okj:
			return oki
		default:
			return paths[i] < paths[j]
		}
	})
}

// retryError is returned while the rotation retry window is closed (R96.1):
// the last attempt is known to have failed, so this packet issues no syscalls
// at all. The message is deliberately CONSTANT — a caller that logs it (the
// engine logs pcap write errors) must not see a new string on every packet, or
// the log-flood this fix exists to stop would simply move one layer up. The
// underlying failure is available through Unwrap.
type retryError struct {
	cause    error
	attempts int
}

func (e *retryError) Error() string {
	return "capture unavailable: rotation is failing and will be retried; blocked packets are not being captured"
}

func (e *retryError) Unwrap() error { return e.cause }

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

	// Bounded retry state (R96.1). Guarded by mu like the rest of the writer.
	// retryInterval is a field rather than the constant so tests can shorten
	// it; production always uses rotateRetryInterval.
	retryInterval  time.Duration
	lastRotateErr  error     // cause reported (via Unwrap) while the window is closed
	nextRotateTry  time.Time // earliest time another attempt may run
	rotateAttempts int       // total rotation attempts, for the warning text
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
	return &Writer{cfg: cfg, retryInterval: rotateRetryInterval}, nil
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

// rotateLocked rotates the current file under a bounded failure backoff
// (R96.1). While the window is closed the call issues no syscalls at all and
// returns a constant-text retryError, so a persistent failure costs one
// rotation attempt per interval instead of one per blocked packet.
func (w *Writer) rotateLocked() error {
	if time.Now().Before(w.nextRotateTry) {
		return &retryError{cause: w.lastRotateErr, attempts: w.rotateAttempts}
	}
	w.rotateAttempts++
	if err := w.rotateOnce(); err != nil {
		w.lastRotateErr = err
		w.nextRotateTry = time.Now().Add(w.retryInterval)
		// One actionable warning per window (the R91 audit-rotation posture):
		// attempts are gated, so this cannot fire per packet.
		slog.Warn("pcap capture unavailable — rotation failed, retrying",
			"dir", w.cfg.Dir, "error", err, "attempt", w.rotateAttempts, "retry_in", w.retryInterval)
		return err
	}
	w.lastRotateErr = nil
	w.nextRotateTry = time.Time{}
	return nil
}

// rotateOnce performs one rotation attempt.
func (w *Writer) rotateOnce() error {
	// Re-verify the directory on EVERY rotation (R64). R45's walk runs
	// once at NewWriter, but rotations re-resolve --pcap-dir fresh: an
	// attacker with write access to the PARENT of the pcap dir (rename +
	// symlink creation — strictly weaker than the R42/R45/R55 model of
	// write access to the directory itself) can swap the real directory
	// for a symlink to an arbitrary writable directory at any time during
	// the run, and the next rotation creates/truncates blocked_%05d.pcap
	// and deletes blocked_*.pcap through the link as the firewall's UID.
	// Mirror persist.SaveState's per-call check; rotation runs once per
	// MaxPackets blocked packets, not on the per-packet hot path.
	if err := securepath.RejectSymlinkComponents(w.cfg.Dir); err != nil {
		return err
	}
	if w.curFile != nil {
		w.curFile.Close()
		w.curFile = nil
	}

	// The rotation index advances only on SUCCESS (R93): the pre-R93 code
	// incremented w.curFileN before the create, so a rotation refused by the
	// hardening guards (a planted hard link / symlink / FIFO at the predictable
	// name) burned that index — the first successful capture after the attack
	// was blocked_00002.pcap and mechanism 1's retention arithmetic
	// (curFileN-MaxFiles) pointed at a slot that never existed. Computing the
	// next name without committing the index keeps the invariant "index N is
	// an existing rotation file of this run".
	nextFileN := w.curFileN + 1
	fname := filepath.Join(w.cfg.Dir, rotationName(nextFileN))
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
	// The mode is 0600, applied with fchmod on the opened descriptor (R89).
	// A pcap holds the payload of every blocked packet — cleartext
	// credentials, DNS queries, protocol metadata — i.e. exactly the traffic
	// the firewall exists to stop. Created 0666 it lands world-readable
	// under any ordinary umask, so any local user (or a neighbouring
	// container sharing the volume) can read it; R6 flagged this and it was
	// never fixed. fchmod also tightens a rotation file left 0644 by an
	// older build that is still inside the retention window.
	f, err := securepath.CreateOwnerOnly(fname)
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
	w.curFileN = nextFileN

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
		name := filepath.Join(w.cfg.Dir, rotationName(oldIdx))
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
	// match the filter (R63). Names are then SORTED before removal (R69):
	// Readdirnames returns directory order — reverse-creation on tmpfs,
	// hash order on ext4 — NOT sorted order, and the pre-R69 removal loop
	// deleted the newest files including the firewall's own open rotation
	// file; after the R69 sort the matches removed are the oldest —
	// exactly what the removal loop targets; leftovers beyond the window
	// are pruned on later rotations. O_NONBLOCK (the R15 pattern) rejects
	// a FIFO swapped in at the directory path instead of blocking the hot
	// path.
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
	// Sort BEFORE removal (R69): Readdirnames returns DIRECTORY order —
	// reverse-creation on tmpfs, hash order on ext4 — NOT sorted order as
	// the pre-R69 comment claimed. The removal loop deletes the first
	// (len(matches)-MaxFiles) entries of the slice; on unsorted order that
	// front is the NEWEST files, so the firewall unlinked its own current
	// open rotation file (silent capture-evidence loss: writes land in an
	// orphaned inode) and deleted newer captures while keeping older stale
	// ones (retention inverted). R96.2: the sort must compare the NUMERIC
	// rotation index, not the name string — `blocked_%05d.pcap` is ordered
	// lexicographically only up to index 99999, and past that the newest
	// captures sort first and the removal loop deletes them (see
	// sortByRotationIndex).
	sortByRotationIndex(matches)
	// Never remove the file this rotation JUST opened (index curFileN): it
	// is definitionally not stale — it is the current forensic capture
	// receiving WriteBlock writes. Mechanism 1 (indexed removal) already
	// enforces the own-file retention cap by index; mechanism 2 exists to
	// prune stale prior-run files the index cannot see. Without this skip,
	// a directory in reverse-creation order (tmpfs) puts the current file
	// FIRST in the sorted-by-creation slice and it is deleted by its own
	// rotation's cleanup (R69). The skip is cheap (strings compare) and
	// runs once per rotation, not per packet. The `removed` counter keeps
	// the total at len(matches)-MaxFiles even when the current file falls
	// inside the removal window — the retention cap is a hard contract
	// (R9.14: at most MaxFiles files remain after cleanup).
	current := filepath.Join(w.cfg.Dir, rotationName(w.curFileN))
	removed := 0
	for i := 0; i < len(matches) && removed < len(matches)-w.cfg.MaxFiles; i++ {
		if matches[i] == current {
			continue
		}
		os.Remove(matches[i])
		removed++
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
