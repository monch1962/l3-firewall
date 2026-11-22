// Red-team security hardening Round 96 (engine integration point) — the pcap
// failure log is per-blocked-packet.
//
// R10 made the pcap `WriteBlock` error LOGGED instead of silently discarded
// (the correct direction: a silent discard hides an evidence-plane outage).
// R96 found that "logged" means one WARN line per BLOCKED PACKET, on the same
// receive goroutine that must deliver verdicts: a persistent capture failure
// (disk full, an unwritable --pcap-dir, or a hard link/symlink planted at the
// rotation name — the standing R42/R45/R55/R93 model) produces a log line per
// blocked packet for the life of the condition. At the firewall's ~83k pps
// ceiling that is ~83k log writes per second competing with the packet path,
// and the operator's log shipper sees the incident as a wall of identical
// lines instead of one actionable warning.
//
// The fix mirrors R91's audit-rotation posture ("one actionable warning per
// window instead of a per-event flood"): the engine reports the FIRST distinct
// pcap failure immediately and then keeps quiet about the same failure until
// the window elapses or the failure text changes — so a genuinely new failure
// mode (e.g. ENOENT after a rotation, then ENOSPC) is still reported at once.
package engine

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/florianl/go-nfqueue"
	"github.com/monch1962/l3-firewall/internal/conntrack"
	"github.com/monch1962/l3-firewall/internal/ratelimit"
)

// recordHandler is a slog.Handler that records (level, message) pairs so a test
// can count how many lines a failure state actually produced.
type recordHandler struct {
	mu   sync.Mutex
	msgs []string
}

func (h *recordHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.msgs = append(h.msgs, r.Message)
	return nil
}
func (h *recordHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordHandler) WithGroup(string) slog.Handler      { return h }

// count returns how many recorded messages contain sub.
func (h *recordHandler) count(sub string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, m := range h.msgs {
		if strings.Contains(m, sub) {
			n++
		}
	}
	return n
}

// ── R96.3: a persistent pcap write failure must not log per blocked packet.
func TestAttack_PcapFailureLogsOnEveryBlockedPacket(t *testing.T) {
	h := &recordHandler{}
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	defer slog.SetDefault(prev)

	eng := New(nil, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(0, 0),
		true, false, nil, nil, nil, nil, &errPcapWriter{err: errors.New("disk full")}, "", nil)

	raw := buildTestTCPPacket(net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"), 12345, 22,
		true, false, false, false)
	id := uint32(1)
	attr := nfqueue.Attribute{Payload: &raw, PacketID: &id}

	const n = 200
	for i := 0; i < n; i++ {
		if got := eng.packetHandler(attr); got == 0 {
			t.Fatalf("setup: packet %d was allowed, want the fail-closed block path", i)
		}
	}

	if got := h.count("pcap write failed"); got > 2 {
		t.Errorf("one persistent pcap failure produced %d \"pcap write failed\" lines for %d blocked "+
			"packets, want at most 2 (first occurrence per distinct failure text): a per-packet log on the "+
			"receive goroutine is its own DoS vector and buries the one actionable line in a wall of "+
			"identical ones — R91 fixed exactly this for audit rotation", got, n)
	}
	if h.count("pcap write failed") == 0 {
		t.Error("the pcap write failure was not reported at all: a silent discard is the R10 regression")
	}
}

// ── R96.3b: the suppression must not swallow a NEW failure mode — a changed
// failure text is reported immediately, so the ordering of distinct failures
// stays visible in the log.
func TestAttack_ChangedPcapFailureIsReportedImmediately(t *testing.T) {
	h := &recordHandler{}
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	defer slog.SetDefault(prev)

	pw := &errPcapWriter{err: errors.New("disk full")}
	eng := New(nil, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(0, 0),
		true, false, nil, nil, nil, nil, pw, "", nil)

	raw := buildTestTCPPacket(net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"), 12345, 22,
		true, false, false, false)
	id := uint32(1)
	attr := nfqueue.Attribute{Payload: &raw, PacketID: &id}

	eng.packetHandler(attr)
	eng.packetHandler(attr)
	first := h.count("pcap write failed")
	if first != 1 {
		t.Fatalf("distinct failure logged %d times, want 1 (same text must be deduped)", first)
	}

	pw.err = errors.New("no space left on device") // a NEW failure mode
	eng.packetHandler(attr)
	if got := h.count("pcap write failed"); got != first+1 {
		t.Errorf("a changed failure text was not reported immediately (%d lines, want %d): suppressing it "+
			"would hide the transition from one evidence-plane outage to another", got, first+1)
	}
}

// ── R96.3c: a successful write re-arms reporting, so a recurrence after
// recovery is not silently swallowed forever.
func TestAttack_PcapFailureReportedAgainAfterRecovery(t *testing.T) {
	h := &recordHandler{}
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	defer slog.SetDefault(prev)

	pw := &errPcapWriter{err: errors.New("disk full")}
	eng := New(nil, conntrack.NewTable(conntrack.DefaultConfig()),
		ratelimit.NewLimiter(0, 0),
		true, false, nil, nil, nil, nil, pw, "", nil)

	raw := buildTestTCPPacket(net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"), 12345, 22,
		true, false, false, false)
	id := uint32(1)
	attr := nfqueue.Attribute{Payload: &raw, PacketID: &id}

	eng.packetHandler(attr) // failure reported
	if got := h.count("pcap write failed"); got != 1 {
		t.Fatalf("first failure logged %d times, want 1", got)
	}

	pw.err = nil // capture recovered
	eng.packetHandler(attr)

	pw.err = errors.New("disk full") // and failed again
	eng.packetHandler(attr)
	if got := h.count("pcap write failed"); got != 2 {
		t.Errorf("a failure recurring after a successful write was not reported (%d lines, want 2): "+
			"recovery must re-arm reporting, otherwise the second outage is silent", got)
	}
}
