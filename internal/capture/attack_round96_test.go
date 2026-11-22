// Red-team security hardening Round 96 — capture-plane availability and
// evidence-retention truthfulness.
//
// Two properties the pcap plane silently loses under attack:
//
// R96.1 — a PERSISTENT rotation failure is retried on every blocked packet.
// `WriteBlock` rotates when the current file is full (or on the first packet),
// and a refused create leaves `curFile == nil`, so the NEXT blocked packet
// re-enters the whole rotation path — directory symlink walk, open, fstat,
// fchmod — and fails again. Rotation was designed as a once-per-MaxPackets
// event (R63 bounded its cleanup scan on exactly that assumption); a failure
// makes it a PER-PACKET event on the NFQUEUE receive goroutine. Measured
// pre-fix: 29 µs per blocked packet (2000 calls = 58 ms) purely on refused
// rotation attempts, which at the documented ~83k pps ceiling of a 1 Gbps link
// is ~2.4 CPU-seconds of receive-loop time per second of traffic — the queue
// overflows and the kernel drops ALL traffic (the R58/R79 outage shape). The
// trigger is inside the standing threat model: write access to --pcap-dir lets
// an attacker plant a hard link (R93's own guard) or a symlink (R42's guard) at
// the predictable rotation name.
//
// R96.2 — the retention scan's SORT KEY breaks past the 5-digit rotation index.
// R69 fixed retention inversion caused by DIRECTORY order (tmpfs reverse
// creation) by sorting the matches before removal. The sort is
// `sort.Strings` over `blocked_%05d.pcap`, which is numerically ordered only
// while the index fits in five digits: at 100000 the name is
// "blocked_100000.pcap", and '1' < '9' means it sorts BEFORE
// "blocked_99999.pcap". From then on the removal loop deletes the NEWEST
// captures and keeps the OLDEST — the exact R69 harm, on the sort key instead
// of the read order. 1e9 blocked packets reach the boundary (100000 rotations
// × 10000 packets), i.e. ~17 minutes of a 1 Mpps flood — precisely when the
// forensic evidence matters.
package capture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── R96.1: a refused rotation must not be re-attempted per blocked packet.
func TestAttack_FailedRotationIsRetriedOnEveryBlockedPacket(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{Dir: dir})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	// Plant the failure shape inside the standing threat model: a hard link at
	// the predictable first rotation name (R93 refuses it, so the create never
	// succeeds) pointing at a file whose contents must survive.
	victim := filepath.Join(dir, "victim.dat")
	if err := os.WriteFile(victim, []byte("evidence-that-must-survive"), 0o600); err != nil {
		t.Fatalf("planting victim: %v", err)
	}
	if err := os.Link(victim, filepath.Join(dir, "blocked_00001.pcap")); err != nil {
		t.Skipf("hard links unsupported on this filesystem: %v", err)
	}

	payload := make([]byte, 64)
	const n = 500
	attempts := 0
	for i := 0; i < n; i++ {
		if err := w.WriteBlock(payload); err != nil && strings.Contains(err.Error(), "hard-linked") {
			attempts++
		}
	}
	if attempts > 1 {
		t.Errorf("the refused rotation was re-attempted %d times for %d blocked packets, want at most 1: "+
			"every blocked packet re-runs the directory walk + open + fstat + fchmod on the NFQUEUE receive "+
			"goroutine (measured 29 µs each), so a planted hard link or symlink at the rotation name turns a "+
			"one-line capture failure into a packet-path stall and queue overflow (kernel drops ALL traffic); "+
			"R91 applied the \"one warning per window\" posture to the audit plane, capture never got it", attempts, n)
	}
	// The linked file must still hold its bytes: the refused create never
	// shortened it (R93's property, re-asserted here because the retry policy
	// must not reintroduce a destructive attempt).
	if b, rerr := os.ReadFile(victim); rerr != nil || string(b) != "evidence-that-must-survive" {
		t.Errorf("linked inode was modified during refused rotation attempts: %q (err=%v)", b, rerr)
	}
}

// ── R96.1b: the retry policy must not make capture permanently unavailable —
// once the attacker's name is gone, capture resumes by itself (R93's
// "capture resumes once it is removed" contract, kept).
func TestAttack_CaptureResumesOnceBlockingNameIsRemoved(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{Dir: dir})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	w.retryInterval = 5 * time.Millisecond // keep the test fast; the policy is the same

	victim := filepath.Join(dir, "victim.dat")
	if err := os.WriteFile(victim, []byte("x"), 0o600); err != nil {
		t.Fatalf("planting victim: %v", err)
	}
	link := filepath.Join(dir, "blocked_00001.pcap")
	if err := os.Link(victim, link); err != nil {
		t.Skipf("hard links unsupported on this filesystem: %v", err)
	}

	payload := make([]byte, 64)
	if err := w.WriteBlock(payload); err == nil {
		t.Fatal("setup: expected the refused rotation to surface an error")
	}
	if err := os.Remove(link); err != nil {
		t.Fatalf("removing the planted link: %v", err)
	}
	// Wait past the retry window, then capture must work again with no
	// operator action.
	time.Sleep(3 * w.retryInterval)
	if err := w.WriteBlock(payload); err != nil {
		t.Errorf("capture did not resume after the blocking name was removed: %v — a backoff must not "+
			"become a permanent disable", err)
	}
	if w.curFile == nil {
		t.Error("capture has no open rotation file after the name was freed")
	}
}

// ── R96.2: retention must remove the OLDEST captures across the 6-digit
// rotation-index boundary, not the newest.
func TestAttack_RetentionInvertsPastSixDigitRotationIndex(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(Config{Dir: dir, MaxFiles: 3})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	// A long-running instance has just crossed the 5↔6 digit boundary. Names
	// sort lexicographically: 100000 < 100001 < 100002 < 99998 < 99999.
	indices := []int{99998, 100000, 100001, 100002}
	for _, n := range indices {
		p := filepath.Join(dir, rotationName(n))
		if err := os.WriteFile(p, []byte("pcap"), 0o600); err != nil {
			t.Fatalf("planting %s: %v", p, err)
		}
	}
	w.curFileN = 100002 // the rotation file this run just opened

	w.cleanupLocked()

	oldest := filepath.Join(dir, rotationName(99998))
	if _, err := os.Stat(oldest); err == nil {
		t.Errorf("the OLDEST capture %s survived retention while a newer file was removed: "+
			"sort.Strings orders 6-digit names before 5-digit ones, so the R69 removal loop deletes the "+
			"NEWEST evidence and keeps the oldest — retention inverted, exactly the R69 harm on the sort key",
			filepath.Base(oldest))
	}
	newest := filepath.Join(dir, rotationName(100001))
	if _, err := os.Stat(newest); err != nil {
		t.Errorf("the NEWEST non-current capture %s was removed by retention (err=%v): evidence from the "+
			"current incident was deleted while stale captures were kept", filepath.Base(newest), err)
	}
	if _, err := os.Stat(filepath.Join(dir, rotationName(100002))); err != nil {
		t.Errorf("the CURRENT capture file was removed by its own rotation's cleanup: %v", err)
	}
}
