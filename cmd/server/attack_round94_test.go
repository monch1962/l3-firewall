package main

import (
	"os"
	"strings"
	"testing"
)

// ── R94.5: an out-of-range --queue value is silently truncated ──────────────
//
// main() hands the queue number to the kernel as uint16(*queueNum). The NFQUEUE
// number is a 16-bit field, so `--queue 65536` becomes 0 and `--queue 70000`
// becomes 4464: the engine registers on a queue the operator never configured
// while the startup line prints the un-truncated value ("queue=70000"). The
// nftables rule that queues to the configured value then matches nothing —
// traffic is NOT firewalled although the process reports it is — and in a mixed
// deployment the firewall can silently take over another service's queue. A
// configuration value that cannot be honoured must be refused, not wrapped.
func TestAttack_QueueNumberOutOfRangeIsRejected(t *testing.T) {
	for _, n := range []uint{65536, 65537, 70000, 1 << 20} {
		if err := validateQueueNumber(n); err == nil {
			t.Errorf("--queue %d accepted: the kernel field is 16-bit, so the engine would register "+
				"on queue %d (uint16) while the log reports %d — the nftables rule for the "+
				"configured queue matches nothing and traffic is unfiltered", n, uint16(n), n)
		}
	}
	for _, n := range []uint{0, 1, 1024, 65535} {
		if err := validateQueueNumber(n); err != nil {
			t.Errorf("valid queue %d rejected: %v", n, err)
		}
	}
}

// ── R94.6: the validator must actually be WIRED into main() ────────────────
// A helper no one calls is documentation, not a control (R90/R93: the wiring
// is the finding). main() is not unit-testable (it ends in eng.Run), so the
// assertion is structural: the call and its conversion site must coexist.
func TestAttack_QueueValidationIsWiredIntoStartup(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}
	text := string(src)

	for _, want := range []string{
		"validateQueueNumber(*queueNum)",
		"eng.Run(uint16(*queueNum))",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("main.go no longer contains %q: the out-of-range queue guard (or the "+
				"float→uint16 conversion it protects) moved, so re-verify that the guard still "+
				"runs before the conversion", want)
		}
	}
}
