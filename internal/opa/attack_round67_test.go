package opa

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// ── R67: Concurrent-Load ordering race (stale policy supersedes newer) ─────
// EmbeddedEvaluator.Load swaps compiler/policy in one critical section, then
// calls rebuild() — which RE-READS e.compiler and swaps e.prepared in a
// SEPARATE critical section. With two concurrent Loaders — the etcd syncer's
// watch goroutine and the --opa-embed file hot-reload watcher (BOTH always
// wired when --etcd-endpoints is configured, since --opa-embed is mandatory)
// — an OLDER policy whose slower compile finishes LAST silently supersedes a
// NEWER policy whose Load already returned success: the newer policy
// governs for a moment, then is permanently reverted by the older policy's
// late swap — the R66 stale-policy-regression class (reverting an
// operator's emergency policy) at the evaluator boundary. Invisible to
// -race: every field access is mutex-guarded; only the ORDER of the two
// swaps is wrong.
//
// Determinism: the older Load (40k rules, ~550ms compile) is issued first;
// the newer fast Load (~0.4ms) is issued 1ms later and completes ~549ms
// BEFORE the older Load's compiler swap — so the older swap lands last and
// governs. The margin is three orders of magnitude wider than any timing
// jitter; no measurement or polling needed.

// slowRacePolicy returns a large Rego policy (40k rules) whose compile phase
// is hundreds of milliseconds — long enough that the concurrent fast Load
// completes long before the slow Load's compiler swap.
func slowRacePolicy() string {
	var sb strings.Builder
	sb.WriteString("package l3_firewall import rego.v1\n")
	for i := 0; i < 40000; i++ {
		sb.WriteString(fmt.Sprintf("allow if { false } # rule %d\n", i))
	}
	sb.WriteString("default allow := false\n")
	sb.WriteString("reason := \"SLOW_OLD\"\n")
	return sb.String()
}

// fastRacePolicy is the NEWER policy: it must govern once its Load returns.
const fastRacePolicy = `package l3_firewall import rego.v1
default allow := true
reason := "FAST_NEW"
`

func TestAttack_ConcurrentLoadStalePolicySupersedesNewer(t *testing.T) {
	slow := slowRacePolicy()

	e, err := NewEmbedded(EmbedConfig{Policy: fastRacePolicy})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}

	// Older, slow policy — issued FIRST, its compile finishes LAST.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = e.Load(slow)
	}()

	// Give the slow compile a head start (1ms vs its ~550ms compile —
	// three orders of magnitude of margin), then issue the NEWER policy.
	// Guard BEFORE issuing: the slow Load must still be in flight (its
	// compile not yet finished) for the race to be exercised — with the
	// fix, Load(fast) blocks until the slow Load completes, so checking
	// after Load(fast) returns would always see the slow Load done.
	time.Sleep(time.Millisecond)
	select {
	case <-done:
		t.Fatal("slow Load completed before the fast Load was issued — race not exercised")
	default:
	}
	if err := e.Load(fastRacePolicy); err != nil {
		t.Fatalf("Load(fast): %v", err)
	}
	// The fast Load returned success — it must be the governing policy.
	<-done // wait for the older Load to fully finish

	res, err := e.Evaluate(&Input{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !res.Allowed || res.Reason != "FAST_NEW" {
		t.Fatalf("newer policy superseded by older: got Allowed=%v Reason=%q, want allow=true reason=FAST_NEW (a completed newer Load must govern)",
			res.Allowed, res.Reason)
	}
}
