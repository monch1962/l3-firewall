// Red-team security hardening Round 71 — watchPolicyFile mtime-comparator
// poisoning via a rejected read (the R65-class stale-policy DoS on the
// --opa-embed file hot-reload path).
//
// R70 hardened readPolicyFile against the planted-symlink read (O_NOFOLLOW
// + securepath walk), but watchPolicyFile's mtime bookkeeping still
// trusted attacker-influenced stat data: the loop advanced `lastMod =
// modTime` UNCONDITIONALLY, including when readPolicyFile REJECTED the
// entry. os.Stat follows a symlink and reports the TARGET's mtime, so an
// attacker with write access to the policy directory (the standing
// R42/R45/R62/R70 model) who plants `l3.rego -> /attacker/t` where t has a
// far-future mtime (touch -d — trivially achievable) poisons the
// comparator in ONE 5-second poll window: the rejected read (ELOOP, logged)
// advances lastMod to the future value, and every subsequent legitimate
// policy edit — the operator's emergency block-everything policy written
// during an incident, whose mtime is the PRESENT — fails the
// `modTime.After(lastMod)` test and is silently never enforced. The
// hot-reload plane is dead until the wall clock passes the poisoned
// timestamp (years), with zero errors after the single rejected poll (the
// R70 skip makes subsequent polls silent). This is the R65/R66/R67
// stale-policy outcome — attacker kills the policy update plane — on the
// file-based reload path, achieved with a single directory-entry swap.
package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakePolicyReloader records every policy handed to Load so the test can
// assert exactly which policies were enforced.
type fakePolicyReloader struct {
	policies []string
}

func (f *fakePolicyReloader) Load(policy string) error {
	f.policies = append(f.policies, policy)
	return nil
}

func writePolicyFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
}

// ── R71.4: a rejected read must not poison lastMod with the attacker's ─
// future target mtime. RED (pre-fix): after the symlink episode the
// operator's emergency policy — written with a NORMAL mtime — is never
// reloaded because lastMod was advanced to the far-future value.
func TestAttack_HotReloadRejectedReadDoesNotPoisonLastMod(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "l3.rego")

	// Phase 1: a legitimate policy P0 is in place and polled once
	// (baseline — no load on the first poll, lastMod = P0's mtime).
	p0 := "package firewall\nallow := true\n"
	writePolicyFile(t, path, p0)
	t0 := time.Now().Add(-2 * time.Second)
	if err := os.Chtimes(path, t0, t0); err != nil {
		t.Fatalf("Chtimes P0: %v", err)
	}

	reloader := &fakePolicyReloader{}
	var lastMod time.Time
	pollPolicyFile(path, reloader, &lastMod)
	if len(reloader.policies) != 0 {
		t.Fatalf("baseline poll loaded %d policies, want 0", len(reloader.policies))
	}

	// Phase 2: the attacker plants a symlink whose TARGET carries a
	// far-future mtime. One poll passes (the 5-second window).
	target := filepath.Join(dir, "future.rego")
	writePolicyFile(t, target, "package firewall\nallow := false\n")
	future := time.Now().Add(365 * 24 * time.Hour) // +1 year
	if err := os.Chtimes(target, future, future); err != nil {
		t.Fatalf("Chtimes target: %v", err)
	}
	// Some filesystems clamp future mtimes — verify the poison actually
	// took before trusting the scenario.
	if fi, err := os.Stat(target); err != nil || !fi.ModTime().After(time.Now().Add(24*time.Hour)) {
		t.Skipf("filesystem does not honor future mtimes (err=%v mtime=%v) — scenario not reproducible here", err, fi.ModTime())
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove policy: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	pollPolicyFile(path, reloader, &lastMod)
	if len(reloader.policies) != 0 {
		t.Fatalf("symlink content reached the reloader (%d policies) — the R70 read guard is broken", len(reloader.policies))
	}

	// Phase 3: the attacker removes the symlink; the operator writes the
	// emergency policy P1 with a NORMAL mtime — strictly newer than the
	// last GOOD policy (t0), strictly older than the poisoned future.
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove symlink: %v", err)
	}
	p1 := "package firewall\nallow := false\n"
	writePolicyFile(t, path, p1)
	t1 := t0.Add(2 * time.Second)
	if !t1.Before(future) {
		t.Skipf("test clock broken: t1 %v not before future %v", t1, future)
	}
	if err := os.Chtimes(path, t1, t1); err != nil {
		t.Fatalf("Chtimes P1: %v", err)
	}
	pollPolicyFile(path, reloader, &lastMod)

	// The emergency policy MUST have been enforced.
	for _, p := range reloader.policies {
		if p == p1 {
			t.Logf("emergency policy P1 enforced after the symlink episode (lastMod not poisoned)")
			return
		}
	}
	t.Errorf("emergency policy P1 was NEVER reloaded: the rejected read advanced lastMod to the attacker's future target mtime (%v), so the operator's edit (mtime %v) failed modTime.After(lastMod) — hot-reload plane dead until the clock passes the poisoned value (R65-class stale-policy DoS on --opa-embed)", future, t1)
}

// ── R71.5: recovery regression — after a rejected-read episode whose ──
// target mtime is NOT in the future (the ordinary R70 case), a later
// real policy edit must still reload exactly once. Guards the R71 fix
// against over-correcting (e.g. never advancing lastMod at all, which
// would reload on every poll forever).
func TestAttack_HotReloadRejectsThenRecovers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "l3.rego")

	p0 := "package firewall\nallow := true\n"
	writePolicyFile(t, path, p0)
	t0 := time.Now().Add(-2 * time.Second)
	if err := os.Chtimes(path, t0, t0); err != nil {
		t.Fatalf("Chtimes P0: %v", err)
	}

	reloader := &fakePolicyReloader{}
	var lastMod time.Time
	pollPolicyFile(path, reloader, &lastMod)

	// Planted symlink (normal target mtime), rejected by the R70 guard.
	target := filepath.Join(dir, "evil.rego")
	writePolicyFile(t, target, "package firewall\nallow := false\n")
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	pollPolicyFile(path, reloader, &lastMod)
	if len(reloader.policies) != 0 {
		t.Fatalf("symlink content reached the reloader")
	}

	// Attacker removes the link; operator writes a newer real policy.
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove link: %v", err)
	}
	p1 := "package firewall\nallow := false\n"
	writePolicyFile(t, path, p1)
	t1 := t0.Add(2 * time.Second)
	if err := os.Chtimes(path, t1, t1); err != nil {
		t.Fatalf("Chtimes P1: %v", err)
	}
	pollPolicyFile(path, reloader, &lastMod)

	count := 0
	for _, p := range reloader.policies {
		if p == p1 {
			count++
		}
	}
	if count != 1 {
		t.Errorf("P1 reloaded %d times after recovery, want exactly 1 (lastMod must advance on success but not on rejection)", count)
	}
}
