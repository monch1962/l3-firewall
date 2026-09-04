// Red-team security hardening Round 72 — watchPolicyFile first-poll
// mtime-comparator poisoning via an unverified stat record (the R71
// read-before-record invariant violated on the zero-lastMod path).
//
// R71 hardened the changed-path bookkeeping: a REJECTED read (planted
// symlink) no longer advances lastMod, because os.Stat follows the link
// and reports the TARGET's mtime — recording it would poison the
// modTime.After(lastMod) comparator with a far-future value, silently
// killing the hot-reload plane for every subsequent legitimate edit (the
// R65/R66/R67 stale-policy outcome on --opa-embed, R71.4).
//
// But R71's guard only engages when the poll takes the read branch:
//
//	if !lastMod.IsZero() && modTime.After(*lastMod) { read... }
//	*lastMod = modTime
//
// A zero lastMod — the FIRST poll after watchPolicyFile starts, before
// anything has ever been read on this path — short-circuits the read
// entirely and records the os.Stat-derived mtime unconditionally. In the
// deployed binary the watcher goroutine starts AFTER main()'s initial
// readPolicyFile (cmd/server/main.go) but AFTER unbounded-latency
// component setup in between (etcd syncer dial, threat-intel feed
// fetches — the --threat-intel-url fetches happen synchronously in
// main), so an attacker with write access to the policy directory (the
// standing R42/R45/R62/R70/R71 model) can plant
// `l3.rego -> /attacker/t` with a far-future target mtime (touch -d)
// during that startup window. The first poll then records the future
// mtime WITH NO READ ATTEMPT — no ELOOP, no rejection, no 30s backoff —
// and every subsequent legitimate policy edit (the operator's emergency
// block-everything policy written during an incident, mtime = present)
// fails modTime.After(lastMod) forever: the exact R71.4 impact, reached
// through the one path R71's fix never guarded. The poisoned record also
// self-sustains: while the entry stays a link, each poll's stat reports
// the same future mtime, which is never After itself, so lastMod is
// silently re-recorded every 5 seconds.
//
// R72 FIX: a zero lastMod is treated as "changed" — the poll attempts
// the hardened read (readPolicyFile rejects the planted link with
// ELOOP) and advances lastMod ONLY on a successful read+load. A
// rejected first poll returns the 30s backoff with lastMod still zero,
// so the loop re-attempts and recovers the moment a real entry appears
// (loading its content — no second operator edit required). On a normal
// restart the first poll re-reads the file main() already loaded and
// reloads identical content once (a single extra compile per process
// start) — the price of making the record read-verified.
package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ── R72.1: the FIRST poll (zero lastMod) must not record an mtime ──────
// observed through a planted symlink. RED (pre-fix): the zero-lastMod
// short-circuit records the symlink TARGET's far-future mtime with no
// read attempt, poisoning the comparator; the operator's emergency
// policy written afterwards (normal mtime) is never reloaded.
func TestAttack_HotReloadFirstPollSymlinkCannotSeedLastMod(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "l3.rego")

	// The attacker plants the symlink BEFORE the watcher's first poll —
	// the startup window between main()'s initial read and the watcher
	// goroutine's first poll (which in the deployed binary includes the
	// etcd syncer dial and synchronous threat-intel feed fetches).
	target := filepath.Join(dir, "future.rego")
	if err := os.WriteFile(target, []byte("package firewall\nallow := false\n"), 0644); err != nil {
		t.Fatalf("WriteFile target: %v", err)
	}
	future := time.Now().Add(365 * 24 * time.Hour) // +1 year
	if err := os.Chtimes(target, future, future); err != nil {
		t.Fatalf("Chtimes target: %v", err)
	}
	// Some filesystems clamp future mtimes — verify the scenario first.
	if fi, err := os.Stat(target); err != nil || !fi.ModTime().After(time.Now().Add(24*time.Hour)) {
		t.Skipf("filesystem does not honor future mtimes (err=%v mtime=%v) — scenario not reproducible here", err, fi.ModTime())
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	reloader := &fakePolicyReloader{}
	var lastMod time.Time // fresh watcher: zero lastMod
	pollPolicyFile(path, reloader, &lastMod)

	// The FIRST poll must not have seeded lastMod from the link's target
	// mtime: R71's read-before-record invariant applies to the first poll
	// too — the record requires a SUCCESSFUL hardened read, and the
	// symlink read was rejected (nothing may have reached the reloader).
	if !lastMod.IsZero() {
		t.Errorf("R72 RED: first poll recorded lastMod=%v from an UNREAD planted symlink (target mtime) — os.Stat follows the link, and a zero lastMod short-circuited the hardened read entirely; the comparator is poisoned: every legitimate edit with a present mtime fails modTime.After(%v) and the hot-reload plane is dead (R71.4 impact via the first-poll path)", lastMod, lastMod)
	}
	if len(reloader.policies) != 0 {
		t.Fatalf("symlink content reached the reloader (%d policies) — the R70 read guard is broken", len(reloader.policies))
	}

	// Recovery: the attacker removes the link; the operator writes the
	// emergency policy P1 with a NORMAL mtime and never touches it again.
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove symlink: %v", err)
	}
	p1 := "package firewall\nallow := false\n"
	if err := os.WriteFile(path, []byte(p1), 0644); err != nil {
		t.Fatalf("WriteFile P1: %v", err)
	}
	pollPolicyFile(path, reloader, &lastMod)

	found := false
	for _, p := range reloader.policies {
		if p == p1 {
			found = true
		}
	}
	if !found {
		t.Errorf("R72 RED: emergency policy P1 was NEVER reloaded after the first-poll symlink episode — the unverified first-poll record poisoned lastMod to the attacker's future target mtime, so the real file's edit failed modTime.After(lastMod); recovery must require no second operator edit")
	}
}

// ── R72.2: regression guard — the first poll of a REAL file must load ──
// exactly once and record its mtime (not stay zero / not reload on every
// poll forever). Guards the R72 fix against over-correcting: a zero
// lastMod must converge to a stable recorded baseline after one read.
func TestAttack_HotReloadFirstPollRealFileConverges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "l3.rego")
	p0 := "package firewall\nallow := true\n"
	if err := os.WriteFile(path, []byte(p0), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	reloader := &fakePolicyReloader{}
	var lastMod time.Time

	// First poll: real file — must read+load P0 once and record mtime.
	pollPolicyFile(path, reloader, &lastMod)
	if len(reloader.policies) != 1 || reloader.policies[0] != p0 {
		t.Errorf("first poll of a real file loaded %d policies %q, want exactly [P0] once", len(reloader.policies), reloader.policies)
	}
	if lastMod.IsZero() {
		t.Errorf("first poll did not record lastMod after a successful read")
	}

	// Second poll: unchanged file — no reload.
	pollPolicyFile(path, reloader, &lastMod)
	if len(reloader.policies) != 1 {
		t.Errorf("unchanged second poll reloaded %d times (policies=%d), want 0 extra loads — lastMod must suppress identical polls", len(reloader.policies)-1, len(reloader.policies))
	}
}
