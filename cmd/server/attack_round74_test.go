// Red-team security hardening Round 74 — the hot-reload lastMod backward
// regression (the R71/R72/R73 mtime-comparator class, BACKWARD direction):
// pollPolicyFile advances *lastMod = modTime — the os.Stat-derived value —
// even when NO hardened read occurred (the no-change path). os.Stat follows
// a planted symlink and reports the TARGET's mtime, so an attacker with
// policy-directory write access (the standing R42/R70/R71/R72/R73 model)
// plants a link whose target mtime is EARLIER than lastMod: the poll skips
// the read (modTime.After(lastMod) is false — no ELOOP, no error log, no
// backoff) and REGRESSES lastMod to the old value.
//
// Once the attacker restores the real file (a rename dance — park the file,
// plant the link for one 5-second poll, rename it back — requires ONLY
// directory write access, no file-content write, no read of the policy), the
// file's UNCHANGED mtime is now After the regressed record: the next poll
// re-reads and re-loads the file's content — which main() already loaded at
// boot and which the etcd syncer's startup Load (or any later etcd push)
// superseded. An UNCHANGED file re-asserts its stale policy over the
// operator's etcd-managed policy — the R73 outcome (R66-class stale-policy
// regression), now attacker-triggerable on demand at ANY quiescent moment,
// silently (a successful load logs nothing), with no content modification.
// The syncer's content-dedupe (R61, lastPolicy) then blocks a same-content
// etcd re-push, so the firewall is STUCK on the stale file policy until the
// next DISTINCT etcd update.
//
// R71/R72/R73 tested only FORWARD poisoning (future-mtime targets — rejected
// reads must not advance lastMod). The invariant they established — "an
// unread record can never move lastMod" — holds only for forward movement;
// BACKWARD movement from an unread stat is unguarded, and a regressed record
// makes an unchanged file pass the comparator.
//
// R74 FIX: pollPolicyFile advances lastMod ONLY from the read-verified fd
// mtime readPolicyFile returns on a successful read+load, and NEVER touches
// the record on the no-change path — a backward-moving stat mtime is not a
// legitimate change signal (a real file's mtime does not spontaneously move
// backward) and must not regress the record.
package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/monch1962/l3-firewall/internal/opa"
)

// ── R74.1: a planted symlink with an OLD target mtime must not regress ──
// lastMod, and must not enable an UNCHANGED file to re-assert its stale
// policy over the etcd-applied policy. RED (pre-fix): poll 1 (link planted)
// skips the read — the old target mtime is not After the seed — and
// regresses lastMod to the old value (no ELOOP, no error, no backoff);
// poll 2 (real file restored, mtime unchanged since boot) then sees its
// mtime After the regressed record, re-reads the UNCHANGED file and
// eval.Load re-asserts the file's stale baseline over the emergency etcd
// policy applied at boot — the R73 regression, reached through the one
// direction R71/R72/R73 left unguarded.
func TestAttack_HotReloadOldMtimeSymlinkCannotRegressLastMod(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "l3.rego")

	// The embedded file: the stale permissive baseline (deny-override —
	// allow by default).
	pFile := "package l3_firewall import rego.v1\ndefault allow := true\nreason := \"FILE-BASELINE\"\n"
	writePolicyFile(t, path, pFile)

	// main(): read the file and compile the boot content once (R73 wiring).
	eval, seed, _ := bootSequence(t, path)

	// syncer.Start → loadCurrent: the operator's emergency block-everything
	// policy governs at boot, BEFORE the watcher's first poll.
	pEtcd := "package l3_firewall import rego.v1\ndefault allow := false\nreason := \"ETCD-EMERGENCY\"\n"
	if err := eval.Load(pEtcd); err != nil {
		t.Fatalf("etcd Load: %v", err)
	}

	// The attacker's dance (directory write access ONLY — no file write, no
	// content read): park the real file, plant a symlink to a file whose
	// mtime is in the PAST, let one poll run, restore the real file.
	parked := filepath.Join(dir, ".l3.rego.parked")
	if err := os.Rename(path, parked); err != nil {
		t.Fatalf("Rename real file aside: %v", err)
	}
	oldTarget := filepath.Join(dir, "old.rego")
	writePolicyFile(t, oldTarget, "package l3_firewall import rego.v1\ndefault allow := true\nreason := \"ATTACKER\"\n")
	past := seed.Add(-24 * time.Hour)
	if err := os.Chtimes(oldTarget, past, past); err != nil {
		t.Fatalf("Chtimes old target: %v", err)
	}
	if fi, err := os.Stat(oldTarget); err != nil || !fi.ModTime().Before(seed) {
		t.Skipf("filesystem does not honor past mtimes (err=%v) — scenario not reproducible here", err)
	}
	if err := os.Symlink(oldTarget, path); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	// Poll 1 — link planted: the old target mtime is NOT After the seed, so
	// the poll must leave the read-verified record untouched (no regression).
	lastMod := seed
	pollPolicyFile(path, eval, &lastMod)
	if lastMod.Before(seed) {
		t.Errorf("R74 RED: lastMod regressed from the read-verified seed %v to %v by an UNREAD stat of a planted symlink (old target mtime) — a backward-moved record makes an unchanged file pass the modTime.After comparator on the next poll and re-assert the stale file policy over the etcd policy (the R73 outcome, attacker-triggerable on demand)", seed, lastMod)
	}

	// Attacker restores the real file (rename back — mtime unchanged since
	// boot, so the file is genuinely UNCHANGED since main() read it).
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove symlink: %v", err)
	}
	if err := os.Rename(parked, path); err != nil {
		t.Fatalf("Rename real file back: %v", err)
	}

	// Poll 2 — real file restored, content and mtime identical to boot.
	pollPolicyFile(path, eval, &lastMod)

	// The emergency etcd policy must STILL govern: an unchanged file must not
	// re-assert over it (R73 contract), regardless of the mtime dance.
	res, err := eval.Evaluate(&opa.Input{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Allowed || res.Reason != "ETCD-EMERGENCY" {
		t.Errorf("R74 RED: the mtime dance forced an UNCHANGED file to reload — got Allowed=%v Reason=%q, want the ETCD-EMERGENCY policy to keep governing (backward lastMod regression let the restored file's boot mtime pass modTime.After; the stale file baseline re-asserted over the etcd policy and the R61 dedupe blocks a same-content etcd re-push)", res.Allowed, res.Reason)
	}
}

// ── R74.2: regression — genuine FORWARD edits must still reload after ──
// no-change polls (the fix must not freeze the hot-reload plane: the record
// staying put across no-change polls must not suppress a real edit).
func TestAttack_HotReloadForwardEditStillReloadsAfterNoChangePolls(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "l3.rego")
	p0 := "package l3_firewall import rego.v1\ndefault allow := true\nreason := \"P0\"\n"
	writePolicyFile(t, path, p0)

	eval, seed, _ := bootSequence(t, path)

	// Several no-change polls: lastMod must stay at the read-verified seed
	// and nothing may load.
	lastMod := seed
	for i := 0; i < 3; i++ {
		pollPolicyFile(path, eval, &lastMod)
	}
	if !lastMod.Equal(seed) {
		t.Fatalf("lastMod drifted from the seed across no-change polls: got %v want %v", lastMod, seed)
	}

	// A genuine forward edit (operator writes a new policy) must load.
	time.Sleep(20 * time.Millisecond)
	p1 := "package l3_firewall import rego.v1\ndefault allow := false\nreason := \"P1-EDIT\"\n"
	writePolicyFile(t, path, p1)
	if fi, err := os.Stat(path); err != nil || !fi.ModTime().After(seed) {
		t.Skipf("filesystem mtime granularity too coarse to distinguish the edit from the seed (err=%v) — scenario not reproducible here", err)
	}
	pollPolicyFile(path, eval, &lastMod)

	res, err := eval.Evaluate(&opa.Input{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Allowed || res.Reason != "P1-EDIT" {
		t.Errorf("forward edit not applied after no-change polls: got Allowed=%v Reason=%q, want P1-EDIT (the R74 fix must keep the hot-reload plane live for genuine edits)", res.Allowed, res.Reason)
	}
}
