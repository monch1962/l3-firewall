// Red-team security hardening Round 73 — the boot-time file re-assertion
// (the R72 first-poll reload × etcd syncer interaction): watchPolicyFile's
// FIRST poll re-loads the --opa-embed file's content — which main() already
// loaded moments earlier — 5 seconds into every process start, silently
// REVERTING any policy the etcd syncer applied at boot (syncer.Start →
// loadCurrent → opaEval.Load runs synchronously in main before the watcher
// goroutine's first poll).
//
// With BOTH --etcd-endpoints and --opa-embed configured (the only
// configuration in which the syncer runs — --opa-embed is mandatory, R67),
// the boot sequence is:
//
//	t0     main: readPolicyFile(file) → opa.NewEmbedded(P_file)
//	t0.x   syncer.Start: loadCurrent → eval.Load(P_etcd)   [etcd policy applied]
//	t0+5s  watchPolicyFile FIRST poll (zero lastMod — R72's
//	       "zero means changed" rule): readPolicyFile(file) → eval.Load(P_file)
//
// The R72 fix treats a zero lastMod as "changed" so the first poll performs a
// hardened read before recording any mtime (closing the symlink-seeding
// window). But on a NORMAL restart the file did NOT change since main() read
// it — the reload re-asserts the file's stale baseline OVER the etcd policy
// the syncer just applied. The firewall runs the embedded file's policy (not
// the operator's etcd-managed policy) until the next DISTINCT etcd update:
// the syncer's content-dedupe (R61, lastPolicy) blocks a same-content
// re-push, so the firewall is STUCK on the stale file policy — the R65/R66/
// R67 stale-policy-governs outcome, reached through R72's own fix on the
// etcd+file boot path. An operator who pushes an emergency block-everything
// policy to etcd during an incident and then restarts a host (crash, update,
// k8s reschedule) finds the firewall enforcing the OLD file policy 5 seconds
// after boot, silently undoing the emergency push (allow-by-default →
// traffic the operator blocked is permitted). Before R72 the first poll only
// RECORDED the mtime (never re-read), so the etcd policy applied at boot
// governed until the file genuinely changed — R72's read-verified-record
// fix changed that for the unchanged-file case.
//
// R73 FIX: main() seeds the watcher with the read-VERIFIED mtime of the file
// it actually read (readPolicyFile returns the fstat of its O_NOFOLLOW'd fd
// — no separate TOCTOU-prone os.Stat), and watchPolicyFile's lastMod starts
// from that seed instead of zero. The first poll then loads ONLY when the
// file changed since main()'s read (modTime.After(seed)) — a genuine edit
// during the startup window still self-heals (R72's intent), a planted
// symlink whose target mtime advances past the seed still forces the
// hardened read and is rejected without advancing lastMod (R71/R72's
// anti-poisoning property — the seed is read-verified, so an unread record
// can never move lastMod forward), and an UNCHANGED file no longer re-asserts
// over the etcd policy.
package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/monch1962/l3-firewall/internal/opa"
)

// bootSequence replicates main()'s production wiring for the watcher's first
// poll: read the file exactly as main does (readPolicyFile — hardened read
// whose returned mtime is the R73 seed), compile it, apply the etcd policy,
// then run the watcher's first poll from the seeded lastMod.
func bootSequence(t *testing.T, path string) (*opa.EmbeddedEvaluator, time.Time, string) {
	t.Helper()
	data, seed, err := readPolicyFile(path)
	if err != nil {
		t.Fatalf("readPolicyFile: %v", err)
	}
	eval, err := opa.NewEmbedded(opa.EmbedConfig{Policy: string(data)})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	return eval, seed, string(data)
}

// ── R73.1: the first file-watcher poll must NOT revert the etcd policy ──
// applied at boot. RED (pre-fix): the watcher started with a ZERO lastMod
// (R72's "zero = changed") re-read the unchanged file on its first poll and
// eval.Load(P_file) silently superseded the emergency etcd policy P_etcd the
// syncer applied at startup — the firewall reverted to the stale embedded
// baseline (RED run: Allowed=true Reason="FILE-BASELINE" after the poll).
// GREEN (post-fix): main seeds lastMod from the read-verified mtime of the
// file it read, so the unchanged file is not re-read and P_etcd keeps
// governing.
func TestAttack_BootFirstPollMustNotRevertEtcdPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "l3.rego")

	// The embedded file: the STALE permissive baseline checked into the
	// image (deny-override — allow by default).
	pFile := "package l3_firewall import rego.v1\ndefault allow := true\nreason := \"FILE-BASELINE\"\n"
	writePolicyFile(t, path, pFile)

	// main(): read the file (post-fix this returns the read-verified mtime
	// seed) and compile the boot content once.
	eval, seed, _ := bootSequence(t, path)

	// syncer.Start → loadCurrent: the operator's emergency block-everything
	// policy is in etcd and is applied at boot, BEFORE the watcher's first poll.
	pEtcd := "package l3_firewall import rego.v1\ndefault allow := false\nreason := \"ETCD-EMERGENCY\"\n"
	if err := eval.Load(pEtcd); err != nil {
		t.Fatalf("etcd Load: %v", err)
	}
	res, err := eval.Evaluate(&opa.Input{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Allowed || res.Reason != "ETCD-EMERGENCY" {
		t.Fatalf("premise broken: emergency policy not governing before the first poll (Allowed=%v Reason=%q)", res.Allowed, res.Reason)
	}

	// The file watcher's FIRST poll under the R73 wiring: lastMod seeded with
	// the read-verified mtime (post-fix main → watchPolicyFile(path, eval,
	// seed)). The file did NOT change since main() read it.
	lastMod := seed
	pollPolicyFile(path, eval, &lastMod)

	// The emergency policy must STILL govern.
	res, err = eval.Evaluate(&opa.Input{})
	if err != nil {
		t.Fatalf("Evaluate after first poll: %v", err)
	}
	if res.Allowed || res.Reason != "ETCD-EMERGENCY" {
		t.Errorf("R73 RED: first poll reverted the boot-applied etcd policy — got Allowed=%v Reason=%q, want the ETCD-EMERGENCY policy to keep governing (an unchanged --opa-embed file must not be re-loaded over the syncer's startup Load; with a zero lastMod the R72 first-poll reload re-asserts the stale file baseline and the firewall is stuck on it until a DISTINCT etcd update — R66 stale-policy outcome)", res.Allowed, res.Reason)
	}
}

// ── R73.2: regression — a file EDITED during the startup window (between ──
// main()'s read and the first poll) must still be picked up by the seeded
// first poll (R72's self-heal contract preserved by the R73 seed).
func TestAttack_BootSeededFirstPollStillSelfHealsStartupWindowEdit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "l3.rego")
	p0 := "package l3_firewall import rego.v1\ndefault allow := true\nreason := \"P0\"\n"
	writePolicyFile(t, path, p0)

	eval, seed, _ := bootSequence(t, path)

	// An operator edits the file during the startup window (before the first
	// poll). The edit must land after the seed (distinct mtime tick).
	time.Sleep(20 * time.Millisecond)
	p1 := "package l3_firewall import rego.v1\ndefault allow := false\nreason := \"P1-EDIT\"\n"
	writePolicyFile(t, path, p1)
	if fi, err := os.Stat(path); err != nil || !fi.ModTime().After(seed) {
		t.Skipf("filesystem mtime granularity too coarse to distinguish the edit from the seed (err=%v) — scenario not reproducible here", err)
	}

	// First poll with the SEEDED lastMod (the R73 wiring).
	lastMod := seed
	pollPolicyFile(path, eval, &lastMod)

	res, err := eval.Evaluate(&opa.Input{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Allowed || res.Reason != "P1-EDIT" {
		t.Errorf("startup-window edit not applied by the seeded first poll: got Allowed=%v Reason=%q, want P1-EDIT (the seeded first poll must still load a file that changed since main()'s read — R72 self-heal preserved)", res.Allowed, res.Reason)
	}
}

// ── R73.3: regression — the R72 anti-poisoning property holds with a seed ──
// a symlink planted during the startup window (target mtime in the future)
// must not advance lastMod past the read-verified seed, and the operator's
// real edit afterwards must load on the first attempt.
func TestAttack_BootSeededFirstPollSymlinkCannotAdvancePastSeed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "l3.rego")
	p0 := "package l3_firewall import rego.v1\ndefault allow := true\nreason := \"P0\"\n"
	writePolicyFile(t, path, p0)

	eval, seed, _ := bootSequence(t, path)

	// Attacker plants a symlink to a target with a far-future mtime during
	// the startup window (the R72/R73 model).
	target := filepath.Join(dir, "future.rego")
	writePolicyFile(t, target, "package l3_firewall import rego.v1\ndefault allow := true\nreason := \"ATTACKER\"\n")
	future := time.Now().Add(365 * 24 * time.Hour)
	if err := os.Chtimes(target, future, future); err != nil {
		t.Fatalf("Chtimes target: %v", err)
	}
	if fi, err := os.Stat(target); err != nil || !fi.ModTime().After(time.Now().Add(24*time.Hour)) {
		t.Skipf("filesystem does not honor future mtimes (err=%v) — scenario not reproducible here", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove real file: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	// Seeded first poll: the link's future target mtime is After the seed, so
	// the hardened read is attempted and REJECTED (ELOOP) — lastMod must stay
	// at the read-verified seed (never the attacker's future value).
	lastMod := seed
	pollPolicyFile(path, eval, &lastMod)
	if lastMod.After(seed) {
		t.Errorf("R73 RED: lastMod advanced past the read-verified seed to %v (planted symlink target mtime) — an unread record poisoned the comparator; every legitimate edit with a present mtime would fail modTime.After(lastMod)", lastMod)
	}

	// Recovery: the operator replaces the link with a real emergency policy;
	// one poll must apply it (no second edit required).
	p1 := "package l3_firewall import rego.v1\ndefault allow := false\nreason := \"P1-EMERGENCY\"\n"
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove symlink: %v", err)
	}
	writePolicyFile(t, path, p1)
	pollPolicyFile(path, eval, &lastMod)

	res, err := eval.Evaluate(&opa.Input{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Allowed || res.Reason != "P1-EMERGENCY" {
		t.Errorf("emergency policy not applied after symlink removal: got Allowed=%v Reason=%q, want P1-EMERGENCY (recovery must require no second operator edit)", res.Allowed, res.Reason)
	}
}
