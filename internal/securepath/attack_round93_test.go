package securepath

import (
	"os"
	"path/filepath"
	"testing"
)

// ── R93.1: hardlink write-through on the create/overwrite path ─────────────
//
// The R42/R43/R45/R55/R62/R89 class covers symlinks (O_NOFOLLOW + a directory
// walk) and FIFOs (O_NONBLOCK). A HARD LINK is the third way to make an
// attacker-chosen inode reachable at a predictable firewall-owned path, and no
// flag on open(2) refuses it: O_NOFOLLOW only refuses symbolic links, and a
// hard link is not resolved at all — it IS the inode.
//
// Threat model (the standing R42/R45/R55/R63/R89 one): write access to the
// state / pcap / audit directory, e.g. a shared volume between containers, the
// default /tmp/l3-firewall, or any directory the firewall's UID created 0755.
// The attacker pre-creates <state>.tmp, blocked_00001.pcap or audit.log as a
// hard link to a file the firewall's UID may write — its OWN evidence (audit
// log, state file, pcap) always qualifies, and any other file owned by the same
// UID (a co-tenant service on a shared volume) does too. The firewall's next
// create/overwrite then destroys that file's contents as its own UID.
//
// fs.protected_hardlinks=1 (the Linux default) narrows but does not close this:
// it blocks linking files the attacker does not own, and is commonly disabled
// in container/perf kernels.
func TestAttack_CreateOwnerOnlyRefusesHardLinkedTarget(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.dat")
	const secret = "SECRET EVIDENCE\n"
	if err := os.WriteFile(victim, []byte(secret), 0o600); err != nil {
		t.Fatalf("seeding victim: %v", err)
	}
	target := filepath.Join(dir, "state.json.tmp")
	if err := os.Link(victim, target); err != nil {
		t.Fatalf("creating hard link: %v", err)
	}

	f, err := CreateOwnerOnly(target)
	if err == nil {
		_, _ = f.WriteString(`{"block_stats":{"x":1}}`)
		f.Close()
		t.Error("CreateOwnerOnly accepted a hard-linked path — the opened inode is shared with the attacker's target")
	}

	got, rerr := os.ReadFile(victim)
	if rerr != nil {
		t.Fatalf("victim unreadable after attack: %v", rerr)
	}
	if string(got) != secret {
		t.Errorf("hardlink write-through destroyed the linked file: got %q, want %q", string(got), secret)
	}
}

// The append path (the audit trail) must refuse a hard-linked target too.
// There is no destructive flag here, so the check is a plain refusal: every
// audit append would otherwise land inside the attacker's chosen file as the
// firewall's UID, corrupting another writer's evidence.
func TestAttack_OpenOwnerOnlyRefusesHardLinkedTarget(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.log")
	const secret = "OTHER SERVICE LOG LINE\n"
	if err := os.WriteFile(victim, []byte(secret), 0o600); err != nil {
		t.Fatalf("seeding victim: %v", err)
	}
	target := filepath.Join(dir, "audit.log")
	if err := os.Link(victim, target); err != nil {
		t.Fatalf("creating hard link: %v", err)
	}

	f, err := OpenOwnerOnly(target, os.O_WRONLY|os.O_CREATE|os.O_APPEND)
	if err == nil {
		_, _ = f.WriteString(`{"type":"packet_block"}` + "\n")
		f.Close()
		t.Error("OpenOwnerOnly accepted a hard-linked path — audit appends write through the link")
	}

	got, rerr := os.ReadFile(victim)
	if rerr != nil {
		t.Fatalf("victim unreadable after attack: %v", rerr)
	}
	if string(got) != secret {
		t.Errorf("audit append wrote through a hard link into the linked file: got %q, want %q", string(got), secret)
	}
}

// The refusal must not break the legitimate contract: create a new file, and
// replace the contents of an existing regular file, both ending at mode 0600
// and readable by the owner only.
func TestAttack_CreateOwnerOnlyStillWorksOnOrdinaryPaths(t *testing.T) {
	dir := t.TempDir()

	fresh := filepath.Join(dir, "fresh.pcap")
	f, err := CreateOwnerOnly(fresh)
	if err != nil {
		t.Fatalf("CreateOwnerOnly(fresh): %v", err)
	}
	if _, err := f.WriteString("packet"); err != nil {
		t.Fatalf("write: %v", err)
	}
	f.Close()

	existing := filepath.Join(dir, "existing.log")
	if err := os.WriteFile(existing, []byte("old contents that are much longer"), 0o644); err != nil {
		t.Fatalf("seeding existing: %v", err)
	}
	f2, err := CreateOwnerOnly(existing)
	if err != nil {
		t.Fatalf("CreateOwnerOnly(existing): %v", err)
	}
	if _, err := f2.WriteString("new"); err != nil {
		t.Fatalf("write: %v", err)
	}
	f2.Close()

	for _, p := range []string{fresh, existing} {
		fi, serr := os.Stat(p)
		if serr != nil {
			t.Fatalf("stat %s: %v", p, serr)
		}
		if perm := fi.Mode().Perm(); perm != OwnerOnlyMode {
			t.Errorf("%s mode = %o, want %o", p, perm, OwnerOnlyMode)
		}
	}
	got, _ := os.ReadFile(existing)
	if string(got) != "new" {
		t.Errorf("existing file content = %q, want %q (overwrite contract broken)", string(got), "new")
	}
}
