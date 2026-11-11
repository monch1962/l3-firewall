// Red-team security hardening Round 85 — the R57 '..'-hides-a-symlink
// class, which never propagated to the two FILE readers added or
// re-hardened AFTER round 57. R57 fixed securepath (reject '..' on the
// raw input) and its then-existing consumers persist/audit, but a
// consumer that hands `filepath.Dir(path)` to the walk silently defeats
// the fix: filepath.Dir applies filepath.Clean, which resolves '..'
// lexically BEFORE RejectSymlinkComponents sees the directory. The '..'
// survives only in the RAW path handed to os.OpenFile, where the kernel
// resolves it component-by-component against the REAL tree.
//
// geoip is the first such consumer (hardened R71, after R57). With
// --geoip-db=/base/evil/../evil.mmdb and /base/evil -> /escape/victim,
// the walk validates only /base (a real directory, so it passes) while
// the kernel resolves evil, then '..' against victim's real parent, and
// the open lands on /escape/evil.mmdb — a database OUTSIDE the checked
// tree, loaded as the firewall's GeoIP database. engine feeds
// LookupCountry into OPA input (input.geo.src_country/dst_country), so
// an attacker-chosen database flips the country-based deny rules in the
// deny-override policy (RULE 16) — the exact R71 impact chain, reached
// without needing write access to the checked directory itself.
package geoip

import (
	"os"
	"path/filepath"
	"testing"
)

// ── R85.1: '..' in --geoip-db hides a symlink and escapes the walk ────
// NewReader("/base/evil/../evil.mmdb") with /base/evil -> /escape/victim
// must FAIL. filepath.Dir(raw) is /base, so the walk validates /base and
// passes; the kernel resolves the RAW string to /escape/evil.mmdb.
func TestAttack_NewReaderRejectsDotDotHiddenSymlink(t *testing.T) {
	// escapeRoot is the attacker-chosen directory the kernel lands in
	// (".." after a symlink resolves against the TARGET's real parent,
	// not the link's own directory).
	escapeRoot := t.TempDir()
	victimDir := filepath.Join(escapeRoot, "victim")
	if err := os.MkdirAll(victimDir, 0755); err != nil {
		t.Fatalf("mkdir victim: %v", err)
	}
	// The crafted database — a VALID mmdb, so a rejection is the only
	// reason the read can fail (no vacuous parse error).
	crafted := filepath.Join(escapeRoot, "evil.mmdb")
	if err := os.WriteFile(crafted, readTestMMDB(t), 0644); err != nil {
		t.Fatalf("WriteFile crafted: %v", err)
	}

	// base is the only tree the walk can see.
	base := t.TempDir()
	if err := os.Symlink(victimDir, filepath.Join(base, "evil")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	// RAW concatenation — filepath.Join would resolve the '..' and
	// defeat the test (the guard lives on the raw string).
	raw := base + "/evil/../evil.mmdb"

	// Precondition: the kernel really does resolve the traversal to the
	// crafted database outside base — otherwise the test is vacuous.
	if _, err := os.Stat(raw); err != nil {
		t.Fatalf("precondition broken: kernel does not resolve %q: %v", raw, err)
	}
	if _, err := os.Stat(filepath.Join(base, "evil.mmdb")); !os.IsNotExist(err) {
		t.Fatalf("precondition broken: cleaned path %s must not exist", filepath.Join(base, "evil.mmdb"))
	}

	r, err := NewReader(raw)
	if err == nil {
		country := r.LookupCountry("8.8.8.8")
		r.Close()
		t.Errorf("expected NewReader to reject %q: '..' hides symlink evil -> %s, so the read lands at %s while the walk only checked %s; loaded the out-of-tree database (8.8.8.8 -> %q) — attacker-chosen country mappings flip the OPA country deny rules",
			raw, victimDir, crafted, base, country)
	}
}
