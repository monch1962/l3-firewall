// Red-team security hardening Round 71 — geoip.NewReader reader-side
// symlink-following: the R62/R70 reader guard applied to the FOURTH
// production file reader.
//
// The R62 (persist.LoadState), R70 (readPolicyFile) and R43/R45
// (audit/capture/persist writers) rounds established the project rule
// that NO production file open follows symlinks: final-component links
// are rejected with O_NOFOLLOW and directory-component links with the
// securepath walk. The R68/R70 fix-propagation accounting
// ("O_NOFOLLOW read-opens 3/3") counted persist.LoadState, readPolicyFile
// and the audit/capture/persist writers — geoip.NewReader, the reader of
// the --geoip-db .mmdb database, was never included. It received only
// the R38 FIFO/oversize treatment (O_NONBLOCK + fstat + size cap) and
// still opens the path verbatim:
//
//	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
//
// no O_NOFOLLOW on the final component, no securepath walk on the
// directory components.
//
// Threat model (the standing R42/R45/R62 posture: attacker with write
// access to the DB file's directory): the attacker plants
// `geo.mmdb -> /attacker/crafted.mmdb` (a symlink to a VALID MaxMind
// database the attacker built mapping their IPs to an allowed country).
// The open follows the link, the crafted database is loaded at startup,
// and every subsequent packet evaluation feeds the attacker-chosen
// country into OPA input: engine's hot path calls
// geoipReader.LookupCountry(pi.SrcIP/DstIP) and the result becomes
// input.geo.src_country / dst_country (internal/opa BuildInput). The
// shipped policy (opa-policies/l3.rego RULE 16) denies by blocked
// country and by allowlist ("deny if input.geo.src_country ==
// blocked_src_countries[_]", "deny if src_country not in
// allowed_src_countries") — so an attacker-controlled country map flips
// country-based deny verdicts in the deny-override firewall: traffic
// that should be dropped by a country rule is permitted (blocking
// silently disabled for the attacker's IPs).
package geoip

import (
	"os"
	"path/filepath"
	"testing"
)

// readTestMMDB loads the committed minimal country database
// (testdata/country-test.mmdb — 8.8.8.0/24 → US, 1.1.1.0/24 → GB,
// generated with the maxmind/mmdbwriter tool; the same static-asset
// approach the pre-R71 geoip_test.go comment described). The target of
// the planted symlink must be a VALID database so a pre-fix follow
// returns a working reader — a rejection is then the ONLY reason the
// read fails (no vacuous error from mmdb parse failure).
func readTestMMDB(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/country-test.mmdb")
	if err != nil {
		t.Fatalf("read testdata/country-test.mmdb: %v", err)
	}
	return b
}

// ── R71.1: NewReader must REJECT a symlink planted at the DB path ─────
// (final path component). Pre-fix the open follows the link, the crafted
// database loads, and NewReader succeeds — the RED failure proves the
// follow, not a vacuous parse error.
func TestAttack_NewReaderRejectsPlantedSymlink(t *testing.T) {
	dir := t.TempDir()

	// The attacker's crafted database — a valid MMDB whose country
	// mapping is under the attacker's control. The target must genuinely
	// exist and be readable so a rejection is the ONLY reason the read
	// fails.
	crafted := filepath.Join(dir, "evil.mmdb")
	if err := os.WriteFile(crafted, readTestMMDB(t), 0644); err != nil {
		t.Fatalf("WriteFile crafted: %v", err)
	}

	// Symlink planted at the DB path, pointing at the crafted database.
	link := filepath.Join(dir, "geo.mmdb")
	if err := os.Symlink(crafted, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	r, err := NewReader(link)
	if err == nil {
		r.Close()
		t.Fatalf("NewReader FOLLOWED the planted symlink and opened the attacker's database — its country map would serve attacker-chosen src_country/dst_country to OPA, flipping country-based deny verdicts (R62 reader class on the --geoip-db path)")
	}
	t.Logf("NewReader correctly rejected the symlink: %v", err)
}

// ── R71.2: NewReader must REJECT a symlink at a DIRECTORY component ───
// of the DB path. O_NOFOLLOW (the R71.1 fix) only protects the final
// component: the kernel resolves an intermediate symlinked directory
// before the open, so a planted `conf -> /attacker/dir` still redirects
// the read. The securepath walk closes this variant.
func TestAttack_NewReaderRejectsDirectorySymlink(t *testing.T) {
	base := t.TempDir()

	// Attacker's directory holding the crafted database.
	attackerDir := filepath.Join(base, "evil")
	if err := os.MkdirAll(attackerDir, 0755); err != nil {
		t.Fatalf("MkdirAll attackerDir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(attackerDir, "geo.mmdb"), readTestMMDB(t), 0644); err != nil {
		t.Fatalf("WriteFile crafted: %v", err)
	}

	// The configured DB directory is swapped for a symlink to it.
	confDir := filepath.Join(base, "conf")
	if err := os.Symlink(attackerDir, confDir); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	dbPath := filepath.Join(confDir, "geo.mmdb")
	r, err := NewReader(dbPath)
	if err == nil {
		r.Close()
		t.Fatalf("NewReader resolved the directory-component symlink (%s -> %s) and opened the attacker's database", confDir, attackerDir)
	}
	t.Logf("NewReader correctly rejected the directory symlink: %v", err)
}

// ── R71.3: regular-file regression — the O_NOFOLLOW + securepath guard ─
// must not break the legitimate database read, and the content must
// decode to the documented country mapping (proves the crafted target
// used above is a genuine database, so R71.1/R71.2 REDs were real).
func TestAttack_NewReaderRegularFileRegression(t *testing.T) {
	r, err := NewReader("testdata/country-test.mmdb")
	if err != nil {
		t.Fatalf("NewReader failed on regular database file: %v", err)
	}
	defer r.Close()

	if got := r.LookupCountry("8.8.8.8"); got != "US" {
		t.Errorf("LookupCountry(8.8.8.8) = %q, want US", got)
	}
	if got := r.LookupCountry("1.1.1.1"); got != "GB" {
		t.Errorf("LookupCountry(1.1.1.1) = %q, want GB", got)
	}
}
