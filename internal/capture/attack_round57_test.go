// Red-team security hardening Round 57 — capture, consumer of the
// securepath '..' fix. NewWriter relies solely on
// securepath.RejectSymlinkComponents for directory-component symlink
// rejection (R45) — unlike persist.SaveState it has no strings.Contains
// guard of its own (R13), so the pre-Clean '..' resolution inside the
// walk made a symlink-before-.. dir pass validation (R57): MkdirAll
// created the state dir inside the attacker-chosen location (parent of
// the symlink target) while the walk — checking only the cleaned path —
// reported no symlink. After the securepath fix, NewWriter must reject
// such paths outright.
package capture

import (
	"os"
	"testing"
)

// ── R57.2: NewWriter rejects a dir whose '..' hides a symlink ─────────
func TestAttack_NewWriterRejectsDotDotDir(t *testing.T) {
	victimDir := t.TempDir()
	parentDir := t.TempDir()
	if err := os.Symlink(victimDir, parentDir+"/evil"); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	// RAW concatenation — filepath.Join would resolve the '..'.
	dir := parentDir + "/evil/../state"

	w, err := NewWriter(Config{Dir: dir})
	if err == nil {
		if w != nil {
			w.Close()
		}
		t.Errorf("expected NewWriter to reject %q: '..' hides symlink component evil → %s", dir, victimDir)
	}
}
