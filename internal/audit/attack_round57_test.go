// Red-team security hardening Round 57 — audit, consumer of the
// securepath '..' fix. NewLogger relies solely on
// securepath.RejectSymlinkComponents for directory-component symlink
// rejection (R45) — but filepath.Dir(cfg.Path) applies Clean to the
// directory it hands to the walk, STRIPPING any ".." component before
// the helper is even called. The ".." survives only in the raw
// cfg.Path used by openAuditFile, so a path like
// /base/evil/../audit.log (evil → /victim) makes the walk pass while
// the kernel resolves evil, then ".." → parent(/victim), and every
// audit append lands in parent(/victim)/audit.log — an
// arbitrary-file-append as the firewall's UID (R57). persist has the
// R13 strings.Contains("..") guard; audit needs the same.
package audit

import (
	"os"
	"testing"
)

// ── R57.3: NewLogger rejects a path whose '..' hides a symlink ────────
func TestAttack_NewLoggerRejectsDotDotPath(t *testing.T) {
	victimDir := t.TempDir()
	parentDir := t.TempDir()
	if err := os.Symlink(victimDir, parentDir+"/evil"); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	// RAW concatenation — filepath.Join would resolve the '..'. The
	// ".." lives in the FILE component so filepath.Dir(cfg.Path) strips
	// it before securepath sees the directory.
	path := parentDir + "/evil/../audit.log"

	l, err := NewLogger(Config{Path: path})
	if err == nil {
		if l != nil {
			l.Close()
		}
		t.Errorf("expected NewLogger to reject %q: '..' hides symlink component evil → %s", path, victimDir)
	}
}
