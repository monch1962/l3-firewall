package securepath

import (
	"os"
	"path/filepath"
	"testing"
)

// ── R45.13: intermediate directory component symlink is rejected ─────
// The consumer tests (persist/capture/audit) plant the symlink AT the dir
// itself. The nastier variant: a symlink ABOVE the target dir, with the
// dir itself created by MkdirAll THROUGH the link (e.g. /tmp/evil ->
// /victim, then MkdirAll("/tmp/evil/state") creates /victim/state). The
// final component is then a REAL directory, so a check that only Lstat's
// the final component misses it — the walk must check every component.
func TestRejectSymlinkComponents_IntermediateComponent(t *testing.T) {
	victimDir := t.TempDir()
	parentDir := t.TempDir()

	// /tmp/xxx/evil -> victimDir (symlink ABOVE the target dir)
	evilLink := filepath.Join(parentDir, "evil")
	if err := os.Symlink(victimDir, evilLink); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	// Simulate what the caller does: MkdirAll through the link creates a
	// real directory inside the victim
	targetDir := filepath.Join(evilLink, "state")
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		t.Fatalf("MkdirAll through symlink: %v", err)
	}

	if err := RejectSymlinkComponents(targetDir); err == nil {
		t.Error("expected rejection of path with intermediate symlink component")
	}
}

// ── R45.14: symlink at the final dir component is rejected ────────────
func TestRejectSymlinkComponents_FinalComponent(t *testing.T) {
	victimDir := t.TempDir()
	parentDir := t.TempDir()
	link := filepath.Join(parentDir, "logdir")
	if err := os.Symlink(victimDir, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	if err := RejectSymlinkComponents(link); err == nil {
		t.Error("expected rejection of symlink at final component")
	}
}

// ── R45.15: genuine directories (absolute and relative) are accepted ──
func TestRejectSymlinkComponents_RealDirs(t *testing.T) {
	abs := t.TempDir()
	if err := RejectSymlinkComponents(abs); err != nil {
		t.Errorf("absolute real dir rejected: %v", err)
	}

	rel := filepath.Join(abs, "sub", "nested")
	if err := os.MkdirAll(rel, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// Relative real dir: chdir into a fresh temp dir so "sub/nested"
	// resolves from the CWD without ".." components. The R45 version
	// built the relative path with filepath.Rel against a DIFFERENT
	// temp dir, yielding a "../.."-heavy path — which R57 now (correctly)
	// rejects, because the kernel resolves ".." against the real tree
	// (following planted symlinks) in a way the lexical walk cannot
	// follow. The genuine relative-path case must be ".."-free.
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("sub/nested", 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := RejectSymlinkComponents("sub/nested"); err != nil {
		t.Errorf("relative real dir rejected: %v", err)
	}

	if err := RejectSymlinkComponents("."); err != nil {
		t.Errorf("'.' rejected: %v", err)
	}
}
