// Package securepath provides path-component validation helpers for
// file-open hardening (the symlink write-through class of attacks).
package securepath

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RejectSymlinkComponents verifies that no path component from the
// filesystem root down to dir is a symbolic link.
//
// O_NOFOLLOW on an opened file (the R42/R43 pattern) only protects the
// FINAL path component: the kernel resolves intermediate directory
// symlinks before the open, so a symlink planted at a directory component
// (e.g. /tmp/state -> /victim) turns every write into an arbitrary-file
// write into the attacker-chosen directory as the firewall's UID (R45 —
// directory symlink write-through). os.MkdirAll "succeeds" through such
// links because the path "exists" as a directory, so callers MUST run
// this check AFTER MkdirAll, not before.
//
// Residual race: an attacker able to swap a checked directory for a
// symlink between this walk and the subsequent open still wins. A fully
// atomic defense requires openat2(RESOLVE_NO_SYMLINKS); this walk closes
// the planted-before-startup window that O_NOFOLLOW alone cannot.
func RejectSymlinkComponents(dir string) error {
	cleaned := filepath.Clean(dir)

	var cur string
	var rest string
	if filepath.IsAbs(cleaned) {
		cur = string(filepath.Separator)
		rest = strings.TrimPrefix(cleaned, cur)
	} else {
		cur = "."
		rest = cleaned
	}

	for _, part := range strings.Split(rest, string(filepath.Separator)) {
		if part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if err != nil {
			if os.IsNotExist(err) {
				// Component does not exist (MkdirAll created it as a real
				// directory, or it is a not-yet-created leaf) — not a symlink.
				continue
			}
			return fmt.Errorf("stating %s: %w", cur, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path component is a symlink: %s", cur)
		}
	}
	return nil
}
