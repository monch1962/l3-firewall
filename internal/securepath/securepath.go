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
	// Reject ".." path components on the RAW input: filepath.Clean
	// (below) resolves ".." lexically BEFORE the walk, so a path like
	// /base/evil/../state would be walked as /base/state while the kernel
	// resolves /base/evil (a planted symlink), then ".." against the REAL
	// directory structure — the walk would validate a different path than
	// the opens that follow, letting MkdirAll and file writes escape the
	// checked tree (R57). persist additionally guards the whole path with
	// strings.Contains (R13); this helper must reject the class for every
	// consumer (capture.NewWriter passes its dir raw). No legitimate
	// firewall state/log/capture directory needs a ".." component.
	if hasDotDotComponent(dir) {
		return fmt.Errorf("path component '..' not allowed: %s", dir)
	}

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

// hasDotDotComponent reports whether the RAW path string contains a ".."
// component. It must be applied BEFORE filepath.Clean/Dir: both resolve
// ".." lexically, so once a path has been through them the component is
// invisible and the traversal can no longer be detected.
func hasDotDotComponent(p string) bool {
	for _, part := range strings.Split(p, string(filepath.Separator)) {
		if part == ".." {
			return true
		}
	}
	return false
}

// RejectUnsafePath validates a FILE path against both path-traversal
// write-through classes, in the only order that is sound:
//
//  1. ".." components in the RAW string — rejected before any lexical
//     resolution (R57 in RejectSymlinkComponents);
//  2. symlinks at every DIRECTORY component of the path.
//
// It exists because the "walk filepath.Dir(path)" idiom used directly by
// file readers silently reopens the R57 bypass: filepath.Dir applies
// filepath.Clean, which consumes the ".." before the walk can see it,
// while the RAW string handed to os.OpenFile/OpenFile is resolved by the
// kernel component-by-component against the real tree. With
// /base/evil/../db.mmdb and /base/evil -> /escape/victim the walk
// validates only /base (a real directory, so it passes) while the open
// lands on /escape/db.mmdb — outside the checked tree, as the
// firewall's UID (geoip --geoip-db, --opa-embed policy file; R85).
//
// The final component is NOT checked for being a symlink here: callers
// open it with O_NOFOLLOW, which the kernel enforces atomically. Use
// RejectSymlinkComponents directly when the argument is itself the
// directory that will be written into (capture --pcap-dir), where a
// symlinked final component must be rejected too.
func RejectUnsafePath(path string) error {
	if hasDotDotComponent(path) {
		return fmt.Errorf("path component '..' not allowed: %s", path)
	}
	return RejectSymlinkComponents(filepath.Dir(path))
}
