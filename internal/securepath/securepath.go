// Package securepath provides path-component validation helpers for
// file-open hardening (the symlink write-through class of attacks).
package securepath

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

// OwnerOnlyMode is the mode every firewall-owned runtime file is forced to.
const OwnerOnlyMode = 0o600

// ReadCredentialFile reads a credential-bearing file (TLS key material, a CA
// bundle) with the hardening every credential reader in this tree needs
// (R91: the admin key pair; R97: the etcd policy channel's CA and client
// identity). A bare os.ReadFile — and every library that wraps it, e.g.
// tls.LoadX509KeyPair — has none of these:
//
//   - ".." components rejected on the RAW path, before any lexical cleaning
//     (filepath.Dir/Clean consume the ".." while the kernel resolves the raw
//     string) — R85;
//   - a symlink at any DIRECTORY component rejected, because the kernel
//     resolves those before the open — R45/R62;
//   - O_NOFOLLOW: a symlink at the FINAL component refused — R42. A planted
//     link serves an attacker-chosen trust root or private key, which for a
//     TLS *client* means the peer it authenticates is the attacker;
//   - O_NONBLOCK + a regular-file check on the already-opened descriptor: a
//     FIFO planted at the path would block the open forever, and these reads
//     run synchronously in main() before the engine starts (R14/R15/R38) —
//     the type check on the open fd leaves no Stat/Open TOCTOU window;
//   - the size cap enforced through fstat AND io.LimitReader, so an oversized
//     "certificate" is refused before its content is buffered — R42's
//     check-before-allocate doctrine.
//
// A hard link (nlink > 1) is deliberately NOT refused here: this is a
// read-only open, and the harm R93 names — destroying or appending to a
// shared inode — cannot happen through it. An attacker who can write the
// directory can already replace the file outright, so a link check would add
// breakage (e.g. unusual but legitimate hard-linked key stores) without
// removing any capability.
func ReadCredentialFile(path string, maxSize int64) ([]byte, error) {
	if err := RejectUnsafePath(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("opening credential file %s: %w", path, err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stating credential file %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("credential path is not a regular file: %s", path)
	}
	if maxSize > 0 && fi.Size() > maxSize {
		return nil, fmt.Errorf("credential file %s too large: %d bytes (max %d)", path, fi.Size(), maxSize)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading credential file %s: %w", path, err)
	}
	if maxSize > 0 && int64(len(data)) > maxSize {
		return nil, fmt.Errorf("credential file %s grew beyond %d bytes while reading", path, maxSize)
	}
	return data, nil
}

// OpenOwnerOnly opens path with the caller's access mode/flags plus the
// two hardening flags every writer of firewall-owned runtime data needs,
// and forces OwnerOnlyMode on the resulting file descriptor.
//
// It centralises three separate rules, so a consumer cannot pick up two and
// miss the third (R85/R89/R90 — the "centralise a guard class, then find
// every consumer" rule; R89 centralised it for persist and capture and this
// round found the third writer, the audit log, still creating 0644):
//
//   - O_NOFOLLOW: a symlink planted at the FINAL component is refused, so
//     the write cannot be redirected into an arbitrary file writable by the
//     firewall's UID (R42);
//   - O_NONBLOCK: a FIFO planted at the (predictable) path is refused with
//     ENXIO instead of blocking the caller forever waiting for a reader —
//     these write paths run on the NFQUEUE hot path and on the 60-second
//     state ticker, where a blocking open stalls the whole engine (R55);
//   - no hard link: a file whose link count exceeds one is refused (R93).
//     O_NOFOLLOW refuses only SYMBOLIC links; a hard link is not resolved at
//     all — it IS the inode — so no open(2) flag can reject it. O_NOFOLLOW,
//     the directory walk and O_NONBLOCK therefore all pass while the file the
//     firewall is about to shorten or append to is shared with an attacker's
//     chosen name. The standing model (write access to the state/pcap/log
//     directory: /tmp/l3-firewall, a shared volume, or the 0755 directory the
//     constructors create) is enough to pre-create <state>.tmp,
//     blocked_00001.pcap or audit.log as a link to a file the firewall's UID
//     may write — its OWN evidence always qualifies, and any co-tenant file of
//     the same UID does too. fs.protected_hardlinks=1 (Linux default) narrows
//     this to files the attacker owns and is routinely disabled in
//     container/perf kernels, so the check cannot be delegated to it;
//   - OwnerOnlyMode applied with fchmod AFTER the open. The mode argument of
//     open(2) is ignored when the file already exists, so passing 0600 to
//     OpenFile alone leaves a file created by an older build (or by hand, or
//     by an attacker who pre-created the predictable path) world-readable
//     forever, and the contents here are captured traffic, blocked-host
//     telemetry and the audit trail (R89/R90).
//
// The fchmod runs on the already-opened descriptor, so it cannot be raced
// against a rename the way a path-based chmod can.
//
// accessFlags must express the access intent (O_RDONLY/O_WRONLY/O_RDWR) plus
// O_CREATE/O_APPEND/O_TRUNC as the caller needs — those are deliberately NOT
// imposed here, because a truncating default would destroy the audit trail
// (append-only evidence) if it were used for every consumer. Callers that need
// create-or-overwrite semantics must use CreateOwnerOnly, which validates the
// inode BEFORE shortening it.
func OpenOwnerOnly(path string, accessFlags int) (*os.File, error) {
	flags := accessFlags | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	f, err := os.OpenFile(path, flags, OwnerOnlyMode)
	if err != nil {
		return nil, err
	}
	if err := refuseSharedInode(f, path); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Chmod(OwnerOnlyMode); err != nil {
		f.Close()
		return nil, fmt.Errorf("forcing owner-only mode on %s: %w", path, err)
	}
	return f, nil
}

// refuseSharedInode rejects a file descriptor whose inode has more than one
// hard link (R93).
//
// It runs on the OPENED descriptor, so there is no stat-then-open race: the
// link count belongs to the same inode the caller is about to write through.
// A count above one means another name references this inode, and none of the
// firewall's runtime files (state, pcap rotation, audit log) is ever
// legitimately hard-linked, so the safe reading is that the name was planted.
//
// Note for callers: this check is only sound if the open did not already
// modify the file. CreateOwnerOnly therefore opens WITHOUT the destructive flag
// and shortens the file only after this returns nil.
func refuseSharedInode(f *os.File, path string) error {
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stating %s: %w", path, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read link count for %s", path)
	}
	if st.Nlink > 1 {
		return fmt.Errorf("refusing hard-linked path (nlink=%d): %s", st.Nlink, path)
	}
	return nil
}

// CreateOwnerOnly opens path for writing, creating it if needed and replacing
// its contents, and forces mode 0600 on the resulting descriptor (see
// OpenOwnerOnly).
//
// The order matters (R93): the file is opened WITHOUT O_TRUNC, the inode is
// validated by OpenOwnerOnly (which refuses a hard-linked path), and only then
// is the content shortened. Opening with O_TRUNC would destroy the target's
// contents at open(2) time — before any check could run — so the destructive
// flag would make the hard-link refusal useless.
func CreateOwnerOnly(path string) (*os.File, error) {
	f, err := OpenOwnerOnly(path, os.O_WRONLY|os.O_CREATE)
	if err != nil {
		return nil, err
	}
	if err := f.Truncate(0); err != nil {
		f.Close()
		return nil, fmt.Errorf("shortening %s: %w", path, err)
	}
	return f, nil
}
