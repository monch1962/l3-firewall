package persist

import (
	"os"
	"path/filepath"
	"testing"
)

// ── R89.5: the state file is world-readable (0666 create) ───────────────
//
// SaveState opens the temp file with mode 0666 (0666 & ~umask = 0644 in every
// ordinary deployment), then renames it into place — so the persisted
// EngineState is readable by every local user.
//
// The contents are not decorative: block_stats keys are per-reason strings
// that embed the offenders' source addresses and ports ("per-IP rate limit
// exceeded: …", "ARP spoofing detected: IP … changed from …"), and the
// adjacent pcap capture (R89.4) is worse. Together they give an unprivileged
// local reader a live picture of who the firewall is blocking — and the
// state file is re-written every 60 s, so the picture is always current.
//
// Nothing outside the firewall's UID needs to read this file, so the mode
// must be owner-only. (The symlink/FIFO hardening on this exact open —
// R42/R45/R55 — already assumes an attacker with directory write access;
// world-read needs no write access at all.)
func TestAttack_StateFileWorldReadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	state := &EngineState{BlockStats: map[string]int64{
		"per-IP rate limit exceeded for source 203.0.113.9": 41,
		"MAC not in allowlist: aa:bb:cc:dd:ee:ff":           7,
	}}
	if err := SaveState(path, state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("state file %s has mode %04o — blocked-host telemetry is readable outside the firewall's UID",
			path, perm)
	}
}

// ── R89.5b: SaveState must not weaken an existing file's mode ───────────
// The rename replaces the inode, so the mode comes from the temp file every
// time. An operator who hardened the file by hand (chmod 0600) must not have
// it silently restored to 0644 on the next 60-second tick.
func TestAttack_StateSaveKeepsOwnerOnlyMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := SaveState(path, &EngineState{BlockStats: map[string]int64{"x": 1}}); err != nil {
		t.Fatalf("initial SaveState: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := SaveState(path, &EngineState{BlockStats: map[string]int64{"x": 2}}); err != nil {
		t.Fatalf("second SaveState: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("state file mode regressed to %04o after a save — the hardened mode is not preserved", perm)
	}
}
