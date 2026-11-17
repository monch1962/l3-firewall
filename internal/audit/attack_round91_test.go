// Red-team security hardening Round 91 — audit rotation failure modes.
//
// R64 named the harm exactly: a rotation that fails AFTER l.file.Close()
// "permanently destroy[s] the audit trail (every subsequent event dropped plus
// a warning-log flood per event)". It then fixed ONE trigger of that harm (the
// directory-symlink swap) by checking the directory before closing. The failure
// itself is still unhandled: any other reason the rename or the re-open fails
// leaves the Logger holding a CLOSED descriptor with l.closed == false, so
// every later Log returns "file already closed" for the life of the process and
// the evidence plane is dead — silently, apart from one slog.Warn per blocked
// packet on the NFQUEUE hot path.
//
// The rotated name is fully predictable: fmt.Sprintf("%s.%s", path,
// time.Now().UTC().Format("20060102T150405Z")) — second resolution, no
// uniquifier. An attacker with write access to the log directory (the DEFAULT
// /tmp/l3-firewall is world-writable) pre-creates a DIRECTORY at the names for
// the next few seconds; os.Rename(file, existing-directory) fails with EISDIR,
// which is the post-close failure above. 86400 empty directories covers a whole
// day of rotations.
package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const r91Canary = "R91_CANARY_MARKER"

// canaryPresent reports whether any file in dir contains the canary marker.
func canaryPresent(t *testing.T, dir string) (bool, string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading log dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if strings.Contains(string(data), r91Canary) {
			return true, p
		}
	}
	return false, ""
}

// plantRotatedNameDirs creates empty directories at the rotated names an
// imminent rotation would pick, covering the surrounding seconds so the test
// does not race the wall clock.
func plantRotatedNameDirs(t *testing.T, logPath string) {
	t.Helper()
	now := time.Now().UTC()
	for sec := -1; sec <= 5; sec++ {
		name := logPath + "." + now.Add(time.Duration(sec)*time.Second).Format("20060102T150405Z")
		if err := os.MkdirAll(name, 0o755); err != nil && !os.IsExist(err) {
			t.Fatalf("planting rotated-name directory %s: %v", name, err)
		}
	}
}

// ── R91.5: a planted directory at the rotated name must not kill the trail ──
// The attacker cannot delete or write the audit content, but can make the
// rotation rename impossible (EISDIR). Pre-R91 that permanently disabled audit
// logging: the descriptor was already closed and nothing re-opened it.
func TestAttack_AuditRotationPlantedDirectoryKillsTrail(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	l, err := NewLogger(Config{Path: logPath, MaxSizeMB: 1, MaxBackups: 2})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	plantRotatedNameDirs(t, logPath)

	// Flood past the 1MB rotation threshold (the R64 test's construction).
	reason := strings.Repeat("A", 1000)
	for i := 0; i < 1200; i++ {
		_ = l.Log(AuditEvent{Type: "packet_block", Reason: reason})
	}

	// The evidence plane must still accept events: this is the whole point.
	if err := l.Log(AuditEvent{Type: "packet_block", Reason: r91Canary}); err != nil {
		t.Fatalf("audit Log failed after a rotation blocked by a planted directory: %v "+
			"(the trail is dead for the life of the process — the descriptor was closed before the failed rename and never re-opened)", err)
	}
	ok, where := canaryPresent(t, dir)
	if !ok {
		t.Fatalf("the event logged after the failed rotation is nowhere in %s: "+
			"audit evidence was silently dropped", dir)
	}
	t.Logf("post-failure evidence landed in %s", filepath.Base(where))
}

// ── R91.6: rotation must recover even when every candidate name is taken ────
// Defense in depth for the recovery path: with the base rotated name AND every
// uniquifier already occupied, rotation genuinely cannot proceed. That must
// still leave the trail appendable (report the failure, keep the evidence).
func TestAttack_AuditRotationTotalBlockStillKeepsTrail(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	l, err := NewLogger(Config{Path: logPath, MaxSizeMB: 1, MaxBackups: 2})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	// Occupy every name nextRotatedPath may try, for the surrounding seconds.
	now := time.Now().UTC()
	for sec := -1; sec <= 5; sec++ {
		base := logPath + "." + now.Add(time.Duration(sec)*time.Second).Format("20060102T150405Z")
		for attempt := 0; attempt < maxRotatedNameAttempts; attempt++ {
			name := base
			if attempt > 0 {
				name = base + "." + itoa91(attempt)
			}
			if err := os.MkdirAll(name, 0o755); err != nil && !os.IsExist(err) {
				t.Fatalf("planting %s: %v", name, err)
			}
		}
	}

	reason := strings.Repeat("A", 1000)
	for i := 0; i < 1200; i++ {
		_ = l.Log(AuditEvent{Type: "packet_block", Reason: reason})
	}

	// Rotation is impossible, so an error is honest and expected — but the
	// canary event must still reach the trail.
	_ = l.Log(AuditEvent{Type: "packet_block", Reason: r91Canary})
	ok, _ := canaryPresent(t, dir)
	if !ok {
		t.Fatalf("audit evidence lost when rotation was impossible (every rotated name occupied): " +
			"the logger must keep appending to the live file and report the rotation failure")
	}
}

// itoa91 avoids importing strconv into the test's hot path (and avoids
// colliding with any other test helper in this package).
func itoa91(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// ── R91.7: rotated-name collision must not silently overwrite a backup ─────
// The rotated name has one-second resolution and no uniquifier, so
// os.Rename replaces an existing backup of the same second without error —
// the destroyed file is the only copy of the events that triggered that
// rotation. Low likelihood at the 100MB default window, so this pins the
// invariant rather than an attacker-reachable sequence.
func TestAttack_AuditRotatedNameCollisionOverwritesBackup(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	for attempt := 0; attempt < 5; attempt++ {
		ts := time.Now().UTC().Format("20060102T150405Z")
		taken := logPath + "." + ts
		if err := os.WriteFile(taken, []byte("PREVIOUS-BACKUP"), 0o600); err != nil {
			t.Fatalf("pre-creating rotated name: %v", err)
		}
		got := nextRotatedPath(logPath)
		if time.Now().UTC().Format("20060102T150405Z") != ts {
			// The second rolled over mid-test; retry against a fresh name.
			os.Remove(taken)
			continue
		}
		if got == taken {
			t.Fatalf("nextRotatedPath returned the already-taken name %s: "+
				"os.Rename would silently overwrite the existing audit backup", filepath.Base(got))
		}
		if _, err := os.Stat(got); err == nil {
			t.Fatalf("nextRotatedPath returned an existing path %s: rename would overwrite it", filepath.Base(got))
		}
		return
	}
	t.Skip("could not pin a single wall-clock second to test the collision")
}
