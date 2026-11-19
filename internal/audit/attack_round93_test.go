package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// ── R93.1 (audit integration): hardlink write-through on the audit trail ────
//
// The audit log is the firewall's primary evidence store and its default path
// (/tmp/l3-firewall/audit.log) sits under a world-traversable directory. R43
// hardened the append open against a symlink (O_NOFOLLOW) and R15 against a
// FIFO; R90 forced mode 0600 for confidentiality. A hard link is the remaining
// shape: the append lands inside whatever inode the attacker linked to the log
// path, as the firewall's UID — its own state file or pcap evidence at
// minimum, any co-tenant file of the same UID on a shared volume too.
func TestAttack_AuditLogHardLinkInjectsIntoVictim(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.log")
	const secret = "ANOTHER SERVICE'S LOG LINE\n"
	if err := os.WriteFile(victim, []byte(secret), 0o600); err != nil {
		t.Fatalf("seeding victim: %v", err)
	}
	logPath := filepath.Join(dir, "audit.log")
	if err := os.Link(victim, logPath); err != nil {
		t.Fatalf("creating hard link at the audit log path: %v", err)
	}

	lg, err := NewLogger(Config{Path: logPath})
	if err == nil {
		_ = lg.Log(AuditEvent{Type: "packet_block", SrcIP: "10.0.0.1", DstIP: "10.0.0.2"})
		lg.Close()
		t.Error("NewLogger accepted a hard-linked audit log path — audit appends write through the link")
	}

	got, rerr := os.ReadFile(victim)
	if rerr != nil {
		t.Fatalf("victim unreadable after attack: %v", rerr)
	}
	if string(got) != secret {
		t.Errorf("audit append wrote through a hard link into %s: got %q, want %q", victim, string(got), secret)
	}
}
