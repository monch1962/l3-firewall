package persist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── R6.9: JSON bomb in LoadState ────────────────────────────────────────
// Attacker provides a JSON file with deeply nested structure to exhaust memory.
// There is no io.LimitReader on the decoder.
func TestAttack_JSONBombInLoadState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bomb.json")

	// Craft a JSON bomb that expands to huge memory via deep nesting
	var bomb strings.Builder
	bomb.WriteString("{\"a\":")
	for i := 0; i < 10000; i++ {
		bomb.WriteString("{\"a\":")
	}
	bomb.WriteString("null")
	for i := 0; i < 10000; i++ {
		bomb.WriteString("}")
	}

	if err := os.WriteFile(path, []byte(bomb.String()), 0644); err != nil {
		t.Fatalf("write bomb file: %v", err)
	}

	// LoadState should not OOM or hang
	done := make(chan struct{})
	go func() {
		state, err := LoadState(path)
		if err == nil {
			t.Logf("LoadState parsed bomb successfully (state=%+v)", state)
		} else {
			t.Logf("LoadState correctly rejected JSON bomb: %v", err)
		}
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Error("LoadState hung on JSON bomb — needs io.LimitReader or max depth check")
	}
}

// ── R6.10: Large block stats in state file ──────────────────────────────
// Attacker provides a state file with 100K block stats entries.
func TestAttack_LargeBlockStatsInLoadState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.json")

	var sb strings.Builder
	sb.WriteString(`{"block_stats":{`)
	for i := 0; i < 100000; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`"reason_`)
		sb.WriteString(itoa(i))
		sb.WriteString(`":`)
		sb.WriteString(itoa(i))
	}
	sb.WriteString("}}")

	if err := os.WriteFile(path, []byte(sb.String()), 0644); err != nil {
		t.Fatalf("write large state file: %v", err)
	}

	done := make(chan struct{})
	go func() {
		state, err := LoadState(path)
		if err != nil {
			t.Logf("LoadState rejected large state file: %v", err)
		} else if state != nil {
			t.Logf("LoadState loaded %d entries", len(state.BlockStats))
		}
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(5 * time.Second):
		t.Error("LoadState hung on large state file — needs read limit")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	d := []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}
	r := ""
	for n > 0 {
		r = d[n%10] + r
		n /= 10
	}
	return r
}
