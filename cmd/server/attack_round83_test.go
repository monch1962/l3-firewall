// Red-team security hardening Round 83 — deployment plane.
//
// Two findings in the shipped deployment surface, neither of which is
// reachable from the Go packages the prior 82 rounds examined:
//
//	(1) deploy/entrypoint.sh queues host INPUT traffic to queue 1, but the
//	    engine registers ONLY the forward queue (eng.Run(*queueNum); the
//	    --queue-input flag is parsed and never wired — R49). A netfilter
//	    queue with no userspace listener DROPS every packet (there is no
//	    `bypass` on the rule), so the shipped container black-holes 100% of
//	    host input: the admin API published by the README's own
//	    `docker run -p 8082:8082`, /metrics, SSH and every container
//	    healthcheck. The docs say input traffic "is not firewalled", which
//	    reads as *allowed*; the measured behaviour is *dropped*.
//
//	(2) config/params.json ships into the runtime image and the README
//	    documents it as "Default parameters", but nothing in the binary reads
//	    it — and its values CONTRADICT the enforced policy on three
//	    security-relevant knobs (fragment attack detection on vs off, GeoIP
//	    blocking off vs on, IPv4-only allowlist vs the family-complete
//	    wildcard R79.1 fixed). An operator templating the only config file in
//	    the image changes nothing; an auditor reads the wrong control state;
//	    a maintainer who wires it reintroduces the R79.1 IPv6 blackhole.
//
// Both tests are pinned here (cmd/server owns the deployment surface) so a
// future change cannot silently re-introduce either.
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	entrypointPath = "../../deploy/entrypoint.sh"
	mainSourcePath = "./main.go"
	dockerfilePath = "../../Dockerfile"
	paramsJSONPath = "../../config/params.json"
	readmePath     = "../../README.md"
)

// defaultForwardQueue parses the --queue flag default out of main.go so the
// test tracks the binary instead of hardcoding 0 twice.
func defaultForwardQueue(t *testing.T) int {
	t.Helper()
	src, err := os.ReadFile(mainSourcePath)
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}
	m := regexp.MustCompile(`flag\.Uint\("queue",\s*(\d+),`).FindSubmatch(src)
	if m == nil {
		t.Fatal("could not find the --queue flag declaration in main.go")
	}
	n, err := strconv.Atoi(string(m[1]))
	if err != nil {
		t.Fatalf("parsing --queue default: %v", err)
	}
	return n
}

// queueRule is one nftables queue statement found in the entrypoint script.
type queueRule struct {
	Hook  string
	Queue int
}

// entrypointQueueRules returns the (hook, queue-number) pairs the shipped
// entrypoint installs, in file order.
func entrypointQueueRules(t *testing.T) []queueRule {
	t.Helper()
	data, err := os.ReadFile(entrypointPath)
	if err != nil {
		t.Fatalf("reading %s: %v", entrypointPath, err)
	}

	var out []queueRule
	// Walk the file keeping the most recent `hook <name>` seen, so each
	// `queue num N` is attributed to the chain it was installed on.
	hookRe := regexp.MustCompile(`hook\s+(\w+)`)
	queueRe := regexp.MustCompile(`queue\s+num\s+(\d+)`)
	hook := ""
	for _, line := range strings.Split(string(data), "\n") {
		// Ignore comments: the R83 note explains the removed input rule and
		// quotes its text, which must not be mistaken for a live rule.
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if hm := hookRe.FindStringSubmatch(line); hm != nil {
			hook = hm[1]
		}
		if qm := queueRe.FindStringSubmatch(line); qm != nil {
			n, err := strconv.Atoi(qm[1])
			if err != nil {
				t.Fatalf("parsing queue number in %q: %v", line, err)
			}
			out = append(out, queueRule{Hook: hook, Queue: n})
		}
	}
	return out
}

// ── R83.1: the entrypoint must only queue queues the engine serves ───────
func TestAttack_EntrypointQueuesOnlyServedQueues(t *testing.T) {
	forward := defaultForwardQueue(t)
	rules := entrypointQueueRules(t)

	if len(rules) == 0 {
		t.Fatal("entrypoint installs no queue rule: forwarded traffic would never reach the firewall (fail-open)")
	}

	// Exactly one FORWARD queue rule, on the queue the engine actually
	// serves — otherwise the firewall never sees forwarded traffic.
	var forwardRules int
	for _, r := range rules {
		if r.Hook == "forward" {
			forwardRules++
			if r.Queue != forward {
				t.Errorf("entrypoint queues FORWARD traffic to queue %d, but the engine serves queue %d (--queue default): forwarded traffic is never inspected", r.Queue, forward)
			}
		}
	}
	if forwardRules != 1 {
		t.Errorf("expected exactly 1 forward queue rule, found %d", forwardRules)
	}

	// Every OTHER queue rule must name a queue the engine serves. The engine
	// registers only the forward queue (`eng.Run(uint16(*queueNum))`); the
	// --queue-input flag is parsed and never wired (R49), so a queue rule on
	// any other chain black-holes that traffic: netfilter DROPS packets
	// queued to a queue with no userspace listener.
	for _, r := range rules {
		if r.Hook == "forward" {
			continue
		}
		t.Errorf("entrypoint queues %s traffic to queue %d, but the engine serves ONLY queue %d: "+
			"a queue with no listener drops every %s packet (admin API %s:8082, /metrics, SSH, healthchecks all black-holed)",
			r.Hook, r.Queue, forward, r.Hook, "host input")
	}
}

// ── R83.2: behavioural proof that an unserved queue drops host traffic ───
//
// Replays the entrypoint's own nftables commands (everything except the final
// `exec` of the firewall binary) inside a throwaway user+network namespace,
// then sends one UDP datagram to a local socket. A queue with no listener
// drops it; a ruleset that only queues what the engine serves delivers it.
//
// The probe runs twice per execution — once with the entrypoint's rules, once
// after `nft flush ruleset` — so a harness problem (no loopback, missing nft)
// fails as a "control" assertion rather than masquerading as a security
// result.
func TestAttack_UnservedQueueDropsHostTraffic(t *testing.T) {
	for _, tool := range []string{"unshare", "nft", "python3", "ip"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available: %v (unprivileged netns test)", tool, err)
		}
	}
	if err := exec.Command("unshare", "-rn", "sh", "-c", "ip link set lo up").Run(); err != nil {
		t.Skipf("unprivileged user+net namespace unavailable: %v", err)
	}

	data, err := os.ReadFile(entrypointPath)
	if err != nil {
		t.Fatalf("reading %s: %v", entrypointPath, err)
	}
	var body []string
	for _, line := range strings.Split(string(data), "\n") {
		// Skip the final exec of the firewall binary: this test exercises the
		// nftables configuration only.
		if strings.HasPrefix(strings.TrimSpace(line), "exec ") {
			continue
		}
		body = append(body, line)
	}

	probeDir := t.TempDir()
	probePath := filepath.Join(probeDir, "udp_probe.py")
	probe := `import socket, sys
r = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
r.bind(("127.0.0.1", 0))
r.settimeout(1.5)
port = r.getsockname()[1]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"probe", ("127.0.0.1", port))
try:
    r.recvfrom(64)
    print("DELIVERED")
except Exception:
    print("DROPPED")
`
	if err := os.WriteFile(probePath, []byte(probe), 0o644); err != nil {
		t.Fatalf("writing probe: %v", err)
	}

	script := "ip link set lo up 2>/dev/null || true\n" +
		strings.Join(body, "\n") + "\n" +
		"echo -n 'WITH-ENTRYPOINT-RULES: '; python3 " + probePath + "\n" +
		"nft flush ruleset 2>/dev/null || true\n" +
		"echo -n 'CONTROL-NO-RULES: '; python3 " + probePath + "\n"

	cmd := exec.Command("unshare", "-rn", "sh", "-c", script)
	cmd.WaitDelay = 10 * time.Second
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("replaying the entrypoint in a netns failed: %v\n%s", err, out)
	}
	text := string(out)
	if !strings.Contains(text, "CONTROL-NO-RULES: DELIVERED") {
		t.Fatalf("harness control failed — a packet to loopback was not delivered even with an empty ruleset, so this test cannot judge the entrypoint:\n%s", text)
	}
	if !strings.Contains(text, "WITH-ENTRYPOINT-RULES: DELIVERED") {
		t.Errorf("the shipped entrypoint drops host INPUT traffic (a UDP packet to a local socket never arrives):\n%s\n"+
			"a netfilter queue with no userspace listener drops everything, and the engine registers only the forward queue (--queue-input is unwired, R49) — the admin API, /metrics, SSH and container healthchecks are all input traffic", text)
	}
}

// ── R83.3: no unread configuration artifact may ship ────────────────────
//
// config/params.json was copied into the runtime image and documented in the
// README as "Default parameters", but no Go code reads it. Worse, its values
// disagree with the enforced policy: enable_fragment_attack_detection=true
// (policy: enable_fragment := false), enable_geo_ip_blocking=false (policy:
// blocked_src_countries := {"KP"}), allowed_subnets=["0.0.0.0/0"] (policy:
// {"0.0.0.0/0", "::/0"} — the R79.1 family-complete fix). A file that looks
// authoritative, changes nothing, and misstates the control state is worse
// than no file: it misleads operators and auditors, and anyone who "fixes"
// the drift by wiring it would reintroduce the IPv6 blackhole.
func TestAttack_NoUnreadConfigArtifact(t *testing.T) {
	if _, err := os.Stat(paramsJSONPath); err == nil {
		t.Errorf("%s exists but is read by no code: it is documented as configuration and shipped in the image while changing nothing (its values also contradict opa-policies/l3.rego — see the R83 finding)", paramsJSONPath)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat %s: %v", paramsJSONPath, err)
	}

	if data, err := os.ReadFile(dockerfilePath); err == nil {
		if strings.Contains(string(data), "config/params.json") {
			t.Error("Dockerfile still copies config/params.json into the runtime image: the binary never reads it")
		}
	} else {
		t.Fatalf("reading Dockerfile: %v", err)
	}

	// The README must not advertise an inert file as configuration. A
	// HISTORICAL mention (the R83 narrative, which quotes what the file used
	// to claim) is fine and must remain, so this check targets the shapes
	// that actually PRESENT the file as configuration: a directory-tree
	// entry (`config/params.json   # ...`) or a `params.json | Default
	// parameters` table row. Matching bare prose would flag the very
	// explanation of the fix.
	if data, err := os.ReadFile(readmePath); err == nil {
		readme := string(data)
		bt := "`"
		advertised := regexp.MustCompile(
			`^[\s│├└─|+` + bt + `\-]*` + bt + `?config/params\.json` + bt + `?\s*(#|\||$)` + `|` +
				`^\s*\|?\s*` + bt + `?params\.json` + bt + `?\s*\|\s*Default parameters`)
		for _, line := range strings.Split(readme, "\n") {
			if advertised.MatchString(line) {
				t.Errorf("README still advertises params.json as configuration (%q): configuration lives in opa-policies/l3.rego", strings.TrimSpace(line))
			}
		}
		if strings.Contains(readme, "params.json") && !strings.Contains(readme, "opa-policies/l3.rego") {
			t.Error("README mentions params.json without naming opa-policies/l3.rego as the authoritative configuration source")
		}
	} else {
		t.Fatalf("reading README: %v", err)
	}
}

// ── R83.4: the served-queue contract must stay explicit ────────────────
//
// Guards the other direction of R83.1: if --queue-input is ever wired, this
// test's static analysis must be updated to count the input queue as served —
// and until then the flag must remain visibly unwired (a startup warning).
func TestAttack_InputQueueWiringIsExplicit(t *testing.T) {
	src, err := os.ReadFile(mainSourcePath)
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}
	code := string(src)

	wired := regexp.MustCompile(`eng\.Run\([^)]*queueNumInput`).MatchString(code) ||
		regexp.MustCompile(`Run\([^)]*queueNumInput`).MatchString(code)
	if wired {
		t.Fatalf("--queue-input is now wired into eng.Run; update R83.1's served-queue analysis (the entrypoint may then queue input traffic)")
	}
	if !strings.Contains(code, "NOT enforced") {
		t.Error("--queue-input is not wired into the engine and the startup warning that makes that dropped control observable is gone (R49/R40.4)")
	}
	if !strings.Contains(code, "queue-input") {
		t.Error("--queue-input flag disappeared unexpectedly")
	}
}
