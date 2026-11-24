// Red-team security hardening Round 97 — the etcd policy plane's transport.
//
// The etcd syncer carries the policy that governs EVERY packet decision, and
// `syncer.New` handed clientv3 nothing but `Endpoints` and `DialTimeout`:
//
//   - no `TLS`, so the channel that delivers the enforced policy is plaintext
//     and unauthenticated. Any host on the path (or a compromised/malicious
//     etcd, the R51/R52 threat model) can rewrite the policy and the
//     deny-override firewall then permits everything. R87 fixed exactly this
//     for the admin control plane (`--admin-tls-cert`/`--admin-tls-key`) and
//     left the OTHER control-plane transport untouched.
//   - no `Username`/`Password`, and clientv3 never reads userinfo out of an
//     endpoint URL (verified: no Userinfo reference anywhere in the package,
//     so `--etcd-endpoints https://alice:<secret>@etcd-0:2379` constructs a
//     client with `Username == ""`). R88 classified the endpoint as a
//     URL-shaped credential and redacted it in the logs, so the operator is
//     told it is a secret while the process never presents it: etcd auth is
//     silently off. The raw credential also reaches clientv3's OWN logger
//     (`"target":"etcd-endpoints://0x…/alice:<secret>@host:2379"`), which no
//     caller-side redaction can reach — so the fix must strip it before the
//     client ever sees it.
//   - the TLS/endpoint pairing is unvalidated, and clientv3's
//     `endpoint.RequiresCredentials` returns CredsDrop for an `http://`
//     endpoint: a client built with a `*tls.Config` and `http://` endpoints
//     connects in CLEARTEXT with no error (measured against a plain TCP
//     listener: the server saw an HTTP/1.1 preface, i.e. no TLS handshake).
//     An operator who sets the TLS flags but leaves the shipped `http://`
//     endpoint keeps a plaintext policy channel and believes otherwise — the
//     R83/R90 "a control that is not what the deployment says it is" class.
package syncer

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// r97Sink is a slog.Handler that records message + attribute text so a test
// can assert what actually reached the log stream (the R87 alert pattern; the
// name differs because this is package syncer).
type r97Sink struct {
	mu    sync.Mutex
	lines []string
}

func (h *r97Sink) Enabled(context.Context, slog.Level) bool { return true }

func (h *r97Sink) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		b.WriteString(" ")
		b.WriteString(a.Key)
		b.WriteString("=")
		b.WriteString(a.Value.String())
		return true
	})
	h.mu.Lock()
	h.lines = append(h.lines, b.String())
	h.mu.Unlock()
	return nil
}

func (h *r97Sink) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *r97Sink) WithGroup(string) slog.Handler      { return h }

func (h *r97Sink) all() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.lines...)
}

func installR97Sink(t *testing.T) *r97Sink {
	t.Helper()
	s := &r97Sink{}
	prev := slog.Default()
	slog.SetDefault(slog.New(s))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return s
}

func mustNewForTest(t *testing.T, cfg Config) *Syncer {
	t.Helper()
	s, err := New(cfg, func(string) error { return nil })
	if err != nil {
		t.Fatalf("New(%v): %v", cfg.Endpoints, err)
	}
	if s == nil {
		t.Fatalf("New(%v) returned a nil syncer", cfg.Endpoints)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// ── R97.1: the endpoint credential must be USED for auth and REMOVED from
// the dial target ────────────────────────────────────────────────────────────
// Attacker model: anyone who can read the log stream. Two harms, one cause —
// the credential is parsed by nobody. (a) etcd authentication is silently off
// because clientv3 only authenticates from Config.Username/Password; (b) the
// raw credential is echoed by clientv3's own retry logger
// (`target: etcd-endpoints://0x…/alice:<secret>@host:2379`), so no caller-side
// redaction can scrub it.
func TestAttack_EtcdEndpointCredentialIsUsedAndStripped(t *testing.T) {
	const secret = "ROUND97ETCDSECRET"

	// The resolved client config is what both the constructed client and the
	// R97 recovery connect path hand to clientv3, so assert on it directly.
	cfg := Config{
		Endpoints: []string{"https://alice:" + secret + "@etcd-0.internal:2379"},
		Timeout:   time.Second,
	}
	cc, err := buildClientConfig(cfg)
	if err != nil {
		t.Fatalf("buildClientConfig: %v", err)
	}
	if cc.Username != "alice" {
		t.Errorf("clientv3 Username = %q, want %q (userinfo in --etcd-endpoints is "+
			"ignored by clientv3, so etcd auth would be silently disabled)", cc.Username, "alice")
	}
	if cc.Password != secret {
		t.Errorf("clientv3 Password not taken from the endpoint URL (len=%d)", len(cc.Password))
	}
	for _, ep := range cc.Endpoints {
		if strings.Contains(ep, "@") || strings.Contains(ep, secret) {
			t.Errorf("endpoint handed to clientv3 still carries the credential: %q — "+
				"clientv3 logs its dial target verbatim, so the credential reaches the log stream", ep)
		}
	}
	if got := cc.Endpoints[0]; got != "https://etcd-0.internal:2379" {
		t.Errorf("stripped endpoint = %q, want %q", got, "https://etcd-0.internal:2379")
	}

	// The same resolved config must be the one the syncer keeps for its
	// recovery connect path (New tolerates an unreachable cluster, so the live
	// client may not exist yet — but the credential must never be re-derived
	// from the raw flag value).
	s := mustNewForTest(t, cfg)
	if s.clientCfg.Username != "alice" || s.clientCfg.Password != secret {
		t.Error("syncer's stored client config lost the endpoint credential")
	}
	if strings.Contains(strings.Join(s.clientCfg.Endpoints, ","), secret) {
		t.Error("syncer's stored client config still contains the credential in an endpoint")
	}
}

// ── R97.6: an etcd outage at STARTUP must not cost the process its policy
// plane ────────────────────────────────────────────────────────────────────
// Setting etcd credentials makes clientv3 authenticate synchronously inside
// clientv3.New (getToken), so a cluster that is unreachable when the firewall
// boots fails construction after DialTimeout. Returning that error would make
// main() log "etcd syncer not available" and never build a syncer at all — the
// policy plane would be dead for the lifetime of the process, where the
// pre-R97 lazily-dialled client recovered via Start's watch reconnect (R65).
func TestAttack_UnreachableEtcdAtStartupKeepsPolicyPlane(t *testing.T) {
	sink := installR97Sink(t)
	// .invalid is reserved (RFC 6761) and never resolves: a guaranteed failure.
	s, err := New(Config{
		Endpoints: []string{"https://alice:pw@etcd.invalid:2379"},
		Timeout:   50 * time.Millisecond,
	}, func(string) error { return nil })
	if err != nil {
		t.Fatalf("New returned an error for a transient unreachable cluster: %v "+
			"(the syncer must retry in the background, not disappear)", err)
	}
	if s == nil {
		t.Fatal("New returned a nil syncer for a transient unreachable cluster")
	}
	// Start must not panic and must leave the recovery path armed; Close must
	// stop it.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	if s.etcdClientOrNil() != nil {
		t.Error("a client that could not be constructed was installed anyway")
	}
	_ = s.Close()

	var warned bool
	for _, line := range sink.all() {
		if strings.Contains(line, "not ready at startup") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("no operator-visible warning that the policy plane is waiting for etcd; log: %v", sink.all())
	}
}

// ── R97.2: two endpoints carrying DIFFERENT credentials must be refused ─────
// Silently picking one is the R97.1 defect with a twist: the operator cannot
// tell which identity the firewall authenticates as, and a typo'd endpoint
// silently becomes the credential source.
func TestAttack_ConflictingEtcdCredentialsRejected(t *testing.T) {
	_, err := New(Config{
		Endpoints: []string{
			"https://alice:pw1@etcd-0.internal:2379",
			"https://bob:pw2@etcd-1.internal:2379",
		},
		Timeout: time.Second,
	}, func(string) error { return nil })
	if err == nil {
		t.Fatal("two endpoints with different credentials were accepted; " +
			"the syncer cannot know which identity to authenticate as")
	}
}

// ── R97.3: the TLS config must reach clientv3 ──────────────────────────────
// Without it the policy channel is plaintext: an on-path attacker rewrites the
// enforced Rego and the deny-override firewall permits everything.
func TestAttack_EtcdTLSConfigIsWiredIntoClient(t *testing.T) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	cc, err := buildClientConfig(Config{
		Endpoints: []string{"https://etcd-0.internal:2379"},
		Timeout:   time.Second,
		TLS:       tlsCfg,
	})
	if err != nil {
		t.Fatalf("buildClientConfig: %v", err)
	}
	if cc.TLS != tlsCfg {
		t.Error("clientv3.Config.TLS is nil: the policy channel would be plaintext " +
			"while the operator believes TLS is on")
	}
	if cc.DialTimeout != time.Second {
		t.Errorf("DialTimeout = %v, want 1s", cc.DialTimeout)
	}
}

// ── R97.4: TLS configured + a plaintext endpoint must FAIL CLOSED ──────────
// clientv3's endpoint.RequiresCredentials returns CredsDrop for `http://`, so
// a tls.Config plus `http://etcd:2379` connects in cleartext with NO error
// (measured: the listener saw an HTTP/1.1 preface). The shipped examples all
// use `http://`, so this is the default path for anyone who adds TLS flags —
// the R83/R90 silently-inert-control class.
func TestAttack_TLSConfigWithPlaintextEndpointIsRefused(t *testing.T) {
	cases := []struct {
		name string
		eps  []string
	}{
		{"http", []string{"http://etcd-0.internal:2379"}},
		{"mixed", []string{"https://etcd-0.internal:2379", "http://etcd-1.internal:2379"}},
		{"schemeless", []string{"etcd-0.internal:2379"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := buildClientConfig(Config{
				Endpoints: tc.eps,
				Timeout:   time.Second,
				TLS:       &tls.Config{MinVersion: tls.VersionTLS12},
			}); err == nil {
				t.Errorf("TLS configured with endpoint(s) %v was accepted; clientv3 "+
					"DROPS the credentials for a non-https endpoint, so the policy "+
					"channel stays plaintext with no error", tc.eps)
			}
		})
	}
}

// ── R97.5: a plaintext policy channel must be audible ──────────────────────
// The default deployment fetches policy over plain HTTP with no credential.
// That is attacker-writable, and nothing in the log says so (R88.3's webhook
// posture applied to the policy plane). Loopback is exempt: those bytes never
// leave the host, so a warning there only trains the operator to ignore it.
func TestAttack_PlaintextEtcdChannelWarns(t *testing.T) {
	sink := installR97Sink(t)
	mustNewForTest(t, Config{Endpoints: []string{"http://etcd-0.internal:2379"}, Timeout: time.Second})

	var warned bool
	for _, line := range sink.all() {
		if strings.Contains(line, "plaintext") || strings.Contains(line, "PLAINTEXT") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("no plaintext warning for a routable http:// etcd endpoint; log lines: %v", sink.all())
	}
}

// ── R97.7: a password with NO username must be refused ─────────────────────
// The mirror image of the half-credential case New already refuses. etcd's
// auth needs BOTH fields; clientv3 authenticates only when Username and
// Password are both non-empty, so `https://:<secret>@etcd-0:2379` (a typo, or
// a templated `${ETCD_USER}` that expanded to nothing) builds a client with
// Username == "" — anonymous — while the operator's credential silently does
// nothing. Nothing is logged, because from clientv3's point of view no
// credential was ever configured.
func TestAttack_EtcdPasswordWithoutUsernameRefused(t *testing.T) {
	const secret = "ROUND97PASSWORDONLYSECRET"
	cc, err := buildClientConfig(Config{
		Endpoints: []string{"https://:" + secret + "@etcd-0.internal:2379"},
		Timeout:   time.Second,
	})
	if err == nil {
		t.Errorf("a password with no username was accepted (Username=%q, Password set: %v): "+
			"clientv3 authenticates only when BOTH fields are set, so etcd auth would be "+
			"silently disabled while a credential is configured", cc.Username, cc.Password != "")
		return
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("the refusal renders the credential: %v", err)
	}
}

// ── R97.8: an endpoint whose HOST is empty must be refused ─────────────────
// `--etcd-endpoints https://${ETCD_USER}:${ETCD_PW}@${ETCD_HOST}:2379` with a
// missing host expands to `https://:pw@` — measured: url.Parse keeps userinfo,
// stripping it yields the bare string `https:` (scheme, no host). It is
// non-empty, so it is accepted, keeps the https:// prefix so it is never
// warned about as plaintext, and the client can never dial it: the policy
// channel is dead for the lifetime of the process while main logs "etcd
// syncer started". A phantom endpoint is a silent degradation, not a config.
func TestAttack_EtcdEndpointWithEmptyHostRefused(t *testing.T) {
	for _, ep := range []string{
		"https://alice:pw@",
		"http://",
		"https:///etcd-0:2379",
	} {
		if _, err := buildClientConfig(Config{Endpoints: []string{ep}, Timeout: time.Second}); err == nil {
			t.Errorf("endpoint %q accepted with no host: the client can never dial it, so the "+
				"policy plane is silently dead while the log reports the syncer started", ep)
		}
	}
	// A unix socket legitimately has no host — it must keep working.
	if _, err := buildClientConfig(Config{Endpoints: []string{"unix:///run/etcd.sock"}, Timeout: time.Second}); err != nil {
		t.Errorf("unix socket endpoint rejected: %v", err)
	}
}

// ── R97.9: an endpoint list with nothing usable must start NOTHING ─────────
// `--etcd-endpoints ","` or `" "` reaches New as a non-empty slice of blanks.
// Every blank is skipped, the resolved endpoint list is empty, and
// clientv3.New fails with "no available endpoints" — so New installs no
// client, and Start's recovery loop then retries that permanently invalid
// config every 5 s for the life of the process, warning once per 30 s, while
// main logs "etcd syncer started". R93 fixed exactly this shape for
// --threat-intel-url (an all-blank list must start no goroutine).
func TestAttack_AllBlankEtcdEndpointsStartNothing(t *testing.T) {
	for _, eps := range [][]string{
		{""},
		{"", "  "},
		{" ", "\t"},
	} {
		s, err := New(Config{Endpoints: eps, Timeout: time.Second}, func(string) error { return nil })
		if err != nil {
			t.Fatalf("New(%q): %v", eps, err)
		}
		if s != nil {
			_ = s.Close()
			t.Errorf("New(%q) returned a syncer with no usable endpoint: clientv3.New fails for "+
				"an empty list, so the recovery loop retries a permanently invalid config "+
				"forever while main reports the sync channel as started", eps)
		}
	}
}

// ── R97.10: a unix socket is not a plaintext-on-the-wire channel ───────────
// `unix://` endpoints never put bytes on a network, so a PLAINTEXT warning is
// a false positive — and a warning that fires on a safe config is exactly what
// trains an operator to ignore the real one (R88.3's posture).
func TestAttack_UnixSocketPolicyChannelDoesNotWarn(t *testing.T) {
	sink := installR97Sink(t)
	mustNewForTest(t, Config{Endpoints: []string{"unix:///run/etcd.sock"}, Timeout: time.Second})
	for _, line := range sink.all() {
		if strings.Contains(line, "PLAINTEXT") {
			t.Errorf("false plaintext warning for a unix-socket endpoint: %q", line)
		}
	}
}

// ── R97.17: a CONFIG error must be distinguishable from an unreachable cluster ──
// The caller has to treat these two very differently: an unreachable cluster
// must not stop the firewall (it reconnects in the background — R97.6), while a
// configuration that can never work must not leave a long-running process whose
// policy plane is silently dead. New marks the first with ErrConfig and the
// second not at all.
func TestAttack_ConfigErrorsAreMarkedAndConnectivityIsNot(t *testing.T) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	_, err := New(Config{
		Endpoints: []string{"http://etcd-0.internal:2379"},
		Timeout:   time.Second,
		TLS:       tlsCfg,
	}, func(string) error { return nil })
	if err == nil {
		t.Fatal("TLS + http:// endpoint was accepted")
	}
	if !errors.Is(err, ErrConfig) {
		t.Errorf("TLS/endpoint mismatch error is not marked ErrConfig: %v — a caller cannot "+
			"tell it apart from an unreachable cluster and will only warn, then run a "+
			"firewall whose policy plane is silently dead", err)
	}

	// An unreachable cluster is NOT a config error: New must succeed (nil
	// error) and let Start's connect path retry.
	s, err := New(Config{
		Endpoints: []string{"https://etcd.invalid:2379"},
		Timeout:   50 * time.Millisecond,
	}, func(string) error { return nil })
	if err != nil {
		t.Fatalf("an unreachable cluster was reported as an error (%v); the firewall would "+
			"lose its policy plane for the lifetime of the process", err)
	}
	if s == nil {
		t.Fatal("New returned no syncer for a transiently unreachable cluster")
	}
	if errors.Is(err, ErrConfig) {
		t.Error("unreachable cluster marked as a config error")
	}
	_ = s.Close()
}

func TestAttack_LoopbackAndTLSChannelsDoNotWarn(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"loopback-v4", Config{Endpoints: []string{"http://127.0.0.1:2379"}, Timeout: time.Second}},
		{"loopback-v6", Config{Endpoints: []string{"http://[::1]:2379"}, Timeout: time.Second}},
		{"localhost", Config{Endpoints: []string{"http://localhost:2379"}, Timeout: time.Second}},
		{"tls", Config{Endpoints: []string{"https://etcd-0.internal:2379"}, Timeout: time.Second}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink := installR97Sink(t)
			mustNewForTest(t, tc.cfg)
			for _, line := range sink.all() {
				if strings.Contains(line, "plaintext") {
					t.Errorf("false plaintext warning for %v: %q", tc.cfg.Endpoints, line)
				}
			}
		})
	}
}
