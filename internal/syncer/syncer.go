// Package syncer synchronizes firewall policy from etcd.
package syncer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/monch1962/l3-firewall/internal/netguard"
	"github.com/monch1962/l3-firewall/internal/redact"
	"github.com/monch1962/l3-firewall/internal/securepath"
)

// maxPolicySize prevents memory exhaustion from an oversized etcd policy value.
// A firewall policy is typically a few KB; 10MB is an extreme upper bound.
const maxPolicySize = 10 * 1024 * 1024

// maxWatchEventsPerResponse bounds the number of events processed from a
// single WatchResponse. R13/R54 bound the per-event VALUE size but not the
// event COUNT: a single response within clientv3's 16MB receive limit can
// carry ~400k minimal events, each triggering a full policy recompile via
// onUpdate — unbounded CPU burn from one wire response (R61 — the R58
// bound-one-dimension rule applied to the watch path). An oversized
// response is collapsed to its LAST event before processing: every event
// on a single-key watch (no WithPrevKV) carries the FULL current value, so
// the last event IS the latest policy state.
const maxWatchEventsPerResponse = 10000

// etcdClient is the minimal client surface the syncer needs. Extracted as
// an interface so tests can inject a stub whose Get stalls — proving the
// per-call timeout prevents the startup hang (R46). *clientv3.Client
// satisfies it implicitly.
type etcdClient interface {
	Get(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error)
	Watch(ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan
	Close() error
}

// Syncer watches an etcd key for policy updates and triggers hot-reload.
type Syncer struct {
	// clientMu guards client. The field is written once on the normal path
	// (New) and, on the R97 recovery path, by the connect goroutine when the
	// client could not be constructed at startup; Close reads it.
	clientMu  sync.RWMutex
	client    etcdClient
	clientCfg clientv3.Config // resolved config, reused by the recovery connect
	key       string
	timeout   time.Duration      // per-operation deadline for Get (R46)
	onUpdate  func(string) error // called with new policy content
	stopCh    chan struct{}
	closeOnce sync.Once // ensures Close() is idempotent
	startOnce sync.Once // ensures Start() is idempotent
	closed    atomic.Bool

	// policyMu + lastPolicy dedupe policy content. etcd emits a modify
	// event for EVERY Put — a same-value Put is a new revision and still
	// produces an event — and every event drives onUpdate (a full Rego
	// recompile via opaEval.Load, ~70ms per 2MB policy, measured R61). An
	// attacker replaying identical policy bytes (malicious/compromised
	// etcd or MITM on the plaintext connection, the R51/R52 threat model)
	// turns the watch loop into a sustained CPU/allocation-churn engine.
	// lastPolicy records the LAST PROCESSED content (applied or rejected),
	// so an identical replay never reloads twice (R61 — the R6 "no rate
	// limiting" documentation finding, finally fixed).
	policyMu   sync.Mutex
	lastPolicy string
}

// Config controls the etcd syncer.
type Config struct {
	Endpoints []string // etcd endpoints
	Key       string   // etcd key to watch for policy
	Timeout   time.Duration
	// TLS configures the transport to the etcd cluster (R97). nil = the
	// scheme decides: https endpoints get TLS with the system root pool, and
	// http endpoints are plaintext (warned about when the host is routable).
	// When set, every endpoint MUST use https:// (or unixs://) — clientv3's
	// endpoint.RequiresCredentials returns CredsDrop for http://, so a TLS
	// config paired with a plaintext endpoint silently connects in cleartext.
	TLS *tls.Config
}

// ErrConfig marks an error in the operator's etcd configuration — conflicting
// endpoint credentials, a TLS config paired with a plaintext endpoint, an
// endpoint that cannot be dialled — as opposed to an unreachable cluster,
// which the syncer retries in the background for the life of the process.
//
// The distinction is load-bearing for the caller (R97): a cluster that is down
// at boot must NOT stop the firewall (R97.6), while a configuration that can
// never work must not leave a long-running process whose policy plane is
// silently dead because main logged one warning and carried on.
var ErrConfig = errors.New("etcd configuration error")

// errNoUsableEndpoints reports a configured endpoint list in which every entry
// is blank ("," or " "). New turns it into "no syncer", not an error: the
// operator did configure something, so the caller must see a warning, but an
// armed retry loop against a config that can never dial is worse than none.
var errNoUsableEndpoints = fmt.Errorf("no usable etcd endpoint configured (every entry is blank)")

// buildClientConfig is the single place where the operator's endpoint list is
// turned into a clientv3.Config (R97).
//
// It exists because the raw flag value is NOT a safe client config, in three
// ways that each leave the policy channel weaker than the deployment says:
//
//   - clientv3 never reads userinfo out of an endpoint URL (there is no
//     Userinfo reference anywhere in the package), so
//     `--etcd-endpoints https://alice:<secret>@etcd-0:2379` builds a client
//     with Username == "" — etcd auth silently off — while the raw URL
//     (credential included) becomes the gRPC dial target that clientv3's own
//     retry logger prints verbatim. The credential is therefore BOTH unused
//     and published. This function splits it into Config.Username/Password
//     and strips it from the endpoint, so the credential is used for auth and
//     never reaches a log line. Two endpoints with DIFFERENT credentials are
//     refused rather than resolved arbitrarily.
//   - clientv3's endpoint.RequiresCredentials returns CredsDrop for `http://`,
//     so a Config.TLS paired with a plaintext endpoint connects in CLEARTEXT
//     with no error (measured: the peer sees an HTTP/1.1 preface). When TLS is
//     configured every endpoint must therefore be https:// (or unixs://);
//     anything else fails closed here instead of silently ignoring the
//     operator's TLS flags.
//   - an endpoint credential with no password would ALSO authenticate as
//     nobody (clientv3 requires both), so a half credential is refused.
func buildClientConfig(cfg Config) (clientv3.Config, error) {
	eps := make([]string, 0, len(cfg.Endpoints))
	var user, pass string
	for _, raw := range cfg.Endpoints {
		ep, u, p, err := splitEndpointCredential(raw)
		if err != nil {
			return clientv3.Config{}, err
		}
		if ep == "" {
			continue
		}
		if u != "" || p != "" {
			if user != "" && (user != u || pass != p) {
				return clientv3.Config{}, fmt.Errorf("etcd endpoints carry conflicting credentials (user %q vs %q): refusing to guess which identity the firewall authenticates as", user, u)
			}
			user, pass = u, p
		}
		if cfg.TLS != nil && !endpointIsTLS(ep) {
			return clientv3.Config{}, fmt.Errorf("etcd TLS is configured but endpoint %q is not https:// (or unixs://): clientv3 drops the TLS configuration for a plaintext endpoint, so the policy channel would stay cleartext while the operator believes TLS is on", ep)
		}
		eps = append(eps, ep)
	}
	if user != "" && pass == "" {
		return clientv3.Config{}, fmt.Errorf("etcd endpoint carries user %q with no password: etcd authentication needs both, so this would connect anonymously while a credential is configured", user)
	}
	// The mirror image (R97): a password with no username is equally
	// anonymous. clientv3 authenticates only when Username AND Password are
	// both non-empty, so `https://:<secret>@etcd:2379` — a typo, or a
	// templated ${ETCD_USER} that expanded to nothing — builds a client with
	// Username == "" and the operator's credential silently does nothing,
	// to no warning at all (clientv3 sees no credential configured).
	if pass != "" && user == "" {
		return clientv3.Config{}, fmt.Errorf("etcd endpoint carries a password with no username: etcd authentication needs both, so this would connect anonymously while a credential is configured (the username list entry is empty — check for an unexpanded $ETCD_USER)")
	}
	if len(eps) == 0 {
		// Every entry was blank ("," or " "): there is nothing to dial.
		// Returning a syncer here would arm Start's recovery loop against a
		// permanently invalid config — a doomed 5 s retry cycle for the life
		// of the process (R93's all-blank --threat-intel-url fix, same shape).
		return clientv3.Config{}, errNoUsableEndpoints
	}
	return clientv3.Config{
		Endpoints:   eps,
		DialTimeout: cfg.Timeout,
		TLS:         cfg.TLS,
		Username:    user,
		Password:    pass,
	}, nil
}

// splitEndpointCredential separates userinfo from an endpoint URL.
//
// A schemeless target ("etcd-0:2379") carries no credential and is returned
// verbatim: url.Parse would read "etcd-0" as a URI scheme, so the `://` test —
// not the parsed scheme — is what decides whether there is a URL to parse.
func splitEndpointCredential(raw string) (endpoint, user, pass string, err error) {
	ep := strings.TrimSpace(raw)
	if !strings.Contains(ep, "://") {
		return ep, "", "", nil
	}
	u, perr := url.Parse(ep)
	if perr != nil {
		// A url.Parse error embeds the raw string; scrub the credential out of
		// it before it can reach a log line (the R88.2 lesson).
		return "", "", "", fmt.Errorf("parsing etcd endpoint: %s", redact.ScrubIn(perr.Error(), ep))
	}
	if u.User == nil {
		// Still check the host: a URL-shaped endpoint with no host can never
		// be dialled whether or not it carries credentials.
		if !isSocketEndpoint(u) && u.Host == "" {
			return "", "", "", fmt.Errorf("etcd endpoint %q has no host: it can never be dialled, so the policy channel would be silently dead (check for an unexpanded variable in the endpoint list)", u.String())
		}
		return ep, "", "", nil
	}
	user = u.User.Username()
	pass, _ = u.User.Password()
	u.User = nil // drops "user:pass@" from the rendered URL
	// A URL-shaped endpoint with no host can never be dialled: it is what a
	// templated `https://${ETCD_USER}:${ETCD_PW}@${ETCD_HOST}:2379` becomes
	// when the host variable is empty (measured: the stripped form is the bare
	// string "https:"). Accepting it keeps the https:// prefix, so it is never
	// warned about as plaintext, and the policy channel is dead for the life
	// of the process while main logs "etcd syncer started" — a silent
	// degradation, not a configuration. A unix socket legitimately has no host
	// (the path is the address), so those schemes are exempt.
	if !isSocketEndpoint(u) && u.Host == "" {
		return "", "", "", fmt.Errorf("etcd endpoint %q has no host: it can never be dialled, so the policy channel would be silently dead (check for an unexpanded variable in the endpoint list)", u.String())
	}
	return u.String(), user, pass, nil
}

// isSocketEndpoint reports a unix-domain endpoint, whose address is a path and
// which therefore legitimately has no URL host.
func isSocketEndpoint(u *url.URL) bool {
	switch strings.ToLower(u.Scheme) {
	case "unix", "unixs":
		return true
	}
	return false
}

// endpointIsTLS reports whether clientv3 will use transport credentials for
// this endpoint. `endpoint.RequiresCredentials` maps https:// and unixs:// to
// CredsRequire and EVERYTHING else — http://, a bare host:port, a unix://
// socket — to a plaintext dial.
func endpointIsTLS(ep string) bool {
	return strings.HasPrefix(strings.ToLower(ep), "https://") || strings.HasPrefix(strings.ToLower(ep), "unixs://")
}

// maxCredentialFileSize caps each etcd TLS material read (R97). A CA bundle
// plus a client pair is a few KB; 1 MB is generous and still far below
// anything that matters for memory.
const maxCredentialFileSize = 1 << 20

// TLSConfig builds the etcd client TLS configuration from operator-supplied PEM
// paths (R97). Empty paths return (nil, nil): the endpoint scheme decides (an
// https:// endpoint gets TLS with the system root pool). This is the ONLY
// place the policy channel's trust anchors and client identity are read, so
// the hardening cannot be forgotten by one call site and kept by another.
//
// Every file is read through securepath.ReadCredentialFile — ".." rejected on
// the raw path, symlinks at the file or any directory component refused, a
// FIFO refused instead of blocking startup, the size cap enforced before the
// content is buffered (R42/R45/R62/R85/R91). These are the most consequential
// files in the policy plane: the CA bundle decides WHICH etcd the firewall
// believes, so a planted link does not just leak data — it hands an attacker
// the authority to rewrite the Rego that governs every packet decision.
//
// Two further rules refuse rather than degrade:
//   - half a client identity (cert without key, or key without cert) would
//     silently disable mTLS, so it is an error;
//   - a CA bundle that contains no certificate would silently leave RootCAs at
//     the system pool if it were ignored, so "the operator pinned a CA" and
//     "the operator's CA is in force" must not be able to disagree.
func TLSConfig(caFile, certFile, keyFile string) (*tls.Config, error) {
	caFile = strings.TrimSpace(caFile)
	certFile = strings.TrimSpace(certFile)
	keyFile = strings.TrimSpace(keyFile)

	if caFile == "" && certFile == "" && keyFile == "" {
		return nil, nil
	}

	cfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if caFile != "" {
		caPEM, err := securepath.ReadCredentialFile(caFile, maxCredentialFileSize)
		if err != nil {
			return nil, fmt.Errorf("reading etcd CA bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("etcd CA bundle %s contains no certificate: refusing to fall back to the system root pool, which would make the pinned CA inert", caFile)
		}
		cfg.RootCAs = pool
	}

	if (certFile == "") != (keyFile == "") {
		return nil, fmt.Errorf("etcd client identity: both --etcd-tls-cert and --etcd-tls-key are required (cert set: %t, key set: %t); half a pair silently disables mutual TLS", certFile != "", keyFile != "")
	}

	if certFile != "" {
		certPEM, err := securepath.ReadCredentialFile(certFile, maxCredentialFileSize)
		if err != nil {
			return nil, fmt.Errorf("reading etcd client certificate: %w", err)
		}
		keyPEM, err := securepath.ReadCredentialFile(keyFile, maxCredentialFileSize)
		if err != nil {
			return nil, fmt.Errorf("reading etcd client key: %w", err)
		}
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("parsing etcd client TLS key pair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}

	return cfg, nil
}

// plaintextWarning returns a loud, actionable warning when the policy channel
// will be plaintext to a host that is not loopback, and "" otherwise.
//
// The etcd channel carries the Rego that governs every packet decision. Over
// plain HTTP any host on the path — or a compromised/malicious etcd, the
// R51/R52 threat model — can rewrite it, and the deny-override firewall then
// permits everything, with nothing in the log to distinguish that deployment
// from a healthy one. TLS-terminating proxies and pod-local collectors are
// legitimate, so this warns rather than refuses; loopback is exempt because
// those bytes never leave the host (R88.3's webhook posture, same predicate).
func plaintextWarning(endpoints []string) string {
	var offenders []string
	for _, ep := range endpoints {
		if endpointIsTLS(ep) {
			continue
		}
		// A unix socket puts no bytes on a network: warning about it would be
		// a false positive, and a warning that fires on a safe config trains
		// the operator to ignore the real one (R88.3's posture).
		if strings.HasPrefix(strings.ToLower(ep), "unix://") {
			continue
		}
		host := ep
		if strings.Contains(ep, "://") {
			if u, err := url.Parse(ep); err == nil && u.Hostname() != "" {
				host = u.Hostname()
			}
		} else if h, _, err := net.SplitHostPort(ep); err == nil {
			host = h
		}
		if netguard.IsLoopbackHost(host) {
			continue
		}
		offenders = append(offenders, ep)
	}
	if len(offenders) == 0 {
		return ""
	}
	return fmt.Sprintf("etcd: policy channel is PLAINTEXT — the policy that governs every packet travels unencrypted and unauthenticated to %s, so any host on the path can rewrite it and disable blocking; use https:// endpoints (add --etcd-tls-ca / --etcd-tls-cert / --etcd-tls-key for a private CA or client identity), or a loopback/pod-local endpoint", strings.Join(offenders, ", "))
}

// New creates an etcd policy syncer.
func New(cfg Config, onUpdate func(string) error) (*Syncer, error) {
	if len(cfg.Endpoints) == 0 {
		return nil, nil
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Key == "" {
		cfg.Key = "/l3-firewall/policy"
	}

	cc, err := buildClientConfig(cfg)
	if err != nil {
		if errors.Is(err, errNoUsableEndpoints) {
			// Configured, but nothing dialable: say so once and start no
			// syncer. Arming the recovery loop against this config would
			// retry forever and log warnings for the life of the process.
			slog.Warn("etcd: policy sync disabled — every configured endpoint is blank", "key", cfg.Key)
			return nil, nil
		}
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}

	s := &Syncer{
		clientCfg: cc,
		key:       cfg.Key,
		timeout:   cfg.Timeout,
		onUpdate:  onUpdate,
		stopCh:    make(chan struct{}),
	}

	// The channel that carries the enforced policy must not be silently
	// plaintext (R97): say so, once, naming only the stripped endpoints.
	if w := plaintextWarning(cc.Endpoints); w != "" {
		slog.Warn(w)
	}

	cli, err := clientv3.New(cc)
	if err != nil {
		// R97: this is NOT a configuration error. Setting etcd credentials
		// makes clientv3 authenticate synchronously inside New (getToken), so an
		// etcd that is briefly unreachable at boot — a cluster rolling restart,
		// a network that is not up yet — fails construction after DialTimeout.
		// Returning that error would cost the process its policy plane for the
		// whole lifetime (main logs "not available" and never retries), which is
		// strictly worse than the pre-R97 lazily-dialled client that Start's
		// watch loop re-established (R65). Keep the syncer and let Start's
		// connect path retry with the same bounded backoff.
		slog.Warn("etcd: client not ready at startup — will connect in the background", "error", err)
		return s, nil
	}
	s.setClient(cli)
	return s, nil
}

// setClient installs the etcd client (guarded: the recovery connect goroutine
// and Close can run concurrently).
func (s *Syncer) setClient(c etcdClient) {
	s.clientMu.Lock()
	s.client = c
	s.clientMu.Unlock()
}

// etcdClientOrNil returns the current client, or nil when none has been
// installed yet (startup connect still pending, or disabled).
func (s *Syncer) etcdClientOrNil() etcdClient {
	s.clientMu.RLock()
	defer s.clientMu.RUnlock()
	return s.client
}

// Start begins watching the etcd key for changes.
// Idempotent — subsequent calls are no-ops.
func (s *Syncer) Start(ctx context.Context) {
	if s == nil {
		return
	}
	s.startOnce.Do(func() {
		if s.etcdClientOrNil() == nil {
			// R97 recovery path: the client could not be constructed at startup
			// (etcd unreachable, or credentials clientv3 authenticates
			// synchronously). Connect in the background, then run the ordinary
			// lifecycle — the policy plane must recover on its own, exactly
			// like the watch loop re-establishes a terminated watch (R65).
			go func() {
				if !s.connect(ctx) {
					return
				}
				s.loadCurrent(ctx)
				s.watch(ctx)
			}()
			return
		}
		// Load initial policy
		s.loadCurrent(ctx)
		// Start watcher
		go s.watch(ctx)
	})
}

// etcdConnectBackoff floors the recovery connect rate AND the per-attempt log
// rate. An etcd outage is measured in seconds, and a background loop that
// retried (or logged) faster would be a CPU/log-flood vector in the ordinary
// "cluster is down" case (the R96 posture applied to the connect loop).
const etcdConnectBackoff = 5 * time.Second

// etcdConnectLogInterval suppresses repeats of the SAME connect failure text
// (R96.3: report the first failure at once, the same text once per window, and
// a changed text immediately).
const etcdConnectLogInterval = 30 * time.Second

// connect builds the etcd client, retrying until it succeeds, the syncer is
// closed, or ctx is done. Returns true when a client is installed.
func (s *Syncer) connect(ctx context.Context) bool {
	var lastText string
	var lastLog time.Time
	for {
		cli, err := clientv3.New(s.clientCfg)
		if err == nil {
			s.setClient(cli)
			if s.closed.Load() {
				// Close() ran while we were connecting: do not leak the client.
				_ = cli.Close()
				s.setClient(nil)
				return false
			}
			slog.Info("etcd: connected", "key", s.key)
			return true
		}
		text := err.Error()
		if text != lastText || time.Since(lastLog) >= etcdConnectLogInterval {
			slog.Warn("etcd: connect failed, retrying", "key", s.key, "error", err)
			lastText, lastLog = text, time.Now()
		}
		select {
		case <-s.stopCh:
			return false
		case <-ctx.Done():
			return false
		case <-time.After(etcdConnectBackoff):
		}
	}
}

// applyPolicy dedupes policy content before the onUpdate callback is
// invoked. It records the last PROCESSED content (applied or rejected) so
// an identical replay never triggers a second recompile: etcd emits a
// modify event for every Put, even a same-value Put, and each reload
// recompiles the full policy (R61 — the R6 "no rate limiting" gap). The
// last-ATTEMPTED (not last-successful) content is tracked so a policy that
// fails to compile is also compiled at most once per distinct content.
// Returns true when the caller should invoke onUpdate.
func (s *Syncer) applyPolicy(policy string) bool {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	if policy == s.lastPolicy {
		return false
	}
	s.lastPolicy = policy
	return true
}

func (s *Syncer) loadCurrent(ctx context.Context) string {
	if s == nil {
		return ""
	}
	cli := s.etcdClientOrNil()
	if cli == nil {
		return ""
	}
	// Bound the Get with the config timeout: main() calls Start with
	// context.Background() (no deadline), and a raw Get on that context
	// hangs forever if the etcd endpoint accepts the connection but never
	// responds — blocking Start synchronously so the firewall never
	// reaches eng.Run() (startup DoS, R46). The timeout also covers a
	// half-open connection where DialTimeout already elapsed.
	getCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	resp, err := cli.Get(getCtx, s.key)
	if err != nil {
		slog.Warn("etcd: failed to get initial policy", "key", s.key, "error", err)
		return ""
	}
	// A Get response missing its kv entirely (nil response) or whose first
	// element is a nil KeyValue pointer must not panic loadCurrent: it runs
	// synchronously inside Start on the MAIN goroutine with no recover
	// anywhere on the path, so a panic there crashes the whole process at
	// startup (R52 — the R51 watch-loop nil-shape guard applied to the
	// initial-load path, which dereferenced resp.Kvs[0].Value unguarded).
	if resp == nil || len(resp.Kvs) == 0 || resp.Kvs[0] == nil {
		slog.Warn("etcd: initial Get response missing key/value, skipping")
		return ""
	}
	// Enforce policy size limit BEFORE converting the value to a string:
	// the conversion copies the full value into memory, so a post-copy
	// len(policy) check (pre-R54) defeats the cap's purpose — the
	// allocation the cap exists to prevent has already happened (R42/R13
	// check-before-allocate doctrine; R42's readPolicyFile enforces the
	// cap via fstat + LimitReader before the bytes ever reach memory).
	if len(resp.Kvs[0].Value) > maxPolicySize {
		slog.Warn("etcd: initial policy exceeds max size, skipping",
			"key", s.key, "size", len(resp.Kvs[0].Value), "max", maxPolicySize)
		return ""
	}
	policy := string(resp.Kvs[0].Value)
	// Content dedupe (R61): the same policy is already applied — a reload
	// would recompile identical content for nothing.
	if !s.applyPolicy(policy) {
		slog.Debug("etcd: initial policy unchanged, skipping", "key", s.key)
		return policy
	}
	// Wrap callback in panic recovery to prevent goroutine death
	if err := safeOnUpdate(s.onUpdate, policy); err != nil {
		slog.Warn("etcd: failed to load initial policy", "error", err)
	} else {
		slog.Info("etcd: loaded policy from", "key", s.key)
	}
	return policy
}

// minReloadInterval is the minimum time between onUpdate (policy
// reload) invocations (R63). R61 bounded the per-response event COUNT
// (maxWatchEventsPerResponse) and deduplicated identical content, but a
// stream of DISTINCT policies — each under the collapse threshold —
// still forced one full Rego recompile per event with no TIME-based
// bound: a malicious or compromised etcd (or a MITM on the plaintext
// connection, the R51/R52 threat model) sustains a CPU/allocation-churn
// engine (the R6 "no rate limiting" finding, which R61 closed only for
// the identical-replay dimension). Distinct policies arriving within
// the interval are collapsed: only the LATEST is applied once the
// interval elapses — every event on this single-key watch carries the
// FULL current value, so the latest event IS the latest state (the same
// latest-wins semantics R61.2 applies to oversized bursts). 100ms
// matches threatintel.StartRefresher's minInterval posture; legitimate
// policy updates are operator-paced and never hit the window.
const minReloadInterval = 100 * time.Millisecond

// watchReconnectDelay bounds the watch-reconnect rate (R65). When the
// watch stream keeps terminating (e.g., etcd permanently down, or a
// hostile server canceling every watch), the reconnect loop must not
// hot-spin: each cycle also pays a loadCurrent Get bounded by
// s.timeout — which dominates when etcd is down — and this delay
// floors the cycle when etcd answers instantly but the stream fails.
// 100ms matches minReloadInterval's posture; a policy syncer is
// eventual-consistency by nature, so one interval of sync downtime is
// invisible.
const watchReconnectDelay = 100 * time.Millisecond

func (s *Syncer) watch(ctx context.Context) {
	if s == nil {
		return
	}
	cli := s.etcdClientOrNil()
	if cli == nil {
		return
	}

	// Reload-rate-limiting state (R63): pendingPolicy holds the latest
	// policy that passed dedupe but has not yet been applied (its
	// minReloadInterval window has not elapsed); a timer armed while
	// pending guarantees a collapsed policy is flushed even if the
	// watch stream goes idle (otherwise the last update of a flood —
	// or a second update within the window — could be dropped forever).
	// Lives OUTSIDE the reconnect loop (R65) so a watch restart does
	// not reset the rate limiter.
	var lastReload time.Time
	var pendingPolicy string
	var pendingSet bool

	flushPending := func() {
		if !pendingSet {
			return
		}
		if time.Since(lastReload) < minReloadInterval {
			return
		}
		pendingSet = false
		// lastReload advances on failure too: a policy that fails to
		// compile must not re-trigger on every event of a flood (the
		// R61 last-PROCESSED dedupe semantics).
		if err := safeOnUpdate(s.onUpdate, pendingPolicy); err != nil {
			slog.Warn("etcd: failed to apply policy update", "error", err)
		} else {
			slog.Info("etcd: policy applied", "key", s.key)
		}
		lastReload = time.Now()
	}

	// Outer loop: re-establish the watch whenever it terminates (R65).
	for {
		wch := cli.Watch(ctx, s.key)
		terminated := false
		for !terminated {
			// While a policy is pending, arm a timer for its flush.
			var timer *time.Timer
			var timerC <-chan time.Time
			if pendingSet {
				d := minReloadInterval - time.Since(lastReload)
				if d < time.Millisecond {
					d = time.Millisecond
				}
				timer = time.NewTimer(d)
				timerC = timer.C
			}
			select {
			case <-s.stopCh:
				if timer != nil {
					timer.Stop()
				}
				return
			case wresp, ok := <-wch:
				if timer != nil {
					timer.Stop()
				}
				// A terminated watch must be RE-ESTABLISHED, not treated
				// as the end of sync (R65). clientv3 closes the watch
				// channel — after delivering a final Canceled/errored
				// WatchResponse (Err() non-nil) — when a watch cannot be
				// resumed: server-side cancel (watch session expiry,
				// server limits), mvcc compaction past the start revision
				// (ErrCompacted), or an unrecoverable stream error.
				// Pre-R65 the loop returned here permanently: under the
				// R51/R52 threat model (malicious/compromised etcd or a
				// MITM on the plaintext connection), one hostile frame
				// that failed the stream silently killed the policy
				// update plane forever — every subsequent legitimate
				// policy push (including emergency block-everything
				// policies during an incident) was dropped with no log
				// line and no recovery. The reconnect path below resyncs
				// via Get (compaction-proof) and re-establishes the watch.
				if !ok || wresp.Err() != nil || wresp.Canceled {
					switch {
					case wresp.Err() != nil:
						slog.Warn("etcd: watch terminated with error, reconnecting", "key", s.key, "error", wresp.Err())
					case wresp.Canceled:
						slog.Warn("etcd: watch canceled, reconnecting", "key", s.key)
					default:
						slog.Warn("etcd: watch channel closed, reconnecting", "key", s.key)
					}
					terminated = true
					break
				}
				// Apply any pending policy whose window has fully elapsed
				// before processing the new batch, so ordering is preserved
				// (older state first).
				flushPending()
				// Bound the event COUNT dimension (R58 rule): R13/R54 cap the
				// per-event VALUE size, but a single response within clientv3's
				// receive limit can carry ~400k minimal events, each triggering
				// a full policy recompile — unbounded CPU burn from one wire
				// response (R61). Collapse an oversized response to its LAST
				// event: every event on this single-key watch (no WithPrevKV)
				// carries the full current value, so the last event IS the
				// latest policy state; intermediates are irrelevant to a policy
				// syncer (eventual consistency).
				events := wresp.Events
				if len(events) > maxWatchEventsPerResponse {
					slog.Warn("etcd: watch response carries excessive events, applying only the latest state",
						"key", s.key, "count", len(events), "max", maxWatchEventsPerResponse)
					events = events[len(events)-1:]
				}
				for _, ev := range events {
					// A watch event missing its key/value (nil event pointer
					// or nil Kv — possible from a malformed/malicious etcd
					// wire response, which clientv3 casts into *Event pointers
					// without filtering) must not panic the watch goroutine:
					// an unrecovered panic there crashes the whole process
					// (R51 — the nil deref was the only unprotected statement
					// in the watch loop).
					if ev == nil || ev.Kv == nil {
						slog.Warn("etcd: watch event missing key/value, skipping")
						continue
					}
					// DELETE events carry no policy value (nil Kv.Value):
					// applying one always failed the empty-policy check,
					// churning a failed reload + error log per delete. Skip
					// with a warning and keep the last applied policy (R61).
					if ev.Type == mvccpb.DELETE {
						slog.Warn("etcd: policy key deleted, keeping last applied policy", "key", s.key)
						continue
					}
					// Enforce policy size limit BEFORE the string conversion —
					// same check-before-allocate ordering as loadCurrent (R54):
					// string() copies the value, so a post-copy check lets an
					// oversized value allocate fully before being rejected.
					if len(ev.Kv.Value) > maxPolicySize {
						slog.Warn("etcd: policy update exceeds max size, skipping",
							"key", s.key, "size", len(ev.Kv.Value), "max", maxPolicySize)
						continue
					}
					policy := string(ev.Kv.Value)
					// Content dedupe (R61): an identical replay never reloads
					// twice — see applyPolicy.
					if !s.applyPolicy(policy) {
						slog.Debug("etcd: policy unchanged, skipping reload", "key", s.key)
						continue
					}
					// Rate limit (R63): distinct policies arriving within
					// minReloadInterval collapse to the LATEST — the pending
					// policy is applied (and logged) once the interval elapses,
					// by flushPending at the next batch boundary or the timer.
					pendingPolicy = policy
					pendingSet = true
				}
				// Flush at the end of the batch when the window allows —
				// the common case: a single event long after the previous
				// reload applies immediately.
				flushPending()
			case <-timerC:
				flushPending()
			}
		}

		// Reconnect (R65): the watch stream is gone. Resync the latest
		// policy FIRST — events delivered between the failure and the
		// re-established watch may have been lost, and a Get at the
		// current revision has no historical dependency (it succeeds
		// even when the watch died to compaction). loadCurrent also
		// throttles the reconnect cycle when etcd is down (its Get is
		// bounded by s.timeout), so the loop cannot hot-spin. If the
		// context is done (shutdown), exit instead of reconnecting.
		if ctx.Err() != nil {
			return
		}
		current := s.loadCurrent(ctx)
		// R66: a pending policy that the resync SUPERSEDED must be dropped,
		// not flushed. R63 queues distinct policies in the pending slot when
		// they arrive within minReloadInterval of the last reload; the slot
		// lives OUTSIDE the reconnect loop (R65), so it survives a watch
		// restart. If the resync Get read a DIFFERENT policy than the queued
		// one, that Get ran at a revision >= the pending event's revision —
		// the resync value is the authoritative, newer state — and flushing
		// the older pending policy after the resync REGRESSES the firewall to
		// a stale policy (e.g. reverting an emergency block-everything policy
		// pushed during an incident — the exact scenario R65 exists to
		// protect). Because the resync also advanced lastPolicy past the
		// pending content, a replay of the newer policy is dedupe-skipped and
		// the firewall is STUCK on the stale policy until the next distinct
		// update. When the resync read the SAME content (pending == current)
		// the slot is kept: the pending flush performs the single apply. When
		// the resync read NOTHING (etcd down), the pending policy is the
		// best-known state and is kept as before.
		if current != "" && pendingSet && pendingPolicy != current {
			slog.Warn("etcd: resync superseded queued policy, dropping stale pending",
				"key", s.key, "queued", pendingPolicy, "current", current)
			pendingSet = false
		}
		select {
		case <-s.stopCh:
			return
		case <-ctx.Done():
			return
		case <-time.After(watchReconnectDelay):
		}
	}
}

// safeOnUpdate calls the onUpdate callback with panic recovery.
// If the callback panics, the panic is recovered and returned as an error.
func safeOnUpdate(fn func(string) error, policy string) (err error) {
	if fn == nil {
		return fmt.Errorf("onUpdate callback is nil")
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("onUpdate panic: %v", r)
			slog.Error("etcd: recovered panic in onUpdate callback", "panic", fmt.Sprintf("%v", r))
		}
	}()
	return fn(policy)
}

// Close shuts down the syncer and closes the etcd connection.
// Idempotent: the closeOnce guard covers the WHOLE close — the stopCh
// AND client.Close(). Before R54 the once guarded only the channel, so a
// second Close() re-invoked client.Close(): clientv3 tolerates double
// calls but the etcdClient interface (R46) makes no such promise for
// arbitrary implementations, and the idempotency contract exists exactly
// so a double Close cannot corrupt a client (R6 double-close panic class).
func (s *Syncer) Close() error {
	if s == nil {
		return nil
	}
	var err error
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.stopCh)
		if cli := s.etcdClientOrNil(); cli != nil {
			err = cli.Close()
		}
	})
	return err
}
