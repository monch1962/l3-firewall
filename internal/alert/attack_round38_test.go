// Red-team security hardening Round 38 — SSRF via redirect in alert webhook client
//
// R11 fixed threatintel.FetchFromURL following redirects with
// http.ErrUseLastResponse. The alert Router's http.Client has NO
// CheckRedirect: a compromised or malicious webhook endpoint can 302/307
// redirect the alert POST (containing src IPs, messages) to an internal
// service (cloud metadata 169.254.169.254, etcd, admin API) — the firewall
// becomes an SSRF proxy and leaks alert payloads to internal targets.
//
// Same attack class as R11, but on a different integration point
// (alert package had zero attack-test coverage prior to this round).
package alert

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// ── R38.1: Alert webhook must NOT follow redirects to internal targets ──
// Malicious webhook endpoint redirects the alert POST to an internal
// service. With a default http.Client the payload is re-sent to the
// redirect target (307 preserves method+body) → SSRF + payload exfil.
func TestAttack_WebhookMustNotFollowRedirect(t *testing.T) {
	var internalHits int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&internalHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer internal.Close()

	// Malicious webhook: 307-redirect every alert POST to the internal target
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL, http.StatusTemporaryRedirect)
	}))
	defer webhook.Close()

	r := NewRouter(Config{WebhookURL: webhook.URL, Cooldown: 0})
	r.Send(AlertEvent{Type: AlertBlockRate, Message: "src=10.0.0.1"})

	time.Sleep(500 * time.Millisecond)

	if got := atomic.LoadInt32(&internalHits); got > 0 {
		t.Errorf("alert payload was redirected to internal target %d times — SSRF via redirect (R11 class)", got)
	} else {
		t.Log("alert client did not follow redirect — payload stayed at webhook endpoint")
	}
}

// ── R38.2: Direct (non-redirect) webhook delivery still works ────────
func TestAttack_WebhookDirectDeliveryStillWorks(t *testing.T) {
	var hits int32
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()

	r := NewRouter(Config{WebhookURL: webhook.URL, Cooldown: 0})
	r.Send(AlertEvent{Type: AlertBlockRate, Message: "test"})

	time.Sleep(500 * time.Millisecond)

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("direct webhook delivery failed: hits=%d, want 1", got)
	} else {
		t.Log("direct webhook delivery works — regression OK")
	}
}
