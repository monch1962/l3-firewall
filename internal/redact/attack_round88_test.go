// Red-team security hardening Round 88 — ScrubIn's exact-match blind spot.
//
// R87.2 established that a message logged by net/http contains the request URL
// verbatim (`Post "http://…/SECRET": dial tcp …`), and that a caller logging
// err.Error() therefore re-leaks whatever the structured "url" attribute just
// redacted. ScrubIn() was written to replace that occurrence.
//
// It used strings.ReplaceAll(msg, raw, URL(raw)) — an EXACT byte match against
// the configured string. But the URL in the error text is not the configured
// string: net/http prints `req.URL.String()`, i.e. the URL RE-ENCODED by
// net/url. Any byte the operator typed literally that the escaping rules cover
// comes back percent-encoded:
//
//	configured  http://h/hooks/T000/SUPERSECRETTOKEN/a b
//	in err text Post "http://h/hooks/T000/SUPERSECRETTOKEN/a%20b": dial tcp …
//
// The exact match fails, so the credential survives scrubbing and reaches the
// log. Measured on Go 1.25:
//
//	raw "http://127.0.0.1:1/hooks/SUPER SECRET" -> err carries SUPER%20SECRET
//	raw "http://127.0.0.1:1/hook/sécrèt"        -> err carries s%C3%A9cr%C3%A8t
//
// The secret's ASCII core survives escaping contiguously, so the credential is
// still recoverable from the log even though the URL looks "encoded".
//
// Attack model: the credential is operator-supplied and may legally contain a
// space (a copied-and-wrapped secret), a non-ASCII byte (a token with an
// accented character, or a feed URL with a Unicode path), or any other byte
// net/url escapes. Redaction must not depend on the secret being
// encoding-neutral.
package redact

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// ── R88.2: scrubbing must survive net/url re-encoding ────────────────────
func TestAttack_ScrubInMissesEscapedURLForm(t *testing.T) {
	const token = "SUPERSECRETTOKEN"

	cases := []struct {
		name string
		raw  string
	}{
		{"literal space in the path", "http://127.0.0.1:1/hooks/" + token + "/a b"},
		{"non-ASCII path segment", "http://127.0.0.1:1/hooks/" + token + "/sécrèt"},
		{"space inside the query value", "http://127.0.0.1:1/feed?auth_key=" + token + "&q=a b"},
		{"control-free unicode host path mix", "http://127.0.0.1:1/" + token + "/ü"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, err := url.Parse(c.raw)
			if err != nil {
				t.Fatalf("test URL %q does not parse: %v", c.raw, err)
			}
			// Exactly what net/http's *url.Error renders.
			msg := fmt.Sprintf("Post %q: dial tcp 127.0.0.1:1: connect: connection refused", u.String())

			got := ScrubIn(msg, c.raw)
			if strings.Contains(got, token) {
				t.Fatalf("ScrubIn left the credential in the message (net/url re-encoded the URL, so the exact match missed):\n  raw: %q\n  msg: %s\n  got: %s", c.raw, msg, got)
			}
			if !strings.Contains(got, "127.0.0.1") {
				t.Errorf("ScrubIn destroyed the endpoint identifier: %q", got)
			}
			if !strings.Contains(got, "connect: connection refused") {
				t.Errorf("ScrubIn destroyed the diagnostic: %q", got)
			}
		})
	}

	// Regression: the encoding-neutral case (what R87 tested) must still work.
	const plainURL = "http://127.0.0.1:1/hooks/T000/B000/" + token
	if got := ScrubIn(`Post "`+plainURL+`": dial tcp 127.0.0.1:1: connect: connection refused`, plainURL); strings.Contains(got, token) {
		t.Errorf("ScrubIn regressed on the encoding-neutral form: %q", got)
	}
	// Regression: a message with no URL, and an empty URL, are untouched.
	if out := ScrubIn("dial tcp: i/o timeout", plainURL); out != "dial tcp: i/o timeout" {
		t.Errorf("ScrubIn(%q) = %q, want unchanged", "dial tcp: i/o timeout", out)
	}
	if out := ScrubIn("dial tcp: i/o timeout", ""); out != "dial tcp: i/o timeout" {
		t.Errorf("ScrubIn with an empty URL = %q, want unchanged", out)
	}
}

// ── R88.2b: a credential-bearing URL must not survive in ANY rendering ───
// The property form of the same finding: whatever the tail of a URL looks like
// when it reaches the log, nothing after scheme://host may remain, because
// that is where the secret lives (path segment, query, fragment).
func TestAttack_NoRenderingOfTheURLLeaksTheTail(t *testing.T) {
	const token = "TAILSECRET"
	raw := "http://127.0.0.1:9/hooks/" + token + "?auth_key=" + token + "#" + token

	renderings := []string{}
	escaped := func() string {
		u, err := url.Parse(raw)
		if err != nil {
			return raw
		}
		return u.String()
	}()
	for _, q := range []func() string{
		func() string { return raw },                                    // as configured
		func() string { return escaped },                                // net/url re-encoded (what *url.Error carries)
		func() string { return "POST " + raw + " (retry 3)" },           // embedded in prose
		func() string { return `Post "` + raw + `": connection reset` }, // net/http shape
	} {
		renderings = append(renderings, q())
	}

	for _, msg := range renderings {
		if got := ScrubIn(msg, raw); strings.Contains(got, token) {
			t.Errorf("ScrubIn(%q) leaked the credential tail: %q", msg, got)
		}
	}
}
