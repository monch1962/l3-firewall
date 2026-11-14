// Package redact turns credential-bearing URLs and messages into log-safe
// strings.
//
// A webhook URL (Slack/Discord/Teams/Mattermost) and an authenticated threat-
// intel feed URL are both BEARER CREDENTIALS: the secret lives in the path or
// the query string, and possession of the URL is enough to use it. The firewall
// logs these URLs at startup and on every failed delivery, so without redaction
// the credential ends up in the container log driver, a hosted log service, a
// SIEM index, or a support bundle — all of which have a wider and less
// privileged readership than the process environment.
//
// Centralised here rather than patched per call site: the R85 lesson is that a
// guard copied into two consumers drifts, so alerting (internal/alert) and the
// binary's startup lines (cmd/server) share this one implementation.
package redact

import (
	"net/url"
	"strings"
)

// ellipsis marks the removed, credential-bearing part of a URL.
const ellipsis = "…"

// URL returns a log-safe rendering of raw: scheme and host are kept (an
// operator needs to know WHICH endpoint failed), userinfo and the entire
// path/query/fragment are dropped.
//
// A string that does not parse as an absolute URL is reduced to the bare
// ellipsis rather than echoed: partial output of an unparseable string may
// still contain the secret verbatim, so there is nothing safe to keep.
func URL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ellipsis
	}
	// u.Host excludes userinfo, so this drops "user:pass@" for free.
	base := u.Scheme + "://" + u.Host
	if u.EscapedPath() == "" || u.EscapedPath() == "/" {
		if u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(raw, "/") {
			return base + "/" + ellipsis
		}
		return base
	}
	return base + "/" + ellipsis
}

// URLs redacts a comma-separated URL list (the form --threat-intel-url takes)
// element by element, so a multi-feed configuration still reports how many
// feeds are configured. Passing the whole string to URL would treat the second
// and later entries as part of the first URL's path and hide them.
func URLs(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		out = append(out, URL(p))
	}
	return strings.Join(out, ", ")
}

// ScrubIn rewrites every occurrence of raw inside msg with the redacted form.
// It exists because net/http embeds the request URL in its own error strings
// (`Post "http://…/SECRET": dial tcp …`), so redacting the structured "url"
// attribute alone would re-leak the credential through err.Error(). Diagnostic
// detail around the URL is preserved.
//
// Three passes, because the string in the message is not necessarily the string
// that was configured (R88.2):
//
//  1. the configured bytes, for messages that quote the URL verbatim (a
//     caller's own fmt.Errorf, an operator's prose);
//  2. net/url's rendering — `req.URL.String()`, which is what *url.Error
//     actually carries — because it percent-encodes bytes the configuration
//     held literally (space → %20, non-ASCII → %XX), so an exact match on (1)
//     misses and the credential survives;
//  3. any remaining occurrence of the same origin (scheme://host), cut at the
//     next quote/whitespace. The tail of a URL is credential-bearing by
//     definition and its exact re-encoding cannot be predicted, so the sweep
//     is what makes the function robust rather than pattern-matching.
func ScrubIn(msg, raw string) string {
	if raw == "" || msg == "" {
		return msg
	}
	msg = strings.ReplaceAll(msg, raw, URL(raw))

	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return msg
	}
	if esc := u.String(); esc != raw {
		msg = strings.ReplaceAll(msg, esc, URL(raw))
	}
	return redactOriginTails(msg, u.Scheme+"://"+u.Host)
}

// urlTokenEnd lists the bytes that terminate a URL embedded in free text.
//
// A comma is deliberately NOT a terminator: a query string may contain one, and
// stopping there would leave the fragment after it exposed. Prose such as
// "posting to http://h/x, retrying" still reads correctly afterwards — the
// trailing text survives, only the URL run is replaced.
const urlTokenEnd = " 	\r\n\"'`<>()[]{}"

// redactOriginTails replaces every `origin/<anything>` run in msg with
// `origin/…`, stopping at urlTokenEnd.
//
// A bare origin (nothing but the terminator after it) is left alone: there is
// no tail to leak, and rewriting it would churn text for no gain. The scan is
// prefix-safe — `origin` = "http://h:1" must not swallow "http://h:18080".
func redactOriginTails(msg, origin string) string {
	replacement := origin + "/" + ellipsis
	var b strings.Builder
	for {
		i := strings.Index(msg, origin)
		if i < 0 {
			b.WriteString(msg)
			return b.String()
		}
		b.WriteString(msg[:i])
		rest := msg[i+len(origin):]
		// Only a URL separator can follow the origin; anything else means this
		// occurrence is a longer host or port (prefix collision), so keep it.
		if rest == "" || !strings.ContainsAny(rest[:1], "/?#") {
			b.WriteString(origin)
			msg = rest
			continue
		}
		end := strings.IndexAny(rest, urlTokenEnd)
		if end < 0 {
			b.WriteString(replacement)
			return b.String()
		}
		b.WriteString(replacement)
		msg = rest[end:]
	}
}
