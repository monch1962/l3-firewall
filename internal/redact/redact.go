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
func ScrubIn(msg, raw string) string {
	if raw == "" || !strings.Contains(msg, raw) {
		return msg
	}
	return strings.ReplaceAll(msg, raw, URL(raw))
}
