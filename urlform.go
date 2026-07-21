package urlform

import (
	"net/url"
	"strings"
	"unicode/utf8"
)

// Class names the structural form of a raw, untrusted URL string -
// specifically the browser-vs-net/url parse quirks that decide whether the
// string really carries a host. It is the single home of that quirk
// vocabulary; see Form.
type Class int

const (
	// ClassEmpty is a string that is empty after whitespace trimming.
	ClassEmpty Class = iota
	// ClassMalformed is a string the canonicalized parse rejected; no
	// structural facts (and no host evidence) can be extracted from it.
	ClassMalformed
	// ClassAbsolute is a scheme-and-host absolute URL ("https://host/x");
	// Host carries the parsed hostname.
	ClassAbsolute
	// ClassHiddenHost is a scheme-bearing parse with no hostname, where
	// net/url sees no host but a browser may navigate to one: a
	// path-relative scheme form ("https:/host/x" parses scheme + path), an
	// opaque host:port form ("host:443/x" parses the host as the scheme), or
	// a port-only authority ("https://:443/x"). The host evidence is hidden.
	ClassHiddenHost
	// ClassProtocolRelative is a network-path reference: "//host/x" (Host
	// carries the parsed host a browser would resolve against the ambient
	// scheme) or a three-or-more-slash form ("///x"), which Go parses as a
	// rooted path while browsers read an authority (Host stays empty - the
	// form is ambiguous).
	ClassProtocolRelative
	// ClassSchemelessHost is a scheme-free, non-rooted form ("host/x"):
	// net/url parses a bare path, but a browser address bar navigates to the
	// first segment as a host. Host carries that authority-reparse evidence
	// (empty for a query- or fragment-only form such as "?x:y");
	// HostUnrecoverable marks a failed reparse.
	ClassSchemelessHost
	// ClassRelative is a rooted, host-free relative path ("/x").
	ClassRelative
)

// Form is the structural classification of one raw, untrusted URL string
// (an upstream API field, a scraped link, operator input). It names the
// browser-vs-net/url parse-quirk classes ONCE - backslash authorities,
// protocol-relative and schemeless-host forms, hidden-host parses - so every
// consumer branches on the same facts while keeping its own fail direction
// as policy: a publisher drops what it cannot vouch for (publish-or-drop),
// while an evidence gate hides what it cannot classify
// (extract-evidence-or-hide). Fields are ordered for govet fieldalignment.
type Form struct {
	// parsed is the canonicalized parse result (backslashes read as slashes,
	// like the WHATWG parser); nil for ClassEmpty and ClassMalformed. It
	// stays private to the classifier: consumers read the semantic facts
	// below (Scheme, Host, Port, HasUserInfo), never the parser
	// representation, so a parser/canonicalization change cannot cross the
	// package boundary. The nil-exactly-for-Empty/Malformed invariant is
	// pinned by the in-package fuzz test.
	parsed *url.URL
	// Trimmed is the whitespace-trimmed raw string the classification read,
	// with backslashes NOT canonicalized: it is what a publisher emits or
	// prefixes, never a rewritten form.
	Trimmed string
	// Host is the lowercased host evidence a browser would navigate to, when
	// extractable: the parsed hostname of an absolute or protocol-relative
	// form, or the authority reparse of a schemeless-host form. Empty when
	// the string carries none (or the form hides it; see Class). The fold is
	// ASCII-only by design (see asciiLower): a full-Unicode fold would
	// launder homograph bytes (U+0130 -> 'i', U+212A -> 'k') into ASCII, so
	// non-ASCII host evidence survives here unfolded for a consumer's
	// fail-closed ASCII-only host gates.
	Host string
	// Scheme is the canonicalized parse's scheme, which url.Parse folds to
	// lowercase (an "HTTPS://" source reads "https", RFC 3986 canonical
	// form), so the value is already case-folded; empty when the string
	// carries none or did not parse. Case-insensitive comparison by consumers
	// remains correct as defense in depth.
	Scheme string
	// Port is the canonicalized parse's port string; empty when none is
	// present or the string did not parse. net/url only accepts an
	// all-digit port, but it does not range-check it - consumers that need
	// a valid 16-bit port (a link publisher) validate the range.
	Port string
	// Class is the structural form.
	Class Class
	// HasBackslash records a '\' anywhere in the trimmed string. Browsers
	// (WHATWG URL parser) treat '\' as '/', so the parsed facts (Scheme/
	// Host/Port/Class) describe the canonicalized reading - a `/\host/x`
	// form classifies protocol-relative,
	// not as a host-less rooted path - while the flag lets a publisher that
	// must emit the raw string reject it outright.
	HasBackslash bool
	// HostUnrecoverable marks a ClassSchemelessHost whose authority reparse
	// failed (e.g. a space before an "@"): browser-visible host evidence may
	// exist but cannot be extracted, so evidence-driven consumers treat the
	// form like a parse failure.
	HostUnrecoverable bool
	// HasUserInfo records a userinfo authority component ("user@host") in
	// the canonicalized parse - a visual-spoofing vector
	// ("https://trusted@evil/") a link publisher typically rejects. For a
	// ClassSchemelessHost the fact comes from the same authority reparse
	// that supplies Host (so "user@host/x" reports it alongside the
	// recovered host). Always false when the string did not parse.
	HasUserInfo bool
}

// Classify classifies a raw URL string into its structural Form. It
// never errors: every input lands in exactly one class, and unparseable input
// is ClassMalformed. Consumers apply their own policy over the returned
// facts (see Form).
func Classify(raw string) Form {
	f := Form{Trimmed: strings.TrimSpace(raw)}
	f.HasBackslash = strings.Contains(f.Trimmed, `\`)
	if f.Trimmed == "" {
		f.Class = ClassEmpty
		return f
	}
	canonical := strings.ReplaceAll(f.Trimmed, `\`, "/")
	parsed, err := url.Parse(canonical)
	if err != nil {
		f.Class = ClassMalformed
		return f
	}
	f.parsed = parsed
	f.Scheme = parsed.Scheme
	f.Port = parsed.Port()
	f.HasUserInfo = parsed.User != nil
	// Hostname() drops the port and userinfo; asciiLower folds case for the
	// byte-wise host predicates downstream while leaving non-ASCII homograph
	// bytes intact for the fail-closed IsASCIIHost gates.
	f.Host = asciiLower(parsed.Hostname())
	switch {
	case parsed.Scheme != "" && f.Host != "":
		f.Class = ClassAbsolute
	case parsed.Scheme != "":
		f.Class = ClassHiddenHost
	case f.Host != "":
		f.Class = ClassProtocolRelative
	case strings.HasPrefix(canonical, "//"):
		// A leading "//" whose parse yielded no host: three or more slashes
		// (Go parsed a rooted path while browsers read an authority) or an
		// empty-authority form ("//", "//?q"). Either way the string is a
		// network-path reference with no extractable host evidence, so Host
		// stays empty and the form classifies protocol-relative.
		f.Class = ClassProtocolRelative
	case strings.HasPrefix(canonical, "/"):
		f.Class = ClassRelative
	default:
		f.Class = ClassSchemelessHost
		rehost, rerr := url.Parse("//" + canonical)
		if rerr != nil {
			f.HostUnrecoverable = true
			return f
		}
		f.Host = asciiLower(rehost.Hostname())
		f.HasUserInfo = rehost.User != nil
	}
	return f
}

// asciiLower lowercases only the ASCII letters A-Z, leaving every other byte
// untouched. Form.Host folds with this instead of strings.ToLower because
// the full-Unicode fold has ASCII-producing mappings (U+0130 LATIN CAPITAL
// LETTER I WITH DOT ABOVE -> 'i', U+212A KELVIN SIGN -> 'k') that would
// launder a homograph host into ASCII before a consumer's fail-closed
// ASCII-only host gates ever see the non-ASCII evidence they exist to
// reject.
func asciiLower(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, s)
}

// IsASCIIHost reports whether every byte of host is ASCII (below
// utf8.RuneSelf). It is the fail-closed companion of Form.Host's
// ASCII-only fold: a consumer matching host evidence against known ASCII
// domains gates on it first, so a homograph host (Cyrillic lookalikes, a
// fold-laundering U+0130 or U+212A) never string-matches a canonical
// domain. Callers that must ACCEPT international hosts convert punycode
// explicitly instead of relaxing this predicate.
func IsASCIIHost(host string) bool {
	for i := range len(host) {
		if host[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
