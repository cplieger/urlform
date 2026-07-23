package urlform

import (
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Class names the structural form of a raw, untrusted URL string -
// specifically the browser-vs-net/url parse quirks that decide whether the
// string really carries a host. It is the single home of that quirk
// vocabulary; see Form.
type Class int

const (
	// ClassEmpty is a string that is empty after the input preprocessing
	// (edge trimming plus tab/newline removal; see Classify).
	ClassEmpty Class = iota
	// ClassMalformed is a string the canonicalized parse rejected; no
	// structural facts (and no host evidence) can be extracted from it.
	ClassMalformed
	// ClassAbsolute is a scheme-and-host absolute URL ("https://host/x");
	// Host carries the parsed hostname.
	ClassAbsolute
	// ClassHiddenHost is a scheme-bearing parse with no hostname, where
	// net/url sees no host but a browser may navigate to one. For the
	// authority-carrying special schemes (http, https, ws, wss, ftp) the
	// WHATWG parser skips ANY run of slashes after the scheme - zero
	// ("https:host/x"), one ("https:/host/x"), or many - and reads the
	// authority, so the classifier runs the same authority reparse it uses
	// for schemeless forms and recovers the browser's reading into
	// Host/Port/HasUserInfo (HostUnrecoverable marks a failed recovery; a
	// port-only authority such as "https://:443/x" recovers no host, which
	// matches the browser - the WHATWG parser fails on an empty special
	// host). For every other scheme ("host:443/x" parsing the host as an
	// opaque scheme, "javascript:alert(1)", "mailto:x") the browser reads an
	// opaque path with no authority, so the facts stay empty - there the
	// host evidence, if any, is genuinely hidden.
	ClassHiddenHost
	// ClassProtocolRelative is a network-path reference: "//host/x" (Host
	// carries the parsed host a browser would resolve against the ambient
	// scheme) or a leading-"//" form with no extractable host evidence - a
	// three-or-more-slash form ("///x": Go parses a rooted path while
	// browsers read an authority) or an empty-authority form ("//", "//?q").
	// Host is the discriminator between the two sub-forms: consumers that
	// need host evidence treat an empty Host here as ambiguous and fail
	// closed.
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
	// Trimmed is the preprocessed raw string the classification read: edges
	// trimmed and embedded ASCII tab/newline removed (the WHATWG input
	// preprocessing, recorded by HasTabOrNewline), with backslashes NOT
	// canonicalized. It is what a publisher emits or prefixes - already free
	// of the whitespace-smuggling bytes a browser would silently drop, and
	// never otherwise rewritten.
	Trimmed string
	// Host is the lowercased host evidence a browser would navigate to, when
	// extractable: the parsed hostname of an absolute or protocol-relative
	// form, or the authority reparse of a schemeless-host or recoverable
	// hidden-host form. Empty when the string carries none (or the form
	// hides it; see Class). The fold is ASCII-only by design (see
	// asciiLower): a full-Unicode fold would launder homograph bytes
	// (U+0130 -> 'i', U+212A -> 'k') into ASCII, so non-ASCII host evidence
	// survives here unfolded for a consumer's fail-closed ASCII-only host
	// gates.
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
	// a valid 16-bit port (a link publisher) validate the range. (The WHATWG
	// parser rejects an out-of-range port outright; reporting the fact and
	// leaving the fail direction to the consumer is this package's model.)
	Port string
	// Class is the structural form.
	Class Class
	// HasBackslash records a '\' anywhere in the trimmed string. Browsers
	// (WHATWG URL parser) treat '\' as '/' for the special schemes (http,
	// https, ws, wss, ftp, file) and for schemeless forms (where the address
	// bar's ambient scheme is special), so for those the parsed facts
	// (Scheme/Host/Port/Class) describe the canonicalized reading - a
	// `/\host/x` form classifies protocol-relative, not as a host-less
	// rooted path. For a non-special scheme a backslash is an ordinary
	// character and is NOT canonicalized (a browser reads an opaque path).
	// Either way the flag lets a publisher that must emit the raw string
	// reject it outright.
	HasBackslash bool
	// HasTabOrNewline records that the edge-trimmed string contained
	// embedded ASCII tab or newline (U+0009, U+000A, U+000D), which the
	// WHATWG parser - and therefore this classification - removes wherever
	// they appear ("https://anime\tbytes.tv/x" navigates to animebytes.tv).
	// Trimmed already has them removed, so emitting Trimmed is safe; the
	// flag records the smuggling attempt for publishers that treat the
	// ORIGINAL string as emittable or want to reject de-smuggled input
	// outright.
	HasTabOrNewline bool
	// HostUnrecoverable marks a ClassSchemelessHost or recoverable
	// ClassHiddenHost whose authority reparse failed (e.g. a space before an
	// "@"): browser-visible host evidence may exist but cannot be extracted,
	// so evidence-driven consumers treat the form like a parse failure.
	HostUnrecoverable bool
	// HasUserInfo records a userinfo authority component ("user@host") in
	// the canonicalized parse - a visual-spoofing vector
	// ("https://trusted@evil/") a link publisher typically rejects. For a
	// ClassSchemelessHost or recovered ClassHiddenHost the fact comes from
	// the same authority reparse that supplies Host (so "user@host/x"
	// reports it alongside the recovered host). Always false when the
	// string did not parse.
	HasUserInfo bool
}

// Classify classifies a raw URL string into its structural Form. It
// never errors: every input lands in exactly one class, and unparseable input
// is ClassMalformed. Consumers apply their own policy over the returned
// facts (see Form).
//
// Classification starts with the WHATWG basic parser's input preprocessing,
// so string-level whitespace smuggling cannot hide a URL from the facts:
// leading/trailing C0 controls and whitespace are trimmed (trimEdges), and
// embedded ASCII tab/newline are removed everywhere (recorded by
// HasTabOrNewline). This is the same hardening CPython adopted for
// urllib.parse (CVE-2022-0391).
func Classify(raw string) Form {
	f := Form{Trimmed: trimEdges(raw)}
	if strings.ContainsAny(f.Trimmed, "\t\n\r") {
		f.HasTabOrNewline = true
		f.Trimmed = strings.Map(dropTabOrNewline, f.Trimmed)
	}
	f.HasBackslash = strings.Contains(f.Trimmed, `\`)
	if f.Trimmed == "" {
		f.Class = ClassEmpty
		return f
	}
	canonical := canonicalizeSlashes(f.Trimmed)
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
		f.recoverHiddenAuthority(canonical)
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

// recoverHiddenAuthority extracts the browser's authority reading from a
// scheme-bearing parse that hid it. The WHATWG scheme state routes every
// special scheme to "special authority ignore slashes", which skips any run
// of slashes (and, already canonicalized here, backslashes) after the colon
// and reads an authority - so "https:/host/x" and "https:host/x" both
// navigate to host. The recovery reuses the classifier's authority-reparse
// heuristic on that remainder. It applies only to the special schemes that
// carry an authority (file is special for slash handling but its slash forms
// yield an empty host, and non-special schemes read an opaque path - no
// browser-visible host exists to recover for either).
func (f *Form) recoverHiddenAuthority(canonical string) {
	if !isAuthorityScheme(f.Scheme) {
		return
	}
	rest := strings.TrimLeft(canonical[len(f.Scheme)+1:], "/")
	rehost, err := url.Parse("//" + rest)
	if err != nil {
		f.HostUnrecoverable = true
		return
	}
	f.Host = asciiLower(rehost.Hostname())
	f.Port = rehost.Port()
	f.HasUserInfo = rehost.User != nil
}

// trimEdges removes leading and trailing C0 controls and space (the WHATWG
// basic parser's edge rule: every byte <= 0x20) plus the wider Unicode
// whitespace set (strings.TrimSpace's rule, kept deliberately: an NBSP- or
// ideographic-space-wrapped link still classifies with facts, and
// over-trimming errs fail-safe for evidence gates where a WHATWG-strict edge
// would return no facts at all). The delta from the spec is edge-only and
// documented; embedded characters are never touched here.
func trimEdges(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		return r <= 0x20 || unicode.IsSpace(r)
	})
}

// dropTabOrNewline is the strings.Map dropper for the WHATWG "remove all
// ASCII tab or newline from input" preprocessing step.
func dropTabOrNewline(r rune) rune {
	if r == '\t' || r == '\n' || r == '\r' {
		return -1
	}
	return r
}

// schemeEnd returns the index of the ':' terminating a leading URL scheme
// (RFC 3986 / WHATWG grammar: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )),
// or -1 when the string carries no scheme prefix.
func schemeEnd(s string) int {
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		case i > 0 && c == ':':
			return i
		default:
			return -1
		}
	}
	return -1
}

// isSpecialScheme reports whether scheme (already lowercased) is a WHATWG
// special scheme - the set for which the spec treats '\' as '/'.
func isSpecialScheme(scheme string) bool {
	switch scheme {
	case "http", "https", "ws", "wss", "ftp", "file":
		return true
	}
	return false
}

// isAuthorityScheme reports whether scheme (already lowercased) is a special
// scheme that carries a recoverable authority after arbitrary slash runs -
// the special set minus file, whose slash forms read an empty host.
func isAuthorityScheme(scheme string) bool {
	return scheme != "file" && isSpecialScheme(scheme)
}

// canonicalizeSlashes rewrites '\' to '/' exactly where the WHATWG parser
// treats them as equivalent: for special-scheme forms and schemeless forms
// (where the address bar's ambient scheme is special), and only ahead of the
// query/fragment (past the first '?' or '#' a backslash is an ordinary
// character even for special schemes). A non-special scheme's backslashes
// are ordinary characters everywhere - rewriting them would fabricate host
// evidence a browser never sees ("non-special:\\x" reads an opaque path,
// not an authority).
func canonicalizeSlashes(s string) string {
	if end := schemeEnd(s); end >= 0 && !isSpecialScheme(strings.ToLower(s[:end])) {
		return s
	}
	stop := strings.IndexAny(s, "?#")
	if stop == -1 {
		stop = len(s)
	}
	if !strings.Contains(s[:stop], `\`) {
		return s
	}
	return strings.ReplaceAll(s[:stop], `\`, "/") + s[stop:]
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
