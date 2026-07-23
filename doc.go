// Package urlform classifies the structural form of a raw, untrusted URL
// string — specifically the forms where a BROWSER's reading (the WHATWG URL
// parser) diverges from net/url's: whitespace-smuggled URLs, backslash
// authorities, slash-count fixups after a special scheme, protocol-relative
// and schemeless-host forms, hidden-host parses, userinfo spoofing.
//
// The parser of record is the divide that places this package. Validating a
// URL the PROCESS will fetch is a different concern (there net/url and the
// dialer are authoritative; use an SSRF guard). urlform models
// classify-for-PUBLISH: the string is destined for a human whose browser
// will read it, and the quirk classes exist precisely where that reading and
// Go's disagree.
//
// The covered divergence set is bounded and enumerated — urlform is a
// classifier over net/url with the WHATWG readings layered on, not a
// conformant WHATWG parser. What it models, pinned by the conformance
// fixtures in testdata/whatwg-fixtures.json (WPT-derived plus hand-derived
// address-bar rows):
//
//   - Input preprocessing: leading/trailing C0-control-or-space trimming
//     (widened to all Unicode whitespace, a documented fail-safe superset)
//     and embedded ASCII tab/newline removal, recorded by HasTabOrNewline —
//     so "https://anime\tbytes.tv/x" classifies with its real host.
//   - Backslash-as-slash for special schemes (http, https, ws, wss, ftp,
//     file) and schemeless forms, ahead of the query/fragment; a
//     non-special scheme's backslashes stay ordinary characters.
//   - Slash-count fixups: after an authority-carrying special scheme the
//     browser reads an authority through ANY run of slashes, so
//     "https:/host/x" and "https:host/x" expose their hidden host evidence
//     (ClassHiddenHost with recovered facts).
//   - Address-bar forms outside the URL spec: "host/x" navigates to host
//     (ClassSchemelessHost), "//host/x" resolves against the ambient scheme
//     (ClassProtocolRelative).
//
// Deliberately NOT modeled (the boundary of the contract): IDNA/UTS46 host
// mapping and punycode (non-ASCII host evidence survives raw for the
// fail-closed gates — see IsASCIIHost), percent-encoding normalization,
// port range checking (the fact is reported, the publisher validates),
// full host validation (net/url's acceptance stands in for it), interior
// non-tab C0 controls (net/url rejects them; where they sit in a host the
// browser rejects them too), and the file scheme's drive-letter quirks.
// Future WHATWG changes land here only when enumerated — the fixtures name
// the supported set, and drift against them fails the build.
//
// Classify never errors: every input lands in exactly one Class
// with the extractable semantic facts (Host, Scheme, Port, HasUserInfo,
// HasBackslash, HasTabOrNewline) alongside. The classification is
// deliberately judgment-free; each consumer applies its own fail direction
// over the same facts — a publisher drops what it cannot vouch for, an
// evidence gate hides what it cannot classify.
//
// Host evidence folds ASCII-only (a full-Unicode fold would launder
// homograph bytes such as U+0130 or U+212A into ASCII), and IsASCIIHost is
// the fail-closed companion gate for consumers matching hosts against known
// ASCII domains.
package urlform
