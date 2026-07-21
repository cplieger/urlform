// Package urlform classifies the structural form of a raw, untrusted URL
// string — specifically the forms where a BROWSER's reading (the WHATWG URL
// parser) diverges from net/url's: backslash authorities, protocol-relative
// and schemeless-host forms, hidden-host parses, userinfo spoofing.
//
// The parser of record is the divide that places this package. Validating a
// URL the PROCESS will fetch is a different concern (there net/url and the
// dialer are authoritative; use an SSRF guard). urlform models
// classify-for-PUBLISH: the string is destined for a human whose browser
// will read it, and the quirk classes exist precisely where that reading and
// Go's disagree — a browser treats '\' as '/', navigates "host/x" to host,
// and resolves "//host/x" against the ambient scheme, while net/url parses a
// rooted path, a bare path, and a hostless reference.
//
// Classify never errors: every input lands in exactly one Class
// with the extractable semantic facts (Host, Scheme, Port, HasUserInfo,
// HasBackslash) alongside. The classification is deliberately judgment-free;
// each consumer applies its own fail direction over the same facts — a
// publisher drops what it cannot vouch for, an evidence gate hides what it
// cannot classify.
//
// Host evidence folds ASCII-only (a full-Unicode fold would launder
// homograph bytes such as U+0130 or U+212A into ASCII), and IsASCIIHost is
// the fail-closed companion gate for consumers matching hosts against known
// ASCII domains.
package urlform
