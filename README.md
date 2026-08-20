# urlform

[![Go Reference](https://pkg.go.dev/badge/github.com/cplieger/urlform.svg)](https://pkg.go.dev/github.com/cplieger/urlform)
[![Go version](https://img.shields.io/github/go-mod/go-version/cplieger/urlform)](https://github.com/cplieger/urlform/blob/main/go.mod)
[![Test coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/urlform/badges/coverage.json)](https://github.com/cplieger/urlform/actions/workflows/coverage.yml)
[![Mutation](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/urlform/badges/mutation.json)](https://github.com/cplieger/urlform/issues?q=label%3Agremlins-tracker)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13723/badge)](https://www.bestpractices.dev/projects/13723)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/cplieger/urlform/badge)](https://scorecard.dev/viewer/?uri=github.com/cplieger/urlform)

> Classify raw untrusted URL strings by structural form: the browser-vs-net/url parse quirks that decide whether a string really carries a host

A standalone, stdlib-only Go library for programs that PUBLISH untrusted URLs to humans or extract the host a browser would navigate to. Go's `net/url` and a browser's WHATWG parser read several string shapes differently. A browser strips embedded tabs and newlines (`https://anime\tbytes.tv` navigates to animebytes.tv), treats `\` as `/`, reads an authority through any run of slashes after `https:`, navigates `host/x` to `host`, resolves `//host/x` against the ambient scheme, and shows the post-`@` host for a `user@host` authority. Code that trusts the Go parse alone can publish a link whose real destination it never saw. `urlform` names those quirk classes once, extracts the browser-visible facts, and leaves the fail direction to each consumer.

The covered divergence set is bounded and enumerated (see the package docs), pinned by a conformance-fixture corpus derived from [web-platform-tests](https://github.com/web-platform-tests/wpt); urlform is a classifier with the WHATWG readings layered on, not a full WHATWG parser. Out of scope by design: IDNA/punycode mapping (non-ASCII host evidence survives raw for the fail-closed gates), percent-encoding normalization, and port range checks (the facts are reported; the publisher validates).

This is deliberately NOT an SSRF guard. Validating a URL your own process will fetch answers to `net/url` and the dialer (the parser of record for the request); use an SSRF library for that. `urlform` models classify-for-publish, where the parser of record is the reader's browser.

## Install

```sh
go get github.com/cplieger/urlform@latest
```

## Usage

```go
f := urlform.Classify(raw)
switch f.Class {
case urlform.ClassAbsolute:
	if f.HasUserInfo || f.HasBackslash {
		// visual-spoofing vectors a publisher typically rejects
		return "", false
	}
	return f.Trimmed, true
case urlform.ClassRelative:
	return base + f.Trimmed, true // rooted path, no host of its own
default:
	return "", false // protocol-relative, schemeless, hidden-host, malformed
}
```

Host evidence for matching against known domains:

```go
f := urlform.Classify(raw)
if f.Host == "" || !urlform.IsASCIIHost(f.Host) {
	// no host evidence, or homograph territory: fail closed
	return nil, false
}
for domain, tracker := range knownDomains {
	if urlform.HostMatchesDomain(f.Host, domain) {
		return tracker, true
	}
}
return nil, false
```

Names of an untrusted raw query, without the evadable parsed view:

```go
for name := range urlform.RawQueryNames(u.RawQuery) {
	if isCredentialParam(name) { // the caller's predicate, and its fail direction
		return true
	}
}
```

Same walk when the predicate needs the value too:

```go
for name, value := range urlform.RawQueryPairs(u.RawQuery) {
	if isCredentialParam(name) && value != "" {
		return redact(name) // a parameter carrying nothing is not a leak
	}
}
```

Two spellings of one destination, compared:

```go
f := urlform.Classify(raw)
if p := f.NormalizedPath(); p == "" || !strings.HasPrefix(p, "/beat/") {
	return errOutsideNamespace // "/beat/api/../ghost" resolves out of the namespace
}
```

## API

- `Classify(raw string) Form`: total classification. Every input lands in exactly one class, never an error; the WHATWG input preprocessing and backslash canonicalization run first (see Design notes).
- `Form`: the extracted facts: `Class`, `Trimmed` (preprocessed, emit-safe), `Host` (ASCII-only lowercase fold), `Scheme`, `Port` (extracted, deliberately not range-checked), `HasBackslash`, `HasTabOrNewline` (a whitespace-smuggling attempt was removed), `HasUserInfo`, `HostUnrecoverable`.
- `Class`: `ClassEmpty`, `ClassMalformed`, `ClassAbsolute`, `ClassHiddenHost` (a scheme-bearing parse hiding host evidence; for the authority-carrying special schemes the browser's reading is recovered into the facts, so `https:/host/x` and `https:host/x` expose `host`, while `host:443/x` and `https://:443/x` stay evidence-free like the browser's own reading), `ClassProtocolRelative` (`//host/x` and the ambiguous `///x`), `ClassSchemelessHost` (`host/x`, where a browser navigates to `host`), `ClassRelative` (`/x`).
- `(*Form).NormalizedPath() string`: the path a browser resolves for the classified string, dot segments removed (`/view/1/../2` reads `/view/2`), for comparing or displaying two spellings of one destination. Rooted; resolved by net/url's own RFC 3986 §5.2.4 resolution, so repeated slashes are preserved exactly as the WHATWG parser preserves them (a consumer wanting net/http's `ServeMux` rewrite is asking about Go's router, not the reader's browser). Empty when no browser-resolvable path exists: no facts at all, a failed authority reparse, an opaque-path reading (`javascript:alert(1)`), or a `//`-leading form whose authority region no parse separated.
- `IsASCIIHost(host string) bool`: the fail-closed companion gate. It reports whether every byte is ASCII, so a homograph host (Cyrillic lookalikes, fold-laundering U+0130/U+212A) never string-matches a canonical domain. Consumers that must accept international hosts convert punycode explicitly instead of relaxing the gate.
- `FoldHostASCII(host string) string`: the ASCII-only case fold `Form.Host` applies, exported for consumers holding host evidence from elsewhere (a configured domain, a header, a host parsed directly). Folds only A-Z, which is the point: `strings.ToLower` maps U+0130 to `i` and U+212A to `k`, and `strings.EqualFold` reads U+017F as `s`, so either one launders a homograph into a canonical ASCII domain before the gate above can reject it.
- `EqualASCIIFold(a, b string) bool`: the same rule as a comparison, for the ASCII protocol tokens that are **not** hosts — a URL path token, a query parameter name — which a structural gate reads out of an untrusted URL and where calling a host fold would misname the operation. `strings.EqualFold` accepts a U+212A KELVIN SIGN spelling of `apikey` and a U+017F LONG S spelling of `/torrents.php`, and a `strings.ToLower` comparison accepts a U+0130 DOTTED CAPITAL I spelling of `torrentid`: each hands a gate a match on bytes no server routes as that token. This comparison cannot — a string that is not ASCII never equals an ASCII token.
- `HostMatchesDomain(host, domain string) bool`: the matcher the gate above leads to. Reports whether the host equals the domain or is a real dot-delimited subdomain of it, refusing the three readings a plain suffix test accepts: suffix confusion (`evilnyaa.si`), parent-domain spoofing (`nyaa.si.evil.example`), and empty DNS labels (`.nyaa.si`, `a..nyaa.si`). Fail-closed on an empty or empty-labelled argument; folds ASCII-only. Trimming surrounding space and the trailing root dot stays the caller's.
- `RawQueryNames(rawQuery string) iter.Seq[string]`: the percent-decoded parameter names of a raw query (`u.RawQuery`'s shape, no leading `?`), split on both `&` and `;`. `url.ParseQuery` drops a malformed pair wholesale, so an unescaped semicolon deletes the pair it sits in while the bytes still ride every request and log line; this walk is the strict superset a gate can't be evaded on. Judgment-free: it reports names and takes no view of them, because consumers need opposite fail directions over the same walk.
- `RawQueryPairs(rawQuery string) iter.Seq2[string, string]`: the same walk carrying each name's VALUE, for the consumers whose predicate reads it (a credential warning that must not fire on an empty parameter, a redaction pass locating the secret text). Name and value are percent-decoded independently, each falling back to its raw text, so one malformed half never hides the other.

## Design notes

- **Judgment-free classification.** The library names facts; policy stays with the caller. One consumer publishes-or-drops, another extracts-evidence-or-hides; both branch on the same classes and can never drift on what the string structurally is.
- **WHATWG input preprocessing.** Browsers delete embedded tab/newline wherever they appear and trim C0-control/space edges before parsing (the same hardening CPython adopted for CVE-2022-0391), so a string-level gate that skips this reads a different URL than the reader's browser will. `Classify` runs both steps first; `HasTabOrNewline` records a removed smuggling attempt, and `Trimmed` is already clean to emit. Edge trimming is deliberately widened to all Unicode whitespace (an NBSP-wrapped link still classifies; over-trimming errs fail-safe).
- **ASCII-only case folding, one byte rule.** `strings.ToLower` has ASCII-producing mappings (U+0130 LATIN CAPITAL LETTER I WITH DOT ABOVE folds to `i`, U+212A KELVIN SIGN to `k`) and `strings.EqualFold` folds simple-case orbits (U+212A to `k`, U+017F LATIN SMALL LETTER LONG S to `s`), so either one launders a homograph into a matchable ASCII host or protocol token before any gate sees it. Note the two admit different inputs and are not interchangeable: `strings.ToLower` accepts the U+0130 spelling that `strings.EqualFold` refuses, and `strings.EqualFold` accepts the U+017F spelling that `strings.ToLower` refuses. `Host`, `FoldHostASCII`, `HostMatchesDomain`, `EqualASCIIFold` and the special-scheme test behind backslash canonicalization all read a single A-Z byte rule instead, so they can never disagree, and `IsASCIIHost` rejects the host evidence that survives. The rule is defined on bytes rather than runes deliberately: mapping runes would rewrite an invalid UTF-8 byte to U+FFFD, laundering distinct non-ASCII evidence onto one canonical spelling in a fold whose job is to leave it intact. Because that rule reads no Unicode table, no Unicode revision can change which bytes it folds; the package's only Unicode-table read is the edge trim's whitespace set.
- **Backslash canonicalization is read-only and spec-scoped.** The parsed facts describe the WHATWG reading (`/\host/x` classifies protocol-relative) for special-scheme and schemeless forms ahead of the query; for a non-special scheme a backslash is an ordinary character, and rewriting it would fabricate host evidence a browser never sees. `HasBackslash` lets a publisher that must emit the raw string reject it outright; the raw form is never rewritten.
- **Dot-segment resolution reads the decoded path.** `NormalizedPath` resolves over the decoded path, which is what makes a percent-encoded dot segment (`/a/%2e%2e/b`) resolve like the literal one — matching the WHATWG parser, whose single- and double-dot segment definitions include the `%2e` spellings. The same decoding reads a percent-encoded slash as a separator, which the parser does not, so a caller whose comparison must keep `%2F` distinct compares the escaped path itself. That is the same boundary as the rest of the contract: the facts model the browser's structural reading, not percent-encoding normalization.
- **Bounded and total.** Allocation is bounded and linear in the input, and unparseable input is a class (`ClassMalformed`), not an error.

## Disclaimer

This project is built with care and follows security best practices, but it is intended for personal / self-hosted use. No guarantees of fitness for production environments. Use at your own risk.

This project was built with AI-assisted tooling using [Claude](https://claude.com), [GPT](https://openai.com), and [Kiro](https://kiro.dev). The human maintainer defines architecture, supervises implementation, and makes all final decisions.

## License

Apache-2.0. See [LICENSE](LICENSE).
