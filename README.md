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
return domainTable[f.Host]
```

## API

- `Classify(raw string) Form`: total classification. Every input lands in exactly one class, never an error; the WHATWG input preprocessing and backslash canonicalization run first (see Design notes).
- `Form`: the extracted facts: `Class`, `Trimmed` (preprocessed, emit-safe), `Host` (ASCII-only lowercase fold), `Scheme`, `Port` (extracted, deliberately not range-checked), `HasBackslash`, `HasTabOrNewline` (a whitespace-smuggling attempt was removed), `HasUserInfo`, `HostUnrecoverable`.
- `Class`: `ClassEmpty`, `ClassMalformed`, `ClassAbsolute`, `ClassHiddenHost` (a scheme-bearing parse hiding host evidence; for the authority-carrying special schemes the browser's reading is recovered into the facts, so `https:/host/x` and `https:host/x` expose `host`, while `host:443/x` and `https://:443/x` stay evidence-free like the browser's own reading), `ClassProtocolRelative` (`//host/x` and the ambiguous `///x`), `ClassSchemelessHost` (`host/x`, where a browser navigates to `host`), `ClassRelative` (`/x`).
- `IsASCIIHost(host string) bool`: the fail-closed companion gate. It reports whether every byte is ASCII, so a homograph host (Cyrillic lookalikes, fold-laundering U+0130/U+212A) never string-matches a canonical domain. Consumers that must accept international hosts convert punycode explicitly instead of relaxing the gate.

## Design notes

- **Judgment-free classification.** The library names facts; policy stays with the caller. One consumer publishes-or-drops, another extracts-evidence-or-hides; both branch on the same classes and can never drift on what the string structurally is.
- **WHATWG input preprocessing.** Browsers delete embedded tab/newline wherever they appear and trim C0-control/space edges before parsing (the same hardening CPython adopted for CVE-2022-0391), so a string-level gate that skips this reads a different URL than the reader's browser will. `Classify` runs both steps first; `HasTabOrNewline` records a removed smuggling attempt, and `Trimmed` is already clean to emit. Edge trimming is deliberately widened to all Unicode whitespace (an NBSP-wrapped link still classifies; over-trimming errs fail-safe).
- **ASCII-only host fold.** `strings.ToLower` has ASCII-producing mappings (U+0130 LATIN CAPITAL LETTER I WITH DOT ABOVE folds to `i`, U+212A KELVIN SIGN to `k`) that would launder a homograph host into a matchable ASCII domain before any gate sees it. `Host` folds only A-Z, and `IsASCIIHost` rejects what survives.
- **Backslash canonicalization is read-only and spec-scoped.** The parsed facts describe the WHATWG reading (`/\host/x` classifies protocol-relative) for special-scheme and schemeless forms ahead of the query; for a non-special scheme a backslash is an ordinary character, and rewriting it would fabricate host evidence a browser never sees. `HasBackslash` lets a publisher that must emit the raw string reject it outright; the raw form is never rewritten.
- **Bounded and total.** Allocation is bounded and linear in the input, and unparseable input is a class (`ClassMalformed`), not an error.

## Disclaimer

This project is built with care and follows security best practices, but it is intended for personal / self-hosted use. No guarantees of fitness for production environments. Use at your own risk.

This project was built with AI-assisted tooling using [Claude](https://claude.com), [GPT](https://openai.com), and [Kiro](https://kiro.dev). The human maintainer defines architecture, supervises implementation, and makes all final decisions.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
