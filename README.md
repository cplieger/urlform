# urlform

[![Go Reference](https://pkg.go.dev/badge/github.com/cplieger/urlform.svg)](https://pkg.go.dev/github.com/cplieger/urlform)
[![Go version](https://img.shields.io/github/go-mod/go-version/cplieger/urlform)](https://github.com/cplieger/urlform/blob/main/go.mod)
[![Test coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/urlform/badges/coverage.json)](https://github.com/cplieger/urlform/actions/workflows/coverage.yml)
[![Mutation](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/urlform/badges/mutation.json)](https://github.com/cplieger/urlform/issues?q=label%3Agremlins-tracker)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13723/badge)](https://www.bestpractices.dev/projects/13723)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/cplieger/urlform/badge)](https://scorecard.dev/viewer/?uri=github.com/cplieger/urlform)

> Classify raw untrusted URL strings by structural form: the browser-vs-net/url parse quirks that decide whether a string really carries a host

A standalone, stdlib-only Go library for programs that PUBLISH untrusted URLs to humans or extract the host a browser would navigate to. Go's `net/url` and a browser's WHATWG parser read several string shapes differently — a browser treats `\` as `/`, navigates `host/x` to `host`, resolves `//host/x` against the ambient scheme, and shows the post-`@` host for a `user@host` authority — so code that trusts the Go parse alone can publish a link whose real destination it never saw. `urlform` names those quirk classes once, extracts the browser-visible facts, and leaves the fail direction to each consumer.

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

- `Classify(raw string) Form` — total classification: every input lands in exactly one class, never an error. Whitespace-trimmed; backslashes canonicalized to slashes for the parse (the WHATWG reading) while `Trimmed` keeps the raw form a publisher would emit.
- `Form` — the extracted facts: `Class`, `Trimmed`, `Host` (lowercased ASCII-only fold; non-ASCII homograph bytes survive unfolded for fail-closed gates), `Scheme`, `Port` (extracted, deliberately not range-checked), `HasBackslash`, `HasUserInfo`, `HostUnrecoverable`.
- `Class` — `ClassEmpty`, `ClassMalformed`, `ClassAbsolute`, `ClassHiddenHost` (a scheme-bearing parse hiding host evidence: `https:/host/x`, `host:443/x`, `https://:443/x`), `ClassProtocolRelative` (`//host/x` and the ambiguous `///x`), `ClassSchemelessHost` (`host/x`, where a browser navigates to `host`), `ClassRelative` (`/x`).
- `IsASCIIHost(host string) bool` — the fail-closed companion gate: reports whether every byte is ASCII, so a homograph host (Cyrillic lookalikes, fold-laundering U+0130/U+212A) never string-matches a canonical domain. Consumers that must accept international hosts convert punycode explicitly instead of relaxing the gate.

## Design notes

- **Judgment-free classification.** The library names facts; policy stays with the caller. One consumer publishes-or-drops, another extracts-evidence-or-hides — both branch on the same classes and can never drift on what the string structurally is.
- **ASCII-only host fold.** `strings.ToLower` has ASCII-producing mappings (U+0130 LATIN CAPITAL LETTER I WITH DOT ABOVE folds to `i`, U+212A KELVIN SIGN to `k`) that would launder a homograph host into a matchable ASCII domain before any gate sees it. `Host` folds only A-Z, and `IsASCIIHost` rejects what survives.
- **Backslash canonicalization is read-only.** The parsed facts describe the WHATWG reading (`/\host/x` classifies protocol-relative), while `HasBackslash` lets a publisher that must emit the raw string reject it outright; the raw form is never rewritten.
- **Bounded and total.** No allocation scales with input beyond the trimmed copy; unparseable input is a class (`ClassMalformed`), not an error. Fuzz targets pin the exactly-one-class, nil-parse-only-for-no-facts, and metamorphic backslash invariants; a rapid property covers the canonicalization law on every PR.

## Disclaimer

This project is built with care and follows security best practices, but it is intended for personal / self-hosted use. No guarantees of fitness for production environments. Use at your own risk.

This project was built with AI-assisted tooling using [Claude Opus](https://www.anthropic.com/claude) and [Kiro](https://kiro.dev). The human maintainer defines architecture, supervises implementation, and makes all final decisions.

## License

GPL-3.0 — see [LICENSE](LICENSE).
