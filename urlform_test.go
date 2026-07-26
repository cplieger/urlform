package urlform

import (
	"net/url"
	"testing"
)

// TestClassify pins one example per structural class plus the
// backslash-canonicalization and host-extraction facts the two consumer
// fail directions branch on (publish-or-drop, extract-evidence-or-hide).
func TestClassify(t *testing.T) {
	tests := []struct {
		name              string
		raw               string
		wantClass         Class
		wantHost          string
		wantBackslash     bool
		wantTabOrNewline  bool
		wantUnrecoverable bool
	}{
		{name: "empty after trimming", raw: "   ", wantClass: ClassEmpty},
		{name: "unparseable control character", raw: "https://nyaa.si/\x7f", wantClass: ClassMalformed},
		{name: "digit-led first segment with colon is malformed", raw: "1a:b", wantClass: ClassMalformed},
		{name: "absolute with host", raw: " https://NYAA.si/view/1 ", wantClass: ClassAbsolute, wantHost: "nyaa.si"},
		{name: "non-http scheme still classifies absolute", raw: "ftp://animebytes.tv/x", wantClass: ClassAbsolute, wantHost: "animebytes.tv"},
		{name: "scheme-relative special form recovers its hidden host", raw: "https:/animebytes.tv/x", wantClass: ClassHiddenHost, wantHost: "animebytes.tv"},
		{name: "zero-slash special form recovers its hidden host", raw: "https:animebytes.tv/x", wantClass: ClassHiddenHost, wantHost: "animebytes.tv"},
		{name: "hidden-host recovery fails on an unparseable authority", raw: "https:/anime bytes@tv/x", wantClass: ClassHiddenHost, wantUnrecoverable: true},
		{name: "opaque host-as-scheme hides its host", raw: "animebytes.tv:443/x", wantClass: ClassHiddenHost},
		{name: "port-only authority hides its host", raw: "https://:443/x", wantClass: ClassHiddenHost},
		{name: "javascript scheme is hidden-host, not absolute", raw: "javascript:alert(1)", wantClass: ClassHiddenHost},
		{name: "non-special backslashes stay opaque, no fabricated host", raw: `non-special:\\opaque\x`, wantClass: ClassHiddenHost, wantBackslash: true},
		{name: "protocol-relative with host", raw: "//animebytes.tv/x", wantClass: ClassProtocolRelative, wantHost: "animebytes.tv"},
		{name: "three slashes are ambiguous protocol-relative without host", raw: "///animebytes.tv/x", wantClass: ClassProtocolRelative},
		{name: "backslash authority canonicalizes to protocol-relative", raw: `\\animebytes.tv/x`, wantClass: ClassProtocolRelative, wantHost: "animebytes.tv", wantBackslash: true},
		{name: "slash-backslash canonicalizes to protocol-relative", raw: `/\animebytes.tv/x`, wantClass: ClassProtocolRelative, wantHost: "animebytes.tv", wantBackslash: true},
		{name: "schemeless host recovers the authority", raw: "animebytes.tv/torrents.php?id=1", wantClass: ClassSchemelessHost, wantHost: "animebytes.tv"},
		{name: "query-only form is schemeless without evidence", raw: "?x:y", wantClass: ClassSchemelessHost},
		{name: "space before @ makes the authority reparse fail", raw: "foo bar@animebytes.tv/x", wantClass: ClassSchemelessHost, wantUnrecoverable: true},
		{name: "rooted relative path", raw: "/torrents.php?id=1", wantClass: ClassRelative},
		{name: "embedded tab is stripped before the parse", raw: "https://anime\tbytes.tv/x", wantClass: ClassAbsolute, wantHost: "animebytes.tv", wantTabOrNewline: true},
		{name: "embedded newlines reassemble the scheme", raw: "ht\ntps://animebytes.tv/x", wantClass: ClassAbsolute, wantHost: "animebytes.tv", wantTabOrNewline: true},
		{name: "edge C0 controls trim like the browser", raw: "\x00\x1fhttps://animebytes.tv/x\x1f ", wantClass: ClassAbsolute, wantHost: "animebytes.tv"},
		{name: "interior non-tab C0 control stays malformed", raw: "https://anime\x01bytes.tv/x", wantClass: ClassMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := Classify(tt.raw)
			if f.Class != tt.wantClass {
				t.Errorf("Class = %v, want %v", f.Class, tt.wantClass)
			}
			if f.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", f.Host, tt.wantHost)
			}
			if f.HasBackslash != tt.wantBackslash {
				t.Errorf("HasBackslash = %v, want %v", f.HasBackslash, tt.wantBackslash)
			}
			if f.HasTabOrNewline != tt.wantTabOrNewline {
				t.Errorf("HasTabOrNewline = %v, want %v", f.HasTabOrNewline, tt.wantTabOrNewline)
			}
			if f.HostUnrecoverable != tt.wantUnrecoverable {
				t.Errorf("HostUnrecoverable = %v, want %v", f.HostUnrecoverable, tt.wantUnrecoverable)
			}
		})
	}
}

// TestClassifySemanticFacts pins the positive extraction of the
// semantic facts a link publisher's gate keys its rejections on - Scheme,
// Port, and HasUserInfo - which the class-focused table never asserts
// non-zero:
// url.Parse folds the scheme to lowercase (an "HTTPS://" source reads
// "https"), the port string is extracted unvalidated (65536 passes through;
// range-checking is deliberately the consumer's job, per the Port doc), and
// a userinfo authority ("trusted@evil.example", the visual-spoofing vector)
// sets HasUserInfo on absolute and protocol-relative forms alike.
func TestClassifySemanticFacts(t *testing.T) {
	tests := []struct {
		name         string
		raw          string
		wantClass    Class
		wantHost     string
		wantScheme   string
		wantPort     string
		wantUserInfo bool
	}{
		{name: "uppercase scheme folds to lowercase", raw: "HTTPS://nyaa.si/x", wantClass: ClassAbsolute, wantHost: "nyaa.si", wantScheme: "https"},
		{name: "port extracted from absolute authority", raw: "https://nyaa.si:8080/x", wantClass: ClassAbsolute, wantHost: "nyaa.si", wantScheme: "https", wantPort: "8080"},
		{name: "userinfo spoof authority sets the flag", raw: "https://trusted@evil.example/x", wantClass: ClassAbsolute, wantHost: "evil.example", wantScheme: "https", wantUserInfo: true},
		{name: "out-of-range port passes through unvalidated", raw: "https://user:pass@animebytes.tv:65536/x", wantClass: ClassAbsolute, wantHost: "animebytes.tv", wantScheme: "https", wantPort: "65536", wantUserInfo: true},
		{name: "userinfo on a protocol-relative form", raw: "//user@animebytes.tv/x", wantClass: ClassProtocolRelative, wantHost: "animebytes.tv", wantUserInfo: true},
		{name: "userinfo recovered from a schemeless authority reparse", raw: "user@animebytes.tv/x", wantClass: ClassSchemelessHost, wantHost: "animebytes.tv", wantUserInfo: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := Classify(tt.raw)
			if f.Class != tt.wantClass {
				t.Errorf("Class = %v, want %v", f.Class, tt.wantClass)
			}
			if f.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", f.Host, tt.wantHost)
			}
			if f.Scheme != tt.wantScheme {
				t.Errorf("Scheme = %q, want %q", f.Scheme, tt.wantScheme)
			}
			if f.Port != tt.wantPort {
				t.Errorf("Port = %q, want %q", f.Port, tt.wantPort)
			}
			if f.HasUserInfo != tt.wantUserInfo {
				t.Errorf("HasUserInfo = %v, want %v", f.HasUserInfo, tt.wantUserInfo)
			}
		})
	}
}

// TestClassifyHomographHostsFailClosed pins the homograph contract
// between Classify's ASCII-only Host fold (asciiLower) and the
// fail-closed IsASCIIHost gate consumers key on: a host spelled with a
// fold-laundering codepoint (U+0130 LATIN CAPITAL LETTER I WITH DOT ABOVE ->
// ASCII 'i', U+212A KELVIN SIGN -> ASCII 'k' under strings.ToLower) must
// survive classification with its non-ASCII bytes intact so the gate rejects
// it - a full-Unicode fold here would launder the spoof into a canonical
// ASCII domain and hand every consumer an already-matchable Host.
func TestClassifyHomographHostsFailClosed(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "U+0130 dotted capital I, absolute form", raw: "https://an\u0130mebytes.tv/torrents.php?id=1"},
		{name: "U+0130 dotted capital I, schemeless form", raw: "an\u0130mebytes.tv/torrents.php?id=1"},
		{name: "U+212A kelvin sign, absolute form", raw: "https://rutrac\u212Aer.org/forum/viewtopic.php?t=1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := Classify(tt.raw)
			if f.Host == "" {
				t.Fatal("Host is empty, want the non-ASCII host evidence preserved")
			}
			if IsASCIIHost(f.Host) {
				t.Errorf("IsASCIIHost(%q) = true: the fold laundered the homograph bytes into ASCII", f.Host)
			}
		})
	}
}

// TestHostMatchesDomain pins the three unsafe readings a plain suffix test
// would accept (suffix confusion, parent-domain spoofing, empty DNS labels),
// the fail-closed handling of a degenerate host or domain, and the ASCII-only
// fold - including the homograph case, where the fold must NOT produce a match
// the IsASCIIHost gate exists to refuse.
func TestHostMatchesDomain(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		domain string
		want   bool
	}{
		{name: "exact match", host: "nyaa.si", domain: "nyaa.si", want: true},
		{name: "real subdomain", host: "sukebei.nyaa.si", domain: "nyaa.si", want: true},
		{name: "deep subdomain", host: "a.b.nyaa.si", domain: "nyaa.si", want: true},
		{name: "ascii case folds", host: "SukeBei.NYAA.si", domain: "nyaa.si", want: true},
		{name: "domain spelled in caps folds", host: "nyaa.si", domain: "NYAA.SI", want: true},

		{name: "suffix confusion without the separating dot", host: "evilnyaa.si", domain: "nyaa.si"},
		{name: "domain as a parent-spoofing prefix", host: "nyaa.si.evil.example", domain: "nyaa.si"},
		{name: "domain as an interior substring", host: "a.nyaa.si.b.example", domain: "nyaa.si"},
		{name: "leading empty label", host: ".nyaa.si", domain: "nyaa.si"},
		{name: "inner empty label", host: "a..nyaa.si", domain: "nyaa.si"},
		{name: "trailing root dot is the caller's to trim", host: "nyaa.si.", domain: "nyaa.si"},
		{name: "surrounding space is the caller's to trim", host: " nyaa.si", domain: "nyaa.si"},

		{name: "empty host", host: "", domain: "nyaa.si"},
		{name: "empty domain", host: "nyaa.si", domain: ""},
		{name: "both empty", host: "", domain: ""},
		{name: "malformed domain with a leading dot, matched exactly", host: ".nyaa.si", domain: ".nyaa.si"},
		{name: "malformed domain with an inner empty label", host: "a.nyaa..si", domain: "nyaa..si"},

		{name: "U+0130 homograph host cannot fold into the domain", host: "an\u0130mebytes.tv", domain: "animebytes.tv"},
		{name: "U+212A homograph host cannot fold into the domain", host: "rutrac\u212Aer.org", domain: "rutracker.org"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HostMatchesDomain(tt.host, tt.domain); got != tt.want {
				t.Errorf("HostMatchesDomain(%q, %q) = %v, want %v", tt.host, tt.domain, got, tt.want)
			}
		})
	}
}

// TestRawQueryNames pins the raw reading's whole contract: the ';' split that
// url.ParseQuery's wholesale pair drop creates the need for, percent-decoding,
// the raw-name fallback for an undecodable escape, order preservation, and the
// documented no-'?'-trimming boundary.
func TestRawQueryNames(t *testing.T) {
	tests := []struct {
		name     string
		rawQuery string
		want     []string
	}{
		{name: "empty query yields nothing", rawQuery: ""},
		{name: "single pair", rawQuery: "id=1", want: []string{"id"}},
		{name: "ampersand separated", rawQuery: "id=1&torrentid=2", want: []string{"id", "torrentid"}},
		{
			name:     "semicolon separated - the pair url.ParseQuery drops wholesale",
			rawQuery: "apikey=SECRET;foo=x",
			want:     []string{"apikey", "foo"},
		},
		{name: "mixed separators", rawQuery: "a=1;b=2&c=3", want: []string{"a", "b", "c"}},
		{name: "empty fields skipped", rawQuery: "&&a=1;;&b=2&", want: []string{"a", "b"}},
		{name: "bare flag parameter yields its whole field", rawQuery: "torrentid", want: []string{"torrentid"}},
		{name: "value containing a separator does not leak into a name", rawQuery: "id=1;2", want: []string{"id", "2"}},
		{name: "percent-encoded name decodes", rawQuery: "torrent%69d=1", want: []string{"torrentid"}},
		{name: "plus in a name decodes to a space", rawQuery: "api+key=1", want: []string{"api key"}},
		{
			name:     "undecodable escape yields the raw name rather than vanishing",
			rawQuery: "api%zzkey=1&ok=2",
			want:     []string{"api%zzkey", "ok"},
		},
		{
			name:     "leading '?' is part of the first name, not trimmed",
			rawQuery: "?apikey=1&b=2",
			want:     []string{"?apikey", "b"},
		},
		{name: "duplicate names are reported once each", rawQuery: "id=1&id=2", want: []string{"id", "id"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for name := range RawQueryNames(tt.rawQuery) {
				got = append(got, name)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("RawQueryNames(%q) = %q, want %q", tt.rawQuery, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("RawQueryNames(%q) = %q, want %q", tt.rawQuery, got, tt.want)
				}
			}
		})
	}
}

// TestRawQueryNamesStopsOnBreak pins the iterator contract a partial consumer
// depends on: a caller that breaks out (every gate does, on its first match)
// stops the walk instead of running it to completion.
func TestRawQueryNamesStopsOnBreak(t *testing.T) {
	visited := 0
	for range RawQueryNames("a=1&b=2&c=3") {
		visited++
		break
	}
	if visited != 1 {
		t.Errorf("visited %d names after break, want 1", visited)
	}
}

// TestRawQueryNamesSupersetOfParsedView is the cross-check that states WHY the
// raw walk exists: for a query whose pairs are all well-formed the two
// readings agree, and for the semicolon-smuggled query the parsed view loses a
// name the raw walk still reports.
func TestRawQueryNamesSupersetOfParsedView(t *testing.T) {
	const smuggled = "apikey=SECRET;foo=x"
	parsed, err := url.ParseQuery(smuggled)
	if err == nil {
		if _, ok := parsed["apikey"]; ok {
			t.Fatalf("url.ParseQuery(%q) kept apikey; the premise of the raw walk no longer holds", smuggled)
		}
	}
	found := false
	for name := range RawQueryNames(smuggled) {
		if name == "apikey" {
			found = true
		}
	}
	if !found {
		t.Errorf("RawQueryNames(%q) did not report apikey", smuggled)
	}
}
