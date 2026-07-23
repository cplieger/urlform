package urlform

import "testing"

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
