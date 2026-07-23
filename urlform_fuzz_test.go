package urlform

import (
	"strings"
	"testing"
)

// FuzzClassify fuzzes the raw-URL structural classifier over untrusted
// upstream link strings with bounded-output and metamorphic invariants (never a
// reimplementation of the class rules): every input lands in exactly one enum
// class; the private parsed object is nil exactly for the two no-facts
// classes (Empty, Malformed) and the exported semantic facts (Scheme, Port,
// HasUserInfo) are zero whenever it is; Host carries no ASCII uppercase (the
// fold is ASCII-only by design, so non-ASCII homograph bytes survive to the
// fail-closed IsASCIIHost gates downstream) and is empty for every class
// that carries no extractable host evidence (Empty, Malformed, Relative)
// while an absolute form always carries its host; HostUnrecoverable marks
// only the two authority-reparse classes (SchemelessHost, HiddenHost);
// Trimmed carries neither surrounding whitespace nor any embedded
// tab/newline (the WHATWG preprocessing); removing every ASCII tab/newline
// from the input before classifying changes nothing but the
// HasTabOrNewline flag (the spec removes them wherever they appear); and
// re-classifying the already-preprocessed string reproduces the same facts
// with the flag cleared.
func FuzzClassify(f *testing.F) {
	f.Add("   ")
	f.Add("https://nyaa.si/view/1")
	f.Add("https://nyaa.si/\x7f")
	f.Add("https:/animebytes.tv/x")
	f.Add("https:animebytes.tv/x")
	f.Add("https://anime\tbytes.tv/x")
	f.Add("ht\ntps://animebytes.tv/x")
	f.Add("\x00\x1fhttps://animebytes.tv/x\x1f ")
	f.Add("animebytes.tv:443/x")
	f.Add("https://:443/x")
	f.Add("javascript:alert(1)")
	f.Add(`non-special:\\opaque\x`)
	f.Add("//animebytes.tv/x")
	f.Add("///animebytes.tv/x")
	f.Add(`\\animebytes.tv/x`)
	f.Add(`/\animebytes.tv/x`)
	f.Add("animebytes.tv/torrents.php?id=1")
	f.Add("ANIMEBYTES.TV/torrents.php?id=1")
	f.Add("https://an\u0130mebytes.tv/x")
	f.Add("?x:y")
	f.Add("foo bar@animebytes.tv/x")
	f.Add("https:/anime bytes@tv/x")
	f.Add("/torrents.php?id=1")
	f.Add("1a:b")
	f.Add("https://h/p\\q?a\\b#c\\d")
	f.Fuzz(func(t *testing.T, raw string) {
		fm := Classify(raw)

		switch fm.Class {
		case ClassEmpty, ClassMalformed, ClassAbsolute, ClassHiddenHost,
			ClassProtocolRelative, ClassSchemelessHost, ClassRelative:
		default:
			t.Errorf("Class = %v outside the enum for %q", fm.Class, raw)
		}
		if fm.Trimmed != strings.TrimSpace(fm.Trimmed) {
			t.Errorf("Trimmed = %q still carries surrounding whitespace", fm.Trimmed)
		}
		if strings.ContainsAny(fm.Trimmed, "\t\n\r") {
			t.Errorf("Trimmed = %q still carries embedded tab/newline after the preprocessing", fm.Trimmed)
		}
		if gotNil := fm.parsed == nil; gotNil != (fm.Class == ClassEmpty || fm.Class == ClassMalformed) {
			t.Errorf("parsed nil = %v for class %v, want nil exactly for Empty/Malformed", gotNil, fm.Class)
		}
		if fm.parsed == nil && (fm.Scheme != "" || fm.Port != "" || fm.HasUserInfo) {
			t.Errorf("Scheme=%q Port=%q HasUserInfo=%v without a parse for %q, want zero facts", fm.Scheme, fm.Port, fm.HasUserInfo, raw)
		}
		if fm.Host != asciiLower(fm.Host) {
			t.Errorf("Host = %q carries ASCII uppercase; the ASCII-only fold must apply", fm.Host)
		}
		switch fm.Class {
		case ClassEmpty, ClassMalformed, ClassRelative:
			if fm.Host != "" {
				t.Errorf("Host = %q for class %v, want empty (the class carries no extractable host evidence)", fm.Host, fm.Class)
			}
		case ClassAbsolute:
			if fm.Host == "" {
				t.Errorf("Host empty for ClassAbsolute input %q", raw)
			}
		}
		if fm.HostUnrecoverable && fm.Class != ClassSchemelessHost && fm.Class != ClassHiddenHost {
			t.Errorf("HostUnrecoverable set on class %v, want only the authority-reparse classes", fm.Class)
		}

		// The WHATWG tab/newline removal is position-independent: stripping
		// the bytes from the raw input up front must yield identical facts,
		// with only the smuggling flag differing.
		stripped := Classify(strings.Map(dropTabOrNewline, raw))
		if stripped.HasTabOrNewline {
			t.Errorf("Classify of a tab/newline-free input set HasTabOrNewline for %q", raw)
		}
		if stripped.Class != fm.Class || stripped.Host != fm.Host || stripped.Trimmed != fm.Trimmed ||
			stripped.Scheme != fm.Scheme || stripped.Port != fm.Port || stripped.HasUserInfo != fm.HasUserInfo ||
			stripped.HasBackslash != fm.HasBackslash || stripped.HostUnrecoverable != fm.HostUnrecoverable {
			t.Errorf("Classify(%q) diverges from its tab/newline-stripped form on facts other than HasTabOrNewline", raw)
		}

		// Stability: the preprocessed string re-classifies to the same
		// facts, with the preprocessing flag cleared (nothing left to strip).
		again := Classify(fm.Trimmed)
		if again.HasTabOrNewline {
			t.Errorf("re-classifying Trimmed %q set HasTabOrNewline", fm.Trimmed)
		}
		if again.Class != fm.Class || again.Host != fm.Host || again.Trimmed != fm.Trimmed ||
			again.Scheme != fm.Scheme || again.Port != fm.Port || again.HasUserInfo != fm.HasUserInfo ||
			again.HasBackslash != fm.HasBackslash || again.HostUnrecoverable != fm.HostUnrecoverable {
			t.Errorf("Classify(%q) is not stable on its own Trimmed form %q", raw, fm.Trimmed)
		}
	})
}
