package urlform

import (
	"encoding/json"
	"os"
	"testing"
)

// fixtureCase is one row of testdata/whatwg-fixtures.json: an input plus the
// expected urlform facts, with the browser truth (wpt) and derivation notes
// carried as provenance. Expectations are hand-vetted against the WHATWG
// reading, never regenerated from the implementation - on mismatch,
// re-derive from the spec before touching the row.
type fixtureCase struct {
	Name              string `json:"name"`
	Input             string `json:"input"`
	Class             string `json:"class"`
	Host              string `json:"host"`
	Scheme            string `json:"scheme"`
	Port              string `json:"port"`
	WPT               string `json:"wpt"`
	Source            string `json:"source"`
	Note              string `json:"note"`
	HasUserInfo       bool   `json:"hasUserInfo"`
	HasBackslash      bool   `json:"hasBackslash"`
	HasTabOrNewline   bool   `json:"hasTabOrNewline"`
	HostUnrecoverable bool   `json:"hostUnrecoverable"`
}

// fixtureClasses maps the fixture file's class vocabulary onto the enum.
var fixtureClasses = map[string]Class{
	"empty":             ClassEmpty,
	"malformed":         ClassMalformed,
	"absolute":          ClassAbsolute,
	"hidden_host":       ClassHiddenHost,
	"protocol_relative": ClassProtocolRelative,
	"schemeless_host":   ClassSchemelessHost,
	"relative":          ClassRelative,
}

// TestClassifyWHATWGFixtures pins the covered divergence set against the
// curated conformance corpus (WPT-derived rows plus hand-derived address-bar
// and model-boundary rows). This is the external oracle the in-package
// fuzz/property tests cannot provide: they check the classifier against
// itself, this table checks it against the browser's documented reading.
//
// MAINTENANCE (for future agents): the corpus is a snapshot, and the WHATWG
// URL Standard moves (rarely). From time to time - a periodic review, or any
// session touching Classify - re-check the upstream sources for drift
// against the covered set: the spec's basic-parser preprocessing and scheme
// states (https://url.spec.whatwg.org) and fresh relevant cases in
// https://github.com/web-platform-tests/wpt url/resources/urltestdata.json
// (the provenance field in testdata/whatwg-fixtures.json records the commit
// this corpus was curated from). If a covered behavior changed or a new
// divergence family appeared, extend the corpus and re-derive expectations
// from the spec - never from the implementation. Adopting a conformant
// engine instead was evaluated and skipped (2026-07 judgement run, P2:
// nlnwa/whatwg-url - low drift risk did not justify 3 runtime deps against
// the stdlib-only contract); revisit only if a consumer needs full
// conformance. An additive IDNA-normalized host fact (P3, for spec-mapped
// lookalikes such as a fullwidth dot) was likewise skipped - revisit only
// when a consumer needs browser-destination equivalence for more than
// annotation accuracy (raw evidence + IsASCIIHost already fail closed).
func TestClassifyWHATWGFixtures(t *testing.T) {
	raw, err := os.ReadFile("testdata/whatwg-fixtures.json")
	if err != nil {
		t.Fatalf("read fixture corpus: %v", err)
	}
	var corpus struct {
		Provenance string        `json:"provenance"`
		Cases      []fixtureCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("decode fixture corpus: %v", err)
	}
	if len(corpus.Cases) == 0 {
		t.Fatal("fixture corpus is empty")
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			wantClass, ok := fixtureClasses[tc.Class]
			if !ok {
				t.Fatalf("fixture class %q is not in the enum vocabulary", tc.Class)
			}
			f := Classify(tc.Input)
			if f.Class != wantClass {
				t.Errorf("Class = %v, want %v (wpt: %s)", f.Class, wantClass, tc.WPT)
			}
			if f.Host != tc.Host {
				t.Errorf("Host = %q, want %q (wpt: %s)", f.Host, tc.Host, tc.WPT)
			}
			if f.Scheme != tc.Scheme {
				t.Errorf("Scheme = %q, want %q", f.Scheme, tc.Scheme)
			}
			if f.Port != tc.Port {
				t.Errorf("Port = %q, want %q", f.Port, tc.Port)
			}
			if f.HasUserInfo != tc.HasUserInfo {
				t.Errorf("HasUserInfo = %v, want %v", f.HasUserInfo, tc.HasUserInfo)
			}
			if f.HasBackslash != tc.HasBackslash {
				t.Errorf("HasBackslash = %v, want %v", f.HasBackslash, tc.HasBackslash)
			}
			if f.HasTabOrNewline != tc.HasTabOrNewline {
				t.Errorf("HasTabOrNewline = %v, want %v", f.HasTabOrNewline, tc.HasTabOrNewline)
			}
			if f.HostUnrecoverable != tc.HostUnrecoverable {
				t.Errorf("HostUnrecoverable = %v, want %v", f.HostUnrecoverable, tc.HostUnrecoverable)
			}
		})
	}
}
