package urlform

import (
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// TestClassifyBackslashCanonicalizationProperty is the every-PR
// property net over the Classify untrusted-URL boundary (the generated
// fuzz exploration runs only in the weekly bounded job): a browser-style
// backslash authority must classify to the same public semantic facts as its
// slash-canonical form, pinning the backslash canonicalization that keeps
// host evidence recoverable.
func TestClassifyBackslashCanonicalizationProperty(t *testing.T) {
	type semanticFacts struct {
		Host              string
		Scheme            string
		Port              string
		Class             Class
		HasUserInfo       bool
		HostUnrecoverable bool
	}
	suffix := rapid.StringMatching(`[A-Za-z0-9._~/?&=%+-]{0,64}`)

	rapid.Check(t, func(t *rapid.T) {
		raw := `\\animebytes.tv/` + suffix.Draw(t, "suffix")
		canonical := strings.ReplaceAll(raw, `\`, "/")

		rawForm := Classify(raw)
		got := semanticFacts{rawForm.Host, rawForm.Scheme, rawForm.Port, rawForm.Class, rawForm.HasUserInfo, rawForm.HostUnrecoverable}
		slashForm := Classify(canonical)
		want := semanticFacts{slashForm.Host, slashForm.Scheme, slashForm.Port, slashForm.Class, slashForm.HasUserInfo, slashForm.HostUnrecoverable}
		if got != want {
			t.Errorf("Classify(%q) semantic facts = %+v, want canonical-slash facts %+v", raw, got, want)
		}
	})
}
