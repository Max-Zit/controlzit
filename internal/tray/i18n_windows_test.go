//go:build windows

package tray

import (
	"strings"
	"testing"
)

// Every language has every text, with the same placeholders.
func TestTexts(t *testing.T) {
	for lang, list := range texts {
		if len(list) != len(textKeys) {
			t.Fatalf("%s: %d texts, want %d", lang, len(list), len(textKeys))
		}
		for i, k := range textKeys {
			for _, p := range []string{"%s", "%d"} {
				if strings.Count(k, p) != strings.Count(list[i], p) {
					t.Errorf("%s: %q has other placeholders than %q", lang, list[i], k)
				}
			}
		}
	}
	if m := textsOf("sr"); m["Connected"] != "Povezan" || textsOf("xx")["Connected"] != "Connected" {
		t.Fatal("lookup")
	}
}
