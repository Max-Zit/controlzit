package web

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// uiTexts collects the English texts of the console: template {{.T "…"}}
// calls and the messages in the Go code that reach the page.
func uiTexts(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	tmpl := regexp.MustCompile(`\.T "((?:[^"\\]|\\.)+)"`)
	files, _ := filepath.Glob("templates/*.html")
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range tmpl.FindAllStringSubmatch(string(b), -1) {
			out[unescapeText(m[1])] = true
		}
	}
	// Go: messages passed to translate/T/redirect/show*/fail and errors.
	goMsg := regexp.MustCompile(`(?:translate\([^,\n]+, |uiErrf?\(|\.T\(|fail\(|redirect\(w, r, "[^"]*", |show\w+\(w, r, http\.Status\w+, [^"\n]*?|errors\.New\()"((?:[^"\\]|\\.)+)"`)
	for _, dir := range []string{".", "../store"} {
		gofiles, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range gofiles {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b, _ := os.ReadFile(f)
			for _, m := range goMsg.FindAllStringSubmatch(string(b), -1) {
				if m[1] != "" {
					out[unescapeText(m[1])] = true
				}
			}
		}
	}
	// Composed in other packages.
	out["the password must be between 12 and 256 characters"] = true
	return out
}

// unescapeText turns a quoted text from the source into the text itself.
func unescapeText(s string) string { return strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(s) }

func TestCatalogsComplete(t *testing.T) {
	texts := uiTexts(t)
	verb := regexp.MustCompile(`%[dsv]`)
	for _, l := range Languages[1:] {
		var missing []string
		for k := range texts {
			if catalogs[l.Code][k] == "" {
				missing = append(missing, k)
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Errorf("%s: %d texts without a translation:\n%s", l.Code, len(missing), strings.Join(missing, "\n"))
		}
		// Format verbs must survive the translation.
		for k, v := range catalogs[l.Code] {
			if strings.Join(verb.FindAllString(k, -1), "") != strings.Join(verb.FindAllString(v, -1), "") {
				t.Errorf("%s: format verbs differ: %q → %q", l.Code, k, v)
			}
		}
	}
}

func TestTemplatesParse(t *testing.T) {
	m, err := loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	if len(m) < 15 {
		t.Fatalf("only %d pages", len(m))
	}
}

func TestCatalogNoDuplicateKeys(t *testing.T) {
	raw, err := i18nFS.ReadFile("i18n/sr.json")
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if _, err := d.Token(); err != nil { // {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for d.More() {
		k, err := d.Token()
		if err != nil {
			t.Fatal(err)
		}
		if seen[k.(string)] {
			t.Errorf("duplicate key %q", k)
		}
		seen[k.(string)] = true
		if _, err := d.Token(); err != nil { // value
			t.Fatal(err)
		}
	}
}
