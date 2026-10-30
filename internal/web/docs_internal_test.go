package web

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// Every page of the guide exists in every language, and a translation keeps
// the anchors (#id) of the English page, so links into a page work in all
// languages.
func TestDocsComplete(t *testing.T) {
	id := regexp.MustCompile(`\bid="([^"]+)"`)
	for _, l := range Languages {
		for _, p := range DocPages {
			b, err := fs.ReadFile(docsFS, "docs/"+l.Code+"/"+p.Slug+".html")
			if err != nil {
				t.Errorf("%s: page %s is missing", l.Code, p.Slug)
				continue
			}
			en, _ := fs.ReadFile(docsFS, "docs/en/"+p.Slug+".html")
			want := strings.Join(flat(id.FindAllStringSubmatch(string(en), -1)), " ")
			if got := strings.Join(flat(id.FindAllStringSubmatch(string(b), -1)), " "); got != want {
				t.Errorf("%s/%s: anchors %q, English has %q", l.Code, p.Slug, got, want)
			}
			if !utf8.Valid(b) {
				t.Errorf("%s/%s is not valid UTF-8", l.Code, p.Slug)
			}
			if strings.Contains(string(b), "{{") {
				t.Errorf("%s/%s contains template syntax", l.Code, p.Slug)
			}
		}
	}
}

func flat(m [][]string) []string {
	var out []string
	for _, x := range m {
		out = append(out, x[1])
	}
	return out
}

func TestDocsSearch(t *testing.T) {
	hits := searchDocs("en", "enrollment code")
	if len(hits) == 0 {
		t.Fatal("no hits for 'enrollment code'")
	}
	if !strings.Contains(string(hits[0].Snippet), "<mark>") {
		t.Errorf("snippet without a mark: %s", hits[0].Snippet)
	}
	if h := searchDocs("en", "<script>"); len(h) != 0 && strings.Contains(string(h[0].Snippet), "<script>") {
		t.Error("snippet not escaped")
	}
}
