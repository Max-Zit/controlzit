// i18n maintains the console's translation catalogs
// (internal/web/i18n/<lang>.json):
//
//	go run ./tools/i18n missing sr            texts without a translation, one per line
//	go run ./tools/i18n add sr file.tsv       merge "English<TAB>translation" lines
//	go run ./tools/i18n stale sr              catalog entries no longer used
//
// The texts are found like the catalog test finds them: {{.T "…"}} in the
// templates and the messages in the Go code that reach the page.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const dir = "internal/web"

func texts() map[string]bool {
	out := map[string]bool{}
	tmpl := regexp.MustCompile(`\.T "((?:[^"\\]|\\.)+)"`)
	files, _ := filepath.Glob(filepath.Join(dir, "templates", "*.html"))
	for _, f := range files {
		b, _ := os.ReadFile(f) // #nosec G304 -- repository files
		for _, m := range tmpl.FindAllStringSubmatch(string(b), -1) {
			out[unquote(m[1])] = true
		}
	}
	goMsg := regexp.MustCompile(`(?:translate\([^,\n]+, |uiErrf?\(|\.T\(|fail\(|redirect\(w, r, "[^"]*", |show\w+\(w, r, http\.Status\w+, [^"\n]*?|errors\.New\()"((?:[^"\\]|\\.)+)"`)
	for _, d := range []string{dir, "internal/store"} {
		gofiles, _ := filepath.Glob(filepath.Join(d, "*.go"))
		for _, f := range gofiles {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b, _ := os.ReadFile(f) // #nosec G304 -- repository files
			for _, m := range goMsg.FindAllStringSubmatch(string(b), -1) {
				out[unquote(m[1])] = true
			}
		}
	}
	out["the password must be between 12 and 256 characters"] = true
	return out
}

func unquote(s string) string { return strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(s) }

// catalog keeps the order of the file (new entries go to the end).
type catalog struct {
	keys []string
	m    map[string]string
}

func load(lang string) *catalog {
	c := &catalog{m: map[string]string{}}
	b, err := os.ReadFile(filepath.Join(dir, "i18n", lang+".json")) // #nosec G304 -- repository files
	if err != nil {
		return c
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if _, err := dec.Token(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for dec.More() {
		k, _ := dec.Token()
		var v string
		if err := dec.Decode(&v); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		key := k.(string)
		if _, dup := c.m[key]; !dup {
			c.keys = append(c.keys, key)
		}
		c.m[key] = v
	}
	return c
}

func (c *catalog) save(lang string) {
	var b bytes.Buffer
	b.WriteString("{\n")
	for i, k := range c.keys {
		kj, _ := json.Marshal(k)
		vj, _ := json.Marshal(c.m[k])
		b.WriteString("  " + string(unescape(kj)) + ": " + string(unescape(vj)))
		if i < len(c.keys)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	if err := os.WriteFile(filepath.Join(dir, "i18n", lang+".json"), b.Bytes(), 0o644); err != nil { // #nosec G306 -- repository file
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// unescape keeps <, > and & readable (json.Marshal escapes them for HTML).
func unescape(b []byte) []byte {
	return bytes.NewBufferString(strings.NewReplacer(`<`, "<", `>`, ">", `&`, "&").Replace(string(b))).Bytes()
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: i18n missing|stale LANG | add LANG FILE")
		os.Exit(2)
	}
	lang := os.Args[2]
	c := load(lang)
	switch os.Args[1] {
	case "missing":
		var out []string
		for k := range texts() {
			if c.m[k] == "" {
				out = append(out, k)
			}
		}
		sort.Strings(out)
		for _, k := range out {
			fmt.Println(k)
		}
	case "stale":
		t := texts()
		for _, k := range c.keys {
			if !t[k] {
				fmt.Println(k)
			}
		}
	case "add":
		f, err := os.Open(os.Args[3])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		n := 0
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), "\t")
			if !ok || k == "" || v == "" {
				continue
			}
			if _, had := c.m[k]; !had {
				c.keys = append(c.keys, k)
			}
			c.m[k] = v
			n++
		}
		c.save(lang)
		fmt.Printf("%d entries merged into %s\n", n, lang)
	}
}
