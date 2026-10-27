package web

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// Matching installed programs to vulnerability data: which programs NVD
// knows by their CPE name, version comparison and CVSS v3 scores.

// vulnApp is a Windows program NVD lists under a CPE vendor and product.
type vulnApp struct {
	re      *regexp.Regexp // on the program's name; a group, if any, is its version
	vendor  string
	product string // as in the CPE (with its escapes)
}

// vulnCatalog lists common programs; more specific names come first.
var vulnCatalog = []vulnApp{
	{regexp.MustCompile(`^Google Chrome$`), "google", "chrome"},
	{regexp.MustCompile(`^Mozilla Firefox ESR\b`), "mozilla", "firefox_esr"},
	{regexp.MustCompile(`^Mozilla Firefox\b`), "mozilla", "firefox"},
	{regexp.MustCompile(`^Mozilla Thunderbird\b`), "mozilla", "thunderbird"},
	{regexp.MustCompile(`^Microsoft Edge$`), "microsoft", "edge_chromium"},
	{regexp.MustCompile(`^Microsoft Visual Studio Code\b`), "microsoft", "visual_studio_code"},
	{regexp.MustCompile(`^7-Zip\b`), "7-zip", "7-zip"},
	{regexp.MustCompile(`^WinRAR\b`), "rarlab", "winrar"},
	{regexp.MustCompile(`^Adobe Acrobat Reader\b`), "adobe", "acrobat_reader_dc"},
	{regexp.MustCompile(`^Adobe Acrobat( \(64-bit\)| DC)?$`), "adobe", "acrobat_dc"},
	{regexp.MustCompile(`^VLC media player\b`), "videolan", "vlc_media_player"},
	{regexp.MustCompile(`^Notepad\+\+`), "notepad-plus-plus", `notepad\+\+`},
	{regexp.MustCompile(`^PuTTY\b`), "simon_tatham", "putty"},
	{regexp.MustCompile(`^WinSCP\b`), "winscp", "winscp"},
	{regexp.MustCompile(`^FileZilla\b`), "filezilla-project", "filezilla_client"},
	{regexp.MustCompile(`^TeamViewer\b`), "teamviewer", "teamviewer"},
	{regexp.MustCompile(`^AnyDesk\b`), "anydesk", "anydesk"},
	{regexp.MustCompile(`^Git$`), "git-scm", "git"},
	{regexp.MustCompile(`^Python (3\.\d+\.\d+)`), "python", "python"},
	{regexp.MustCompile(`^Node\.js$`), "nodejs", "node.js"},
	{regexp.MustCompile(`^Oracle (VM )?VirtualBox\b`), "oracle", "vm_virtualbox"},
	{regexp.MustCompile(`^Wireshark\b`), "wireshark", "wireshark"},
	{regexp.MustCompile(`^KeePass Password Safe 2\b`), "keepass", "keepass"},
	{regexp.MustCompile(`^LibreOffice\b`), "libreoffice", "libreoffice"},
	{regexp.MustCompile(`^GIMP\b`), "gimp", "gimp"},
	{regexp.MustCompile(`^Brave$`), "brave", "brave"},
	{regexp.MustCompile(`^Opera Stable\b`), "opera", "opera_browser"},
	{regexp.MustCompile(`^Foxit (PDF )?Reader\b`), "foxit", "pdf_reader"},
	{regexp.MustCompile(`^Docker Desktop$`), "docker", "desktop"},
	{regexp.MustCompile(`^Audacity\b`), "audacityteam", "audacity"},
	{regexp.MustCompile(`^Inkscape\b`), "inkscape", "inkscape"},
	{regexp.MustCompile(`^OBS Studio$`), "obsproject", "obs_studio"},
	{regexp.MustCompile(`^PostgreSQL \d+`), "postgresql", "postgresql"},
}

// catalogApp finds the catalog entry of an installed program and the
// version to compare.
func catalogApp(name, version string) (*vulnApp, string) {
	name = strings.TrimSpace(name)
	for i := range vulnCatalog {
		a := &vulnCatalog[i]
		m := a.re.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		// A group that starts with a digit is the version (Python's
		// DisplayVersion is a build number).
		if n := a.re.NumSubexp(); n > 0 {
			if g := m[n]; g != "" && g[0] >= '0' && g[0] <= '9' {
				version = g
			}
		}
		return a, strings.TrimSpace(version)
	}
	return nil, ""
}

// versionTokens splits a version into numbers and words.
func versionTokens(v string) []string {
	return strings.FieldsFunc(strings.ToLower(v), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
}

// cmpVersion compares versions part by part, numbers as numbers; missing
// parts count as 0 (so 7.01 equals 7.01.0).
func cmpVersion(a, b string) int {
	ta, tb := versionTokens(a), versionTokens(b)
	for i := 0; i < len(ta) || i < len(tb); i++ {
		x, y := "0", "0"
		if i < len(ta) {
			x = ta[i]
		}
		if i < len(tb) {
			y = tb[i]
		}
		nx, ex := strconv.ParseUint(x, 10, 64)
		ny, ey := strconv.ParseUint(y, 10, 64)
		switch {
		case ex == nil && ey == nil:
			if nx != ny {
				if nx < ny {
					return -1
				}
				return 1
			}
		case ex == nil: // a number is newer than a word (1.0 > 1.0-beta)
			return 1
		case ey == nil:
			return -1
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		}
	}
	return 0
}

// verRange is the affected versions of a CVE match: one version, or a
// range (empty ends are open).
type verRange struct {
	V  string `json:"v,omitempty"`
	SI string `json:"si,omitempty"` // start including
	SE string `json:"se,omitempty"` // start excluding
	EI string `json:"ei,omitempty"` // end including
	EE string `json:"ee,omitempty"` // end excluding
}

func (r verRange) matches(v string) bool {
	if r.V != "" {
		return cmpVersion(v, r.V) == 0
	}
	switch {
	case r.SI != "" && cmpVersion(v, r.SI) < 0,
		r.SE != "" && cmpVersion(v, r.SE) <= 0,
		r.EI != "" && cmpVersion(v, r.EI) > 0,
		r.EE != "" && cmpVersion(v, r.EE) >= 0:
		return false
	}
	return true
}

// severityOf names a CVSS score.
func severityOf(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	}
	return "unknown"
}

// cvss3Score is the base score of a CVSS v3 vector (0 if it is not one).
func cvss3Score(vector string) float64 {
	if !strings.HasPrefix(vector, "CVSS:3.") {
		return 0
	}
	m := map[string]string{}
	for _, p := range strings.Split(vector, "/")[1:] {
		if k, v, ok := strings.Cut(p, ":"); ok {
			m[k] = v
		}
	}
	changed := m["S"] == "C"
	pick := func(k string, vals map[string]float64) (float64, bool) {
		x, ok := vals[m[k]]
		return x, ok
	}
	av, ok1 := pick("AV", map[string]float64{"N": .85, "A": .62, "L": .55, "P": .2})
	ac, ok2 := pick("AC", map[string]float64{"L": .77, "H": .44})
	prVals := map[string]float64{"N": .85, "L": .62, "H": .27}
	if changed {
		prVals = map[string]float64{"N": .85, "L": .68, "H": .5}
	}
	pr, ok3 := pick("PR", prVals)
	ui, ok4 := pick("UI", map[string]float64{"N": .85, "R": .62})
	cia := map[string]float64{"H": .56, "L": .22, "N": 0}
	c, ok5 := pick("C", cia)
	i, ok6 := pick("I", cia)
	a, ok7 := pick("A", cia)
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return 0
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	impact := 6.42 * iss
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0
	}
	expl := 8.22 * av * ac * pr * ui
	base := impact + expl
	if changed {
		base *= 1.08
	}
	return roundUp1(math.Min(base, 10))
}

// roundUp1 rounds up to one decimal as CVSS v3.1 defines it.
func roundUp1(x float64) float64 {
	n := int(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return (math.Floor(float64(n)/10000) + 1) / 10
}
