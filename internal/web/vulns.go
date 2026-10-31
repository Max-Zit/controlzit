package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/rmmzit/internal/proto"
	"github.com/max-zit/rmmzit/internal/store"
)

// Vulnerability scanning: the installed programs of all devices are
// compared with public vulnerability databases — NVD for common Windows
// programs (by their CPE name, version ranges checked here) and OSV for
// the packages of Debian and Ubuntu. Only product names and versions leave
// the server, never device data. It is off until an administrator switches
// it on.

const (
	settingVulns   = "vulnerabilities"
	vulnScanEvery  = 6 * time.Hour
	vulnCacheFresh = 24 * time.Hour
	defaultNVD     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	defaultOSV     = "https://api.osv.dev"
)

// VulnSettings switch the scan on and keep its last result.
type VulnSettings struct {
	Enabled   bool      `json:"enabled"`
	NVDKey    string    `json:"nvd_key,omitempty"` // sealed
	LastScan  time.Time `json:"last_scan,omitzero"`
	LastError string    `json:"last_error,omitempty"`
}

func (s *Server) vulnSettings(ctx context.Context) VulnSettings {
	var v VulnSettings
	_ = s.store.GetSetting(ctx, settingVulns, &v)
	return v
}

// vulnScanner keeps scans from overlapping.
type vulnScanner struct {
	mu   sync.Mutex
	busy bool
}

func (v *vulnScanner) start() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.busy {
		return false
	}
	v.busy = true
	return true
}

func (v *vulnScanner) done() {
	v.mu.Lock()
	v.busy = false
	v.mu.Unlock()
}

func (v *vulnScanner) running() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.busy
}

// RunVulnScan starts a scan when one is due (monitor loop).
func (s *Server) RunVulnScan(ctx context.Context) {
	if v := s.vulnSettings(ctx); v.Enabled && s.now().Sub(v.LastScan) >= vulnScanEvery {
		s.startVulnScan()
	}
}

// startVulnScan scans in the background unless a scan runs.
func (s *Server) startVulnScan() bool {
	if !s.vulns.start() {
		return false
	}
	go func() { // #nosec G118 -- a scan outlives the request or tick that started it
		defer s.vulns.done()
		ctx := context.Background()
		err := s.scanVulns(ctx)
		v := s.vulnSettings(ctx)
		v.LastScan, v.LastError = s.now(), ""
		if err != nil {
			v.LastError = clip(err.Error(), 500)
			s.log.Warn("vulnerability scan", "err", err)
		}
		_ = s.store.SetSetting(ctx, settingVulns, v)
		s.CheckAlerts(ctx)
	}()
	return true
}

func (s *Server) scanVulns(ctx context.Context) error {
	invs, err := s.store.Inventories(ctx)
	if err != nil {
		return err
	}
	found := map[int64][]store.DeviceVuln{}
	var problems []string

	// Windows programs NVD knows.
	type winItem struct {
		dev     int64
		name    string
		version string
	}
	items := map[*vulnApp][]winItem{}
	for id, inv := range invs {
		if !isWindowsOS(inv.OS.Name) {
			continue
		}
		for _, sw := range inv.Software {
			if app, ver := catalogApp(sw.Name, sw.Version); app != nil && ver != "" {
				items[app] = append(items[app], winItem{dev: id, name: sw.Name, version: ver})
			}
		}
	}
	apps := make([]*vulnApp, 0, len(items))
	for a := range items {
		apps = append(apps, a)
	}
	sort.Slice(apps, func(i, j int) bool { return apps[i].product < apps[j].product })
	for _, app := range apps {
		cves, err := s.productCVEs(ctx, app.vendor, app.product)
		if err != nil {
			problems = append(problems, app.product+": "+err.Error())
			continue
		}
		for _, it := range items[app] {
			for _, c := range cves {
				for _, r := range c.Ranges {
					if r.matches(it.version) {
						found[it.dev] = append(found[it.dev], store.DeviceVuln{ID: c.ID, Product: it.name, Version: it.version,
							Severity: severityOf(c.Score), Score: c.Score, Summary: c.Summary, Source: "nvd"})
						break
					}
				}
			}
		}
	}

	// Debian and Ubuntu packages in OSV.
	type pkgAt struct{ eco, name, version string }
	devPkgs := map[int64][]pkgAt{}
	want := map[pkgAt]bool{}
	for id, inv := range invs {
		eco := osvEcosystem(inv.OS)
		if eco == "" {
			continue
		}
		for _, sw := range inv.Software {
			p := pkgAt{eco: eco, name: sw.Name, version: sw.Version}
			if sw.Source != "" && sw.SourceVersion != "" {
				p.name, p.version = sw.Source, sw.SourceVersion
			}
			devPkgs[id] = append(devPkgs[id], p)
			want[p] = true
		}
	}
	if len(want) > 0 {
		var qs []osvQuery
		for p := range want {
			qs = append(qs, osvQuery{Eco: p.eco, Name: p.name, Version: p.version})
		}
		ids, err := s.osvLookup(ctx, qs)
		if err != nil {
			problems = append(problems, "OSV: "+err.Error())
		}
		var all []string
		seen := map[string]bool{}
		for _, list := range ids {
			for _, id := range list {
				if !seen[id] {
					seen[id] = true
					all = append(all, id)
				}
			}
		}
		details, err := s.osvDetails(ctx, all)
		if err != nil {
			problems = append(problems, "OSV: "+err.Error())
		}
		for dev, pkgs := range devPkgs {
			done := map[string]bool{}
			for _, p := range pkgs {
				for _, id := range ids[osvQuery{Eco: p.eco, Name: p.name, Version: p.version}] {
					if done[id+p.name] {
						continue
					}
					done[id+p.name] = true
					d := details[id]
					fix := d.Fixed[p.eco]
					if fix == "" && d.Ranges {
						fix = "none"
					}
					found[dev] = append(found[dev], store.DeviceVuln{ID: id, Product: p.name, Version: p.version,
						Severity: d.Severity, Score: d.Score, Summary: d.Summary, Source: "osv", Fix: fix})
				}
			}
		}
	}

	for id := range invs {
		if err := s.store.ReplaceDeviceVulns(ctx, id, found[id]); err != nil {
			return err
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// ---- NVD

// cveEntry is a CVE of a product with the versions it affects.
type cveEntry struct {
	ID      string     `json:"id"`
	Score   float64    `json:"s"`
	Summary string     `json:"d"`
	Ranges  []verRange `json:"r"`
}

type nvdMetric struct {
	Data struct {
		Score    float64 `json:"baseScore"`
		Severity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Status       string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		V40 []nvdMetric `json:"cvssMetricV40"`
		V31 []nvdMetric `json:"cvssMetricV31"`
		V30 []nvdMetric `json:"cvssMetricV30"`
		V2  []nvdMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
	Configurations []struct {
		Nodes []struct {
			Match []struct {
				Vulnerable bool   `json:"vulnerable"`
				Criteria   string `json:"criteria"`
				SI         string `json:"versionStartIncluding"`
				SE         string `json:"versionStartExcluding"`
				EI         string `json:"versionEndIncluding"`
				EE         string `json:"versionEndExcluding"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
}

type nvdPage struct {
	ResultsPerPage int `json:"resultsPerPage"`
	StartIndex     int `json:"startIndex"`
	TotalResults   int `json:"totalResults"`
	Items          []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

// entryOf keeps what a scan needs of a CVE: its score and the version
// ranges of the product.
func entryOf(c nvdCVE, vendor, product string) (cveEntry, bool) {
	e := cveEntry{ID: c.ID}
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			e.Summary = clip(d.Value, 300)
			break
		}
	}
	for _, list := range [][]nvdMetric{c.Metrics.V31, c.Metrics.V40, c.Metrics.V30, c.Metrics.V2} {
		if len(list) > 0 && list[0].Data.Score > 0 {
			e.Score = list[0].Data.Score
			break
		}
	}
	for _, cfg := range c.Configurations {
		for _, n := range cfg.Nodes {
			for _, m := range n.Match {
				p := strings.Split(m.Criteria, ":")
				if !m.Vulnerable || len(p) < 6 || !strings.EqualFold(p[3], vendor) || !strings.EqualFold(p[4], product) {
					continue
				}
				r := verRange{SI: m.SI, SE: m.SE, EI: m.EI, EE: m.EE}
				switch {
				case p[5] == "-":
					continue
				case p[5] != "*":
					r = verRange{V: strings.ReplaceAll(p[5], `\`, "")}
				case r == verRange{}:
					// "Every version" (old entries, often a browser listed
					// next to the affected system): too vague to report.
					continue
				}
				e.Ranges = append(e.Ranges, r)
			}
		}
	}
	return e, len(e.Ranges) > 0 && c.Status != "Rejected"
}

// productCVEs returns the CVEs of a product, from the cache or NVD: the
// first time all of them, later the ones changed since the last fetch.
func (s *Server) productCVEs(ctx context.Context, vendor, product string) ([]cveEntry, error) {
	// "nvd2": ranges without versions are no longer kept.
	key := "nvd2:" + vendor + ":" + product
	var cached struct {
		CVEs []cveEntry `json:"cves"`
	}
	at, err := s.store.VulnSource(ctx, key, &cached)
	if err != nil {
		return nil, err
	}
	now := s.now()
	if !at.IsZero() && now.Sub(at) < vulnCacheFresh {
		return cached.CVEs, nil
	}
	since := time.Time{}
	if !at.IsZero() && now.Sub(at) < 100*24*time.Hour { // NVD allows 120 days per request
		since = at.Add(-time.Hour)
	}
	fresh, err := s.fetchNVD(ctx, vendor, product, since, now)
	if err != nil {
		if len(cached.CVEs) > 0 {
			return cached.CVEs, nil // older data is better than none
		}
		return nil, err
	}
	if !since.IsZero() {
		byID := map[string]int{}
		for i, c := range cached.CVEs {
			byID[c.ID] = i
		}
		for id, e := range fresh {
			if i, ok := byID[id]; ok {
				cached.CVEs[i] = e
			} else {
				cached.CVEs = append(cached.CVEs, e)
			}
		}
	} else {
		cached.CVEs = cached.CVEs[:0]
		for _, e := range fresh {
			cached.CVEs = append(cached.CVEs, e)
		}
	}
	// Rejected CVEs come back without ranges: drop them.
	out := cached.CVEs[:0]
	for _, c := range cached.CVEs {
		if len(c.Ranges) > 0 {
			out = append(out, c)
		}
	}
	cached.CVEs = out
	if err := s.store.SaveVulnSource(ctx, key, cached); err != nil {
		return nil, err
	}
	return cached.CVEs, nil
}

var nvdClient = &http.Client{Timeout: 5 * time.Minute}

func (s *Server) nvdWait(key string) time.Duration {
	switch {
	case s.NVDWait > 0:
		return s.NVDWait
	case key != "":
		return 700 * time.Millisecond // 50 requests in 30 s with a key
	}
	return 6500 * time.Millisecond // 5 requests in 30 s without one
}

// fetchNVD reads the CVEs of a product (changed since, if set) page by page.
func (s *Server) fetchNVD(ctx context.Context, vendor, product string, since, until time.Time) (map[string]cveEntry, error) {
	base := s.NVDURL
	if base == "" {
		base = defaultNVD
	}
	key := ""
	if v := s.vulnSettings(ctx); v.NVDKey != "" {
		key, _ = s.store.OpenSecret("settings.vulns.nvd_key", v.NVDKey)
	}
	out := map[string]cveEntry{}
	for start := 0; ; {
		q := url.Values{"virtualMatchString": {"cpe:2.3:a:" + vendor + ":" + product + ":*"}, "resultsPerPage": {"500"}, "startIndex": {strconv.Itoa(start)}}
		if !since.IsZero() {
			q.Set("lastModStartDate", since.UTC().Format("2006-01-02T15:04:05.000Z"))
			q.Set("lastModEndDate", until.UTC().Format("2006-01-02T15:04:05.000Z"))
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "RMMZit/"+s.Version)
		if key != "" {
			req.Header.Set("apiKey", key)
		}
		resp, err := nvdClient.Do(req) // #nosec G704 -- the NVD address (or a test server)
		if err != nil {
			return nil, err
		}
		var page nvdPage
		err = json.NewDecoder(io.LimitReader(resp.Body, 256<<20)).Decode(&page)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("NVD answered %s", resp.Status)
		}
		if err != nil {
			return nil, fmt.Errorf("NVD: %w", err)
		}
		for _, it := range page.Items {
			if e, ok := entryOf(it.CVE, vendor, product); ok {
				out[e.ID] = e
			} else {
				out[it.CVE.ID] = cveEntry{ID: it.CVE.ID} // gone or rejected: no ranges
			}
		}
		start += len(page.Items)
		if len(page.Items) == 0 || start >= page.TotalResults {
			return out, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(s.nvdWait(key)):
		}
	}
}

// ---- OSV

type osvQuery struct{ Eco, Name, Version string }

// osvEcosystem names the OSV ecosystem of Debian and Ubuntu releases.
func osvEcosystem(os proto.OSInfo) string {
	name, ver := strings.ToLower(os.Name), strings.TrimSpace(os.Version)
	switch {
	case ver == "":
		return ""
	case strings.Contains(name, "ubuntu"):
		if y, m, ok := strings.Cut(ver, "."); ok && m == "04" {
			if n, err := strconv.Atoi(y); err == nil && n%2 == 0 {
				return "Ubuntu:" + ver + ":LTS"
			}
		}
		return "Ubuntu:" + ver
	case strings.Contains(name, "debian"):
		major, _, _ := strings.Cut(ver, ".")
		return "Debian:" + major
	}
	return ""
}

var osvClient = &http.Client{Timeout: 2 * time.Minute}

func (s *Server) osvURL() string {
	if s.OSVURL != "" {
		return s.OSVURL
	}
	return defaultOSV
}

// osvLookup returns the vulnerability IDs of package versions, from the
// cache or OSV (in batches).
func (s *Server) osvLookup(ctx context.Context, qs []osvQuery) (map[osvQuery][]string, error) {
	out := map[osvQuery][]string{}
	var ask []osvQuery
	for _, q := range qs {
		var ids []string
		at, err := s.store.VulnSource(ctx, "osv:"+q.Eco+":"+q.Name+":"+q.Version, &ids)
		if err != nil {
			return out, err
		}
		if !at.IsZero() && s.now().Sub(at) < vulnCacheFresh {
			out[q] = ids
			continue
		}
		ask = append(ask, q)
	}
	for len(ask) > 0 {
		n := min(len(ask), 500)
		batch := ask[:n]
		ask = ask[n:]
		type pkg struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		}
		type query struct {
			Package pkg    `json:"package"`
			Version string `json:"version"`
		}
		body := struct {
			Queries []query `json:"queries"`
		}{}
		for _, q := range batch {
			body.Queries = append(body.Queries, query{Package: pkg{Name: q.Name, Ecosystem: q.Eco}, Version: q.Version})
		}
		raw, _ := json.Marshal(body)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.osvURL()+"/v1/querybatch", bytes.NewReader(raw))
		if err != nil {
			return out, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "RMMZit/"+s.Version)
		resp, err := osvClient.Do(req) // #nosec G704 -- the OSV address (or a test server)
		if err != nil {
			return out, err
		}
		var res struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			} `json:"results"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&res)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return out, fmt.Errorf("OSV answered %s", resp.Status)
		}
		if err != nil {
			return out, err
		}
		for i, q := range batch {
			ids := []string{}
			if i < len(res.Results) {
				for _, v := range res.Results[i].Vulns {
					ids = append(ids, v.ID)
				}
			}
			out[q] = ids
			if err := s.store.SaveVulnSource(ctx, "osv:"+q.Eco+":"+q.Name+":"+q.Version, ids); err != nil {
				return out, err
			}
		}
	}
	return out, nil
}

// osvDetail is what the pages show of an OSV vulnerability.
type osvDetail struct {
	Summary  string            `json:"summary"`
	Score    float64           `json:"score"`
	Severity string            `json:"severity"`
	Fixed    map[string]string `json:"fixed,omitempty"` // by ecosystem: the version that fixes it
	Ranges   bool              `json:"ranges"`          // Fixed was read (older cache entries lack it)
}

// osvDetailMax is how many details one scan fetches (the rest next time).
const osvDetailMax = 3000

// osvDetails returns the details of vulnerabilities, from the cache or OSV.
func (s *Server) osvDetails(ctx context.Context, ids []string) (map[string]osvDetail, error) {
	out := map[string]osvDetail{}
	cached, err := s.store.VulnDetails(ctx, ids, s.now().Add(-7*24*time.Hour))
	if err != nil {
		return out, err
	}
	var missing []string
	for _, id := range ids {
		var d osvDetail
		if raw, ok := cached[id]; ok && json.Unmarshal(raw, &d) == nil && d.Ranges {
			out[id] = d
			continue
		}
		out[id] = osvDetail{Severity: "unknown"}
		if len(missing) < osvDetailMax {
			missing = append(missing, id)
		}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var firstErr error
	sem := make(chan struct{}, 8)
	for _, id := range missing {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			d, err := s.fetchOSVDetail(ctx, id)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			out[id] = d
			_ = s.store.SaveVulnDetail(ctx, id, d)
		}()
	}
	wg.Wait()
	return out, firstErr
}

func (s *Server) fetchOSVDetail(ctx context.Context, id string) (osvDetail, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.osvURL()+"/v1/vulns/"+url.PathEscape(id), nil)
	if err != nil {
		return osvDetail{}, err
	}
	req.Header.Set("User-Agent", "RMMZit/"+s.Version)
	resp, err := osvClient.Do(req) // #nosec G704 -- the OSV address (or a test server)
	if err != nil {
		return osvDetail{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return osvDetail{}, fmt.Errorf("OSV answered %s for %s", resp.Status, id)
	}
	var v struct {
		Summary  string `json:"summary"`
		Details  string `json:"details"`
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
		DB struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
		Affected []struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Ranges []struct {
				Events []map[string]string `json:"events"`
			} `json:"ranges"`
		} `json:"affected"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&v); err != nil {
		return osvDetail{}, err
	}
	d := osvDetail{Summary: v.Summary, Fixed: map[string]string{}, Ranges: true}
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if f := e["fixed"]; f != "" {
					d.Fixed[a.Package.Ecosystem] = f
				}
			}
		}
	}
	if d.Summary == "" {
		d.Summary = v.Details
	}
	d.Summary = clip(strings.TrimSpace(d.Summary), 300)
	for _, sv := range v.Severity {
		if sc := cvss3Score(sv.Score); sc > d.Score {
			d.Score = sc
		}
	}
	d.Severity = severityOf(d.Score)
	if d.Score == 0 {
		switch strings.ToLower(v.DB.Severity) {
		case "critical":
			d.Severity = "critical"
		case "high", "important":
			d.Severity = "high"
		case "medium", "moderate":
			d.Severity = "medium"
		case "low", "negligible", "unimportant":
			d.Severity = "low"
		}
	}
	return d, nil
}

// ---- alerts

// AlertVuln is the alert of critical vulnerabilities on a device.
const AlertVuln = "vulnerability"

func init() { alertTitles[AlertVuln] = "Critical vulnerability" }

// vulnConditions open an alert per program with critical vulnerabilities
// on devices whose alert rules ask for it.
func (s *Server) vulnConditions(ctx context.Context, rules map[int64]MonitoringSettings) []store.Condition {
	list, err := s.store.DeviceVulns(ctx, 0)
	if err != nil {
		return nil
	}
	type key struct {
		dev     int64
		product string
	}
	count := map[key]int{}
	first := map[key]store.DeviceVuln{}
	for _, v := range list {
		if v.Severity != "critical" || !rules[v.DeviceID].VulnAlerts {
			continue
		}
		k := key{v.DeviceID, v.Product}
		if count[k] == 0 {
			first[k] = v
		}
		count[k]++
	}
	var conds []store.Condition
	for k, n := range count {
		f := first[k]
		conds = append(conds, store.Condition{DeviceID: k.dev, Kind: AlertVuln, Key: k.product, Severity: "critical",
			Message: fmt.Sprintf("%d critical vulnerabilities in %s %s (for example %s)", n, f.Product, f.Version, f.ID)})
	}
	return conds
}
