package web

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/rmmzit/internal/store"
)

// Metric history: the minute samples stay 7 days, hourly summaries 90 days.
// The disk-full forecast fits a line through the used space of each drive
// over the last forecastWindow.
const (
	samplesKeep    = 7 * 24 * time.Hour
	historyKeep    = 90 * 24 * time.Hour
	forecastWindow = 14 * 24 * time.Hour
	// A forecast needs this much history and at most reaches this far.
	forecastMinSpan = 3 * 24 * time.Hour
	forecastMaxDays = 365
)

// AlertDiskFull is the alert of a disk that will be full soon by its trend.
const AlertDiskFull = "disk_forecast"

func init() { alertTitles[AlertDiskFull] = "Disk will be full soon" }

// DiskForecast is when a drive will be full if it keeps growing as in the
// forecast window.
type DiskForecast struct {
	Drive        string
	Size, Free   int64
	GrowthPerDay float64 // bytes
	Days         float64 // until full
	FullAt       time.Time
}

// forecasts keeps the latest forecasts of all devices (computed hourly).
type forecasts struct {
	mu       sync.Mutex
	byDevice map[int64][]DiskForecast
	at       time.Time
	purged   time.Time
}

// forecastOf turns a trend into a forecast; ok is false when the drive does
// not grow, has too little history, or will not be full within a year.
func forecastOf(t store.DiskTrend, now time.Time) (DiskForecast, bool) {
	f := DiskForecast{Drive: t.Drive, Size: t.Size, Free: t.Free, GrowthPerDay: t.GrowthPerDay}
	if t.Span < forecastMinSpan || t.Points < 24 || t.Size <= 0 || t.GrowthPerDay < 1<<20 { // under 1 MB a day is noise
		return f, false
	}
	f.Days = math.Max(0, float64(t.Free)/t.GrowthPerDay)
	if f.Days > forecastMaxDays {
		return f, false
	}
	f.FullAt = now.Add(time.Duration(f.Days * float64(24*time.Hour)))
	return f, true
}

// RunMetricHistory writes the hourly summaries (every 10 minutes), deletes
// old history and computes the disk forecasts (hourly).
func (s *Server) RunMetricHistory(ctx context.Context) {
	now := s.now()
	// From the start of the previous hour, so its summary gets its last samples.
	if err := s.store.RollupMetrics(ctx, now.Add(-time.Hour)); err != nil {
		s.log.Warn("metric history: cannot write the hourly summaries", "err", err)
	}
	s.forecast.mu.Lock()
	purge := now.Sub(s.forecast.purged) >= 6*time.Hour
	due := now.Sub(s.forecast.at) >= time.Hour
	s.forecast.mu.Unlock()
	if purge {
		if err := s.store.PurgeSamples(ctx, samplesKeep); err != nil {
			s.log.Warn("cannot purge old samples", "err", err)
		}
		if err := s.store.PurgeHistory(ctx, historyKeep); err != nil {
			s.log.Warn("cannot purge old metric history", "err", err)
		}
	}
	if due {
		s.updateForecasts(ctx)
	}
	s.forecast.mu.Lock()
	if purge {
		s.forecast.purged = now
	}
	s.forecast.mu.Unlock()
}

// updateForecasts recomputes the disk forecasts of all devices.
func (s *Server) updateForecasts(ctx context.Context) {
	now := s.now()
	trends, err := s.store.DiskTrends(ctx, now.Add(-forecastWindow))
	if err != nil {
		s.log.Warn("disk forecast", "err", err)
		return
	}
	by := map[int64][]DiskForecast{}
	for _, t := range trends {
		if f, ok := forecastOf(t, now); ok {
			by[t.DeviceID] = append(by[t.DeviceID], f)
		}
	}
	for _, l := range by {
		slices.SortFunc(l, func(a, b DiskForecast) int { return strings.Compare(a.Drive, b.Drive) })
	}
	s.forecast.mu.Lock()
	s.forecast.byDevice, s.forecast.at = by, now
	s.forecast.mu.Unlock()
}

// deviceForecasts returns the disk forecasts of a device.
func (s *Server) deviceForecasts(id int64) []DiskForecast {
	s.forecast.mu.Lock()
	defer s.forecast.mu.Unlock()
	return slices.Clone(s.forecast.byDevice[id])
}

// forecastConditions opens an alert for each drive that will be full within
// the days of the device's rules.
func (s *Server) forecastConditions(rules map[int64]MonitoringSettings, def MonitoringSettings) []store.Condition {
	s.forecast.mu.Lock()
	defer s.forecast.mu.Unlock()
	var conds []store.Condition
	for id, list := range s.forecast.byDevice {
		r, ok := rules[id]
		if !ok {
			r = def
		}
		for _, f := range list {
			if r.DiskFullDays <= 0 || f.Days > float64(r.DiskFullDays) {
				continue
			}
			sev := "warning"
			if f.Days <= 3 {
				sev = "critical"
			}
			conds = append(conds, store.Condition{DeviceID: id, Kind: AlertDiskFull, Key: f.Drive, Severity: sev,
				Message: fmt.Sprintf("%s full in about %.0f days (grows %s a day, %s free)", f.Drive, math.Ceil(f.Days), gb(uint64(f.GrowthPerDay)), gb(uint64(max(f.Free, 0))))}) // #nosec G115 -- non-negative
		}
	}
	return conds
}

// ---- history page

// historyRange is a choice of the history page.
type historyRange struct {
	Key   string
	Label string
	Span  time.Duration
	Step  time.Duration
}

var historyRanges = []historyRange{
	{"1d", "24 hours", 24 * time.Hour, 10 * time.Minute},
	{"7d", "7 days", 7 * 24 * time.Hour, time.Hour},
	{"30d", "30 days", 30 * 24 * time.Hour, 4 * time.Hour},
	{"90d", "90 days", 90 * 24 * time.Hour, 12 * time.Hour},
}

type historyData struct {
	D         *store.Device
	Range     historyRange
	Ranges    []historyRange
	Load      *chart
	Net       *chart
	Disk      *chart
	Forecasts []DiskForecast
	Empty     bool
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	d := s.deviceFor(w, r)
	if d == nil {
		return
	}
	hr := historyRanges[0]
	for _, x := range historyRanges {
		if x.Key == r.FormValue("range") {
			hr = x
		}
	}
	now := s.now()
	from := now.Add(-hr.Span)
	load, err := s.store.LoadHistory(r.Context(), d.ID, from, hr.Step)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	disks, err := s.store.DiskHistory(r.Context(), d.ID, from, max(hr.Step, time.Hour))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	tr := func(k string) string { return translate(s.lang(r, userFrom(r)), k) }
	hd := &historyData{D: d, Range: hr, Ranges: historyRanges, Forecasts: s.deviceForecasts(d.ID), Empty: len(load) == 0 && len(disks) == 0}
	hd.Load = loadChart(load, from, now, hr.Step, tr)
	hd.Net = netChart(load, from, now, hr.Step, tr)
	hd.Disk = diskChart(disks, from, now, max(hr.Step, time.Hour))
	s.render(w, r, http.StatusOK, "history", &Page{Title: d.Hostname, Nav: "devices", Data: hd})
}

// ---- charts (SVG drawn on the server; the CSP allows no chart scripts)

const (
	chartW, chartH = 720.0, 180.0
	chartL, chartR = 52.0, 8.0 // room for the value labels
	chartT, chartB = 8.0, 22.0 // room for the time labels
)

type chart struct {
	W, H   float64
	Series []chartSeries
	YTicks []chartTick
	XTicks []chartTick
}

type chartSeries struct {
	Name  string
	Class string
	Paths []string // polylines; gaps (device offline) split a series
	Last  string
}

type chartTick struct {
	Pos   float64
	Label string
}

type chartPoint struct {
	At time.Time
	V  float64
}

// newChart lays out series over from–to with a value axis from 0 to top.
func newChart(from, to time.Time, top float64, yLabel func(float64) string) *chart {
	c := &chart{W: chartW, H: chartH}
	for i := 0; i <= 4; i++ {
		v := top * float64(i) / 4
		c.YTicks = append(c.YTicks, chartTick{Pos: c.y(v, top), Label: yLabel(v)})
	}
	span := to.Sub(from)
	layout := "15:04"
	if span > 2*24*time.Hour {
		layout = "02.01."
	}
	for i := 0; i <= 5; i++ {
		t := from.Add(time.Duration(float64(span) * float64(i) / 5))
		c.XTicks = append(c.XTicks, chartTick{Pos: c.x(t, from, to), Label: t.Local().Format(layout)})
	}
	return c
}

func (c *chart) x(t, from, to time.Time) float64 {
	span := to.Sub(from).Seconds()
	if span <= 0 {
		return chartL
	}
	return chartL + (chartW-chartL-chartR)*t.Sub(from).Seconds()/span
}

func (c *chart) y(v, top float64) float64 {
	if top <= 0 {
		top = 1
	}
	return chartT + (chartH-chartT-chartB)*(1-math.Min(1, math.Max(0, v/top)))
}

// add draws points as polylines, starting a new one after a gap longer than
// two steps.
func (c *chart) add(name, class string, pts []chartPoint, from, to time.Time, top float64, step time.Duration, last string) {
	sr := chartSeries{Name: name, Class: class, Last: last}
	var b strings.Builder
	var prev time.Time
	flush := func() {
		if b.Len() > 0 {
			sr.Paths = append(sr.Paths, b.String())
			b.Reset()
		}
	}
	for _, p := range pts {
		if !prev.IsZero() && p.At.Sub(prev) > 2*step {
			flush()
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%.1f,%.1f", c.x(p.At, from, to), c.y(p.V, top))
		prev = p.At
	}
	flush()
	if len(sr.Paths) > 0 {
		c.Series = append(c.Series, sr)
	}
}

func pct(v float64) string { return fmt.Sprintf("%.0f %%", v) }

func loadChart(load []store.LoadPoint, from, to time.Time, step time.Duration, tr func(string) string) *chart {
	if len(load) == 0 {
		return nil
	}
	c := newChart(from, to, 100, pct)
	var cpu, mem []chartPoint
	for _, p := range load {
		cpu = append(cpu, chartPoint{p.At, p.CPUAvg})
		mem = append(mem, chartPoint{p.At, p.MemAvg})
	}
	l := load[len(load)-1]
	c.add("CPU", "s1", cpu, from, to, 100, step, pct(l.CPUAvg))
	c.add(tr("Memory"), "s2", mem, from, to, 100, step, pct(l.MemAvg))
	return c
}

// rate writes bytes per second the way people read network speed (bits).
func rate(bps float64) string {
	bits := bps * 8
	switch {
	case bits >= 1e9:
		return fmt.Sprintf("%.1f Gb/s", bits/1e9)
	case bits >= 1e6:
		return fmt.Sprintf("%.1f Mb/s", bits/1e6)
	case bits >= 1e3:
		return fmt.Sprintf("%.0f kb/s", bits/1e3)
	}
	return fmt.Sprintf("%.0f b/s", bits)
}

func netChart(load []store.LoadPoint, from, to time.Time, step time.Duration, tr func(string) string) *chart {
	var rx, tx []chartPoint
	top := 0.0
	var lastRx, lastTx float64
	for _, p := range load {
		if p.Rx == nil || p.Tx == nil {
			continue
		}
		rx = append(rx, chartPoint{p.At, *p.Rx})
		tx = append(tx, chartPoint{p.At, *p.Tx})
		top = math.Max(top, math.Max(*p.Rx, *p.Tx))
		lastRx, lastTx = *p.Rx, *p.Tx
	}
	if len(rx) == 0 {
		return nil
	}
	top = niceTop(top)
	c := newChart(from, to, top, rate)
	c.add(tr("Received"), "s1", rx, from, to, top, step, rate(lastRx))
	c.add(tr("Sent"), "s2", tx, from, to, top, step, rate(lastTx))
	return c
}

func diskChart(disks map[string][]store.DiskPoint, from, to time.Time, step time.Duration) *chart {
	if len(disks) == 0 {
		return nil
	}
	c := newChart(from, to, 100, pct)
	names := make([]string, 0, len(disks))
	for n := range disks {
		names = append(names, n)
	}
	slices.Sort(names)
	for i, n := range names {
		var pts []chartPoint
		var last float64
		for _, p := range disks[n] {
			if p.Size <= 0 {
				continue
			}
			last = float64(p.Size-p.Free) / float64(p.Size) * 100
			pts = append(pts, chartPoint{p.At, last})
		}
		c.add(n, "s"+strconv.Itoa(i%6+1), pts, from, to, 100, step, pct(last))
	}
	return c
}

// niceTop rounds a chart's top up to 1, 2 or 5 times a power of ten.
func niceTop(v float64) float64 {
	if v <= 0 {
		return 1
	}
	p := math.Pow(10, math.Floor(math.Log10(v)))
	for _, m := range []float64{1, 2, 5, 10} {
		if v <= m*p {
			return m * p
		}
	}
	return 10 * p
}

// DaysLeft is Days rounded up, for the page.
func (f DiskForecast) DaysLeft() int { return int(math.Ceil(f.Days)) }

// Growth, FreeBytes and SizeBytes are the sizes for the page.
func (f DiskForecast) Growth() uint64    { return uint64(max(f.GrowthPerDay, 0)) }
func (f DiskForecast) FreeBytes() uint64 { return uint64(max(f.Free, 0)) } // #nosec G115 -- non-negative
func (f DiskForecast) SizeBytes() uint64 { return uint64(max(f.Size, 0)) } // #nosec G115 -- non-negative
