package web_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/max-zit/rmmzit/internal/proto"
)

// The history page draws the load and network of the samples; a drive that
// grows steadily gets a forecast on the pages and an alert.
func TestMetricHistoryAndForecast(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin("192.168.1.10")
	ctx := context.Background()
	d := e.device(t, "HIST-PC", "Windows 11")
	base := "/devices/" + itoa(d.ID)

	if b := admin.get(base + "/history").body; !strings.Contains(b, "No history for this period yet") {
		t.Fatal("empty history not explained")
	}
	start := e.now
	for i := 0; i < 30; i++ {
		e.now = start.Add(time.Duration(i) * time.Minute)
		if err := e.st.SaveMetrics(ctx, d.ID, &proto.Metrics{CPU: float64(i), MemTotal: 100, MemUsed: 50, NetRx: 125000, NetTx: 1000,
			Disks: []proto.Disk{{Drive: "C:", Size: 100 << 30, Free: 50 << 30}}}); err != nil {
			t.Fatal(err)
		}
	}
	b := admin.get(base + "/history").body
	for _, want := range []string{"CPU and memory", "<polyline", "Network", "1.0 Mb/s"} {
		if !strings.Contains(b, want) {
			t.Fatalf("history page lacks %q", want)
		}
	}
	if code := admin.get(base + "/history?range=90d").code; code != 200 {
		t.Fatalf("90 days: %d", code)
	}

	// Ten days of hourly disk space, 2 GB more used each day: 10 GB free
	// left means full in about 5 days.
	day0 := e.now.Add(-10 * 24 * time.Hour).Truncate(time.Hour)
	for h := 0; h <= 240; h++ {
		used := int64(80<<30) + int64(h)*(2<<30)/24
		if _, err := e.st.Pool().Exec(ctx, `INSERT INTO device_disk_hourly (device_id, hour, drive, size, free) VALUES ($1,$2,'D:',$3,$4)`,
			d.ID, day0.Add(time.Duration(h)*time.Hour), int64(110<<30), int64(110<<30)-used); err != nil {
			t.Fatal(err)
		}
	}
	e.srv.RunMetricHistory(ctx)
	b = admin.get(base + "/history").body
	if !strings.Contains(b, "Disk full forecast") || !strings.Contains(b, "D:") {
		t.Fatal("no forecast on the history page")
	}
	if b := admin.get(base).body; !strings.Contains(b, "D: full in about") {
		t.Fatal("no forecast on the device page")
	}
	e.srv.CheckAlerts(ctx)
	if b := admin.get("/alerts").body; !strings.Contains(b, "Disk will be full soon") {
		t.Fatal("no forecast alert")
	}
	var n int
	if err := e.st.Pool().QueryRow(ctx, `SELECT count(*) FROM device_hourly WHERE device_id=$1 AND rx > 0`, d.ID).Scan(&n); err != nil || n == 0 {
		t.Fatalf("no hourly summary: %d %v", n, err)
	}
}
