package store_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
	"github.com/max-zit/controlzit/internal/store"
	"github.com/max-zit/controlzit/internal/testdb"
)

// A dump restored into another database gives the same rows, ids keep
// counting where they were, and the restored database opens normally.
func TestDumpRestore(t *testing.T) {
	ctx := context.Background()
	src := open(t)
	cid, err := src.CreateCustomer(ctx, "Dump Ltd", "notes with ćšž")
	if err != nil {
		t.Fatal(err)
	}
	sid, err := src.CreateSite(ctx, cid, "HQ", "", "")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := src.CreateEnrollToken(ctx, sid, "", "admin", time.Hour, 10)
	if err != nil {
		t.Fatal(err)
	}
	d, err := src.EnrollDevice(ctx, tok, bytes.Repeat([]byte{1}, 32), "PC-1", "Windows 11", "0.11.0", "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := src.SaveMetrics(ctx, d.ID, &proto.Metrics{CPU: 12.5, MemTotal: 100, MemUsed: 40, NetRx: 1000, NetTx: 10,
		Disks: []proto.Disk{{Drive: "C:", Size: 100 << 30, Free: 40 << 30}}}); err != nil {
		t.Fatal(err)
	}
	if err := src.RollupMetrics(ctx, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	var dump bytes.Buffer
	if err := src.Dump(ctx, &dump); err != nil {
		t.Fatal(err)
	}

	// The target has its own data, which the restore replaces.
	url := testdb.URL(t)
	dst, err := store.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dst.CreateCustomer(ctx, "Other", ""); err != nil {
		t.Fatal(err)
	}
	dst.Close()
	if err := store.RestoreDump(ctx, url, bytes.NewReader(dump.Bytes())); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreDump(ctx, url, strings.NewReader("garbage")); err == nil {
		t.Fatal("garbage restored")
	}
	got, err := store.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	if err := got.UseSecretKey(bytes.Repeat([]byte{9}, 32)); err != nil {
		t.Fatal(err)
	}
	cs, err := got.Customers(ctx, nil)
	if err != nil || len(cs) != 1 || cs[0].Name != "Dump Ltd" {
		t.Fatalf("customers after restore: %+v %v", cs, err)
	}
	dev, err := got.Device(ctx, d.ID)
	if err != nil || dev.Hostname != "PC-1" {
		t.Fatalf("device after restore: %+v %v", dev, err)
	}
	var hourly int
	if err := got.Pool().QueryRow(ctx, `SELECT count(*) FROM device_hourly WHERE device_id=$1 AND rx IS NOT NULL`, d.ID).Scan(&hourly); err != nil || hourly != 1 {
		t.Fatalf("hourly rows after restore: %d %v", hourly, err)
	}
	id2, err := got.CreateCustomer(ctx, "Next", "")
	if err != nil || id2 <= cid {
		t.Fatalf("ids do not continue: %d after %d (%v)", id2, cid, err)
	}
}
