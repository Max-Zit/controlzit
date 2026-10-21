//go:build windows

package agent

import (
	"context"
	"testing"
	"time"
)

func TestCollectMetrics(t *testing.T) {
	CollectMetrics(context.Background()) // first CPU sample
	time.Sleep(300 * time.Millisecond)
	m := CollectMetrics(context.Background())
	if m.MemTotal == 0 || m.MemUsed == 0 || m.MemUsed > m.MemTotal || len(m.Disks) == 0 || m.CPU < 0 || m.CPU > 100 {
		t.Fatalf("metrics: %+v", m)
	}
	if m.StoppedAuto != nil || m.Security != nil {
		t.Fatal("slow parts collected twice in a row")
	}
	t.Logf("cpu %.1f%%, mem %d/%d MB, %d disks", m.CPU, m.MemUsed>>20, m.MemTotal>>20, len(m.Disks))
}
