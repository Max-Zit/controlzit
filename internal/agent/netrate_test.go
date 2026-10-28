package agent

import (
	"testing"
	"time"
)

func TestNetRate(t *testing.T) {
	var n netRate
	t0 := time.Date(2026, 10, 28, 10, 0, 0, 0, time.UTC)
	if rx, tx := n.rate(1000, 500, t0); rx != 0 || tx != 0 {
		t.Fatal("the first sample has no rate")
	}
	if rx, tx := n.rate(61000, 6500, t0.Add(time.Minute)); rx != 1000 || tx != 100 {
		t.Fatalf("rate %v %v", rx, tx)
	}
	if rx, tx := n.rate(10, 10, t0.Add(2*time.Minute)); rx != 0 || tx != 0 {
		t.Fatal("a reset counter gives no rate")
	}
}

func TestParseNetDev(t *testing.T) {
	s := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 9999       10    0    0    0     0          0         0     9999      10    0    0    0     0       0          0
  eth0: 1000        5    0    0    0     0          0         0      300       3    0    0    0     0       0          0
  eth1:  500        5    0    0    0     0          0         0      200       3    0    0    0     0       0          0
`
	if rx, tx, ok := parseNetDev(s); !ok || rx != 1500 || tx != 500 {
		t.Fatalf("got %d %d %v", rx, tx, ok)
	}
}
