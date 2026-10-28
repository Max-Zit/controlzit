package agent

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// netRate turns the byte counters of the network adapters into bytes per
// second since the previous sample.
type netRate struct {
	mu     sync.Mutex
	rx, tx uint64
	at     time.Time
}

var netPrev netRate

// rate returns the bytes per second for the counters read at now; the first
// sample and a counter that went back (adapter reset) give 0.
func (n *netRate) rate(rx, tx uint64, now time.Time) (rxps, txps float64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	prevRx, prevTx, prevAt := n.rx, n.tx, n.at
	n.rx, n.tx, n.at = rx, tx, now
	secs := now.Sub(prevAt).Seconds()
	if prevAt.IsZero() || secs < 1 || rx < prevRx || tx < prevTx {
		return 0, 0
	}
	return float64(rx-prevRx) / secs, float64(tx-prevTx) / secs
}

// parseNetDev sums the receive and transmit bytes of /proc/net/dev
// without loopback.
func parseNetDev(s string) (rx, tx uint64, ok bool) {
	for _, l := range strings.Split(s, "\n") {
		name, rest, found := strings.Cut(l, ":")
		if !found || strings.TrimSpace(name) == "lo" {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		r, err1 := strconv.ParseUint(f[0], 10, 64)
		t, err2 := strconv.ParseUint(f[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		rx, tx, ok = rx+r, tx+t, true
	}
	return rx, tx, ok
}
