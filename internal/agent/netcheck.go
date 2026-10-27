package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
)

// Network checks of a policy, run from the agent's own network.

func init() { register(proto.KindNetCheck, runNetChecks) }

const netCheckTimeout = 10 * time.Second

var netHTTP = &http.Client{Timeout: netCheckTimeout}

func runNetChecks(ctx context.Context, raw json.RawMessage) (any, error) {
	var in proto.NetCheckRun
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	if len(in.Checks) > proto.MaxNetChecks {
		return nil, errors.New("too many network checks")
	}
	out := make([]proto.NetCheckResult, len(in.Checks))
	ctx, cancel := context.WithTimeout(ctx, 2*netCheckTimeout+5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, c := range in.Checks {
		if err := c.Valid(); err != nil {
			out[i] = proto.NetCheckResult{Name: c.Name, Error: err.Error()}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = netCheck(ctx, c)
		}()
	}
	wg.Wait()
	return proto.NetCheckResults{Results: out}, nil
}

func netCheck(ctx context.Context, c proto.NetCheck) proto.NetCheckResult {
	r := proto.NetCheckResult{Name: c.Name}
	start := time.Now()
	var err error
	switch c.Kind {
	case proto.NetPing:
		var rtt time.Duration
		if rtt, err = ping(ctx, strings.Trim(c.Target, "[]")); err == nil {
			r.MS = millis(rtt)
		}
	case proto.NetTCP:
		d := net.Dialer{Timeout: netCheckTimeout}
		var conn net.Conn
		if conn, err = d.DialContext(ctx, "tcp", net.JoinHostPort(strings.Trim(c.Target, "[]"), strconv.Itoa(c.Port))); err == nil {
			_ = conn.Close()
		}
	case proto.NetHTTP:
		r.CertDays, err = fetchCheck(ctx, c.Target)
	}
	if err == nil && r.MS == 0 {
		r.MS = millis(time.Since(start))
	}
	r.OK = err == nil
	if err != nil {
		r.Error = trim(err.Error(), 200)
	}
	return r
}

// fetchCheck fetches a web address; it fails on HTTP errors and invalid
// certificates and returns the days until the certificate expires.
func fetchCheck(ctx context.Context, target string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "ControlZit-Agent/"+Version)
	resp, err := netHTTP.Do(req) // #nosec G704 -- the address an administrator set in a policy
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	days := 0
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		days = int(math.Ceil(time.Until(resp.TLS.PeerCertificates[0].NotAfter).Hours() / 24))
		if days == 0 {
			days = -1 // expires within the day; 0 means "no certificate"
		}
	}
	if resp.StatusCode >= 400 {
		return days, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return days, nil
}

func millis(d time.Duration) int {
	if ms := int(d / time.Millisecond); ms > 0 {
		return ms
	}
	return 1
}
