//go:build !windows

package agent

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"time"
)

var pingTimeRE = regexp.MustCompile(`time[=<]([0-9.]+) ?ms`)

// ping runs the system's ping once (raw sockets need privileges the ping
// program already has).
func ping(ctx context.Context, host string) (time.Duration, error) {
	cmd := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "5", "--", host) // #nosec G204 -- validated host name or address
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		return 0, errors.New("no answer")
	}
	if m := pingTimeRE.FindSubmatch(out); m != nil {
		if ms, err := strconv.ParseFloat(string(m[1]), 64); err == nil {
			return time.Duration(ms * float64(time.Millisecond)), nil
		}
	}
	return time.Millisecond, nil
}
