//go:build windows

package agent

import (
	"context"
	"testing"

	"github.com/max-zit/controlzit/internal/proto"
)

func TestEventQuery(t *testing.T) {
	q := eventQuery(proto.EventMonitor{Log: "Security", IDs: []int{4625, 4740}, Level: 2, Source: "Microsoft-Windows-Security-Auditing", Minutes: 10})
	want := "*[System[TimeCreated[timediff(@SystemTime) <= 600000] and (EventID=4625 or EventID=4740) and (Level=1 or Level=2) and Provider[@Name='Microsoft-Windows-Security-Auditing']]]"
	if q != want {
		t.Fatalf("query\n%s\nwant\n%s", q, want)
	}
}

// The System log of any Windows has events in the last day; a monitor for
// an ID nobody writes counts none.
func TestCountEvents(t *testing.T) {
	n, err := countEvents(context.Background(), proto.EventMonitor{Log: "System", Minutes: 1440})
	if err != nil || n == 0 {
		t.Fatalf("System log: %d %v", n, err)
	}
	n, err = countEvents(context.Background(), proto.EventMonitor{Log: "System", IDs: []int{65000}, Minutes: 60})
	if err != nil || n != 0 {
		t.Fatalf("unused ID: %d %v", n, err)
	}
	procs, err := processList()
	if err != nil || len(procs) == 0 {
		t.Fatal("no processes")
	}
}
