package agent

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"testing"

	"github.com/max-zit/controlzit/internal/proto"
)

// A definition update found by the last scan is replaced by the one Windows
// Update offers now; other updates keep their IDs.
func TestCurrentDefinitions(t *testing.T) {
	const (
		oldDef = "11111111-1111-1111-1111-111111111111"
		newDef = "22222222-2222-2222-2222-222222222222"
		sec    = "33333333-3333-3333-3333-333333333333"
	)
	def := []string{"Definition Updates"}
	a := &Agent{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	a.patch = &patchState{report: proto.PatchReport{Updates: []proto.PatchUpdate{
		{ID: oldDef, KB: "KB2267602", Categories: def},
		{ID: sec, KB: "KB5099999", Categories: []string{"Security Updates"}},
	}}}
	scans := 0
	old := PatchScan
	defer func() { PatchScan = old }()
	PatchScan = func(context.Context) (*PatchScanResult, error) {
		scans++
		return &PatchScanResult{Updates: []proto.PatchUpdate{
			{ID: newDef, KB: "KB2267602", Categories: def},
			{ID: sec, KB: "KB5099999", Categories: []string{"Security Updates"}},
		}}, nil
	}
	if got := a.currentDefinitions(context.Background(), []string{oldDef, sec}); !slices.Equal(got, []string{newDef, sec}) {
		t.Fatalf("ids = %v", got)
	}
	// Without definition updates there is no extra scan.
	if got := a.currentDefinitions(context.Background(), []string{sec}); !slices.Equal(got, []string{sec}) || scans != 1 {
		t.Fatalf("ids = %v, scans = %d", got, scans)
	}
}
