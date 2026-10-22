//go:build windows

package agent

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestPatchScan talks to the real Windows Update service; it needs
// CONTROLZIT_TEST_WU=1 (a scan can take minutes and needs the service).
func TestPatchScan(t *testing.T) {
	if os.Getenv("CONTROLZIT_TEST_WU") == "" {
		t.Skip("set CONTROLZIT_TEST_WU=1 to scan with Windows Update")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	r, err := patchScan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d updates missing, %d history entries, reboot required %v", len(r.Updates), len(r.History), r.RebootRequired)
	for _, u := range r.Updates {
		t.Logf("  %s %s %v %s", u.ID, u.Title, u.Categories, u.Severity)
	}
}

// TestPatchInstallNothing runs the installation script against the real
// service with an update that is not offered: the whole script is parsed
// and the search runs, nothing is installed.
func TestPatchInstallNothing(t *testing.T) {
	if os.Getenv("CONTROLZIT_TEST_WU") == "" {
		t.Skip("set CONTROLZIT_TEST_WU=1 to talk to Windows Update")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	r, err := patchInstall(ctx, []string{"00000000-0000-0000-0000-000000000000"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Result != 2 || len(r.Results) != 0 {
		t.Fatalf("%+v", r)
	}
}
