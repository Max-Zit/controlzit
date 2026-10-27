package web

import (
	"testing"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
)

// A maintenance window covers its hours, also past midnight into the next
// day, and only on its weekdays.
func TestMaintenanceWindow(t *testing.T) {
	sat := time.Date(2026, 10, 31, 0, 0, 0, 0, time.Local) // a Saturday
	m := &MaintenancePolicy{Windows: []MaintWindow{{Days: []int{6}, Start: 22 * 60, Hours: 4}}}
	for _, c := range []struct {
		at   time.Time
		want bool
	}{
		{sat.Add(21*time.Hour + 59*time.Minute), false},
		{sat.Add(22 * time.Hour), true},
		{sat.Add(25*time.Hour + 59*time.Minute), true}, // Sunday 01:59
		{sat.Add(26 * time.Hour), false},               // Sunday 02:00
		{sat.Add(-2 * time.Hour), false},               // Friday 22:00
	} {
		if got := m.active(c.at); got != c.want {
			t.Errorf("%s: %v, want %v", c.at.Format("Mon 15:04"), got, c.want)
		}
	}
	var none *MaintenancePolicy
	if none.active(sat) || scheduleDue(nil, 0, true, nil, sat) {
		t.Fatal("without windows nothing is due in the window")
	}
	if !scheduleDue([]int{6}, 22, false, nil, sat.Add(22*time.Hour+30*time.Minute)) || scheduleDue([]int{6}, 22, false, nil, sat.Add(23*time.Hour)) {
		t.Fatal("days and hour")
	}
	if !scheduleDue(nil, 0, true, m, sat.Add(23*time.Hour)) {
		t.Fatal("in the window")
	}
	if err := (&MaintenancePolicy{Windows: []MaintWindow{{Start: 60, Hours: 2}}}).validate(); err == nil {
		t.Fatal("a window without days")
	}
}

// Update rings: an update waits its days after the server first saw it;
// Defender definitions never wait; upgrades are never picked.
func TestUpdateRing(t *testing.T) {
	now := time.Now()
	r := &proto.PatchReport{Updates: []proto.PatchUpdate{
		{ID: "new", Categories: []string{"Security Updates"}},
		{ID: "old", Categories: []string{"Security Updates"}},
		{ID: "defs", Categories: []string{"Definition Updates"}},
		{ID: "upg", Categories: []string{"Upgrades"}},
	}}
	seen := map[string]time.Time{"new\x00": now.Add(-2 * 24 * time.Hour), "old\x00": now.Add(-8 * 24 * time.Hour), "defs\x00": now}
	got := PatchPolicy{Mode: PatchAutoAll, DelayDays: 7}.pick(r, seen, now)
	if len(got) != 2 || got[0] != "old" || got[1] != "defs" {
		t.Fatalf("ring of 7 days picked %v", got)
	}
	if got := (PatchPolicy{Mode: PatchAutoAll}).pick(r, seen, now); len(got) != 3 {
		t.Fatalf("without a ring: %v", got)
	}
	if !ringWaits(now, 1, now) || ringWaits(time.Time{}, 1, now) || ringWaits(now, 0, now) {
		t.Fatal("ringWaits")
	}
	if (PatchPolicy{Reboot: true}).restartMode() != RestartAuto || (PatchPolicy{}).restartMode() != RestartNever ||
		(PatchPolicy{Reboot: true, RestartMode: RestartDeadline}).restartMode() != RestartDeadline {
		t.Fatal("restart modes")
	}
}

func TestExcluded(t *testing.T) {
	p := proto.WingetPackage{ID: "Microsoft.Office", Name: "Microsoft 365 Apps"}
	if !excluded([]string{"microsoft.office"}, p) || !excluded([]string{" 365 "}, p) || excluded([]string{"", "Java"}, p) {
		t.Fatal("exclude list")
	}
}

// Packages winget cannot update count as skipped, not failed.
func TestWingetSkips(t *testing.T) {
	if !unknownVersion("Unknown") || !unknownVersion("< 2.0") || !unknownVersion("") || unknownVersion("1.2") {
		t.Fatal("unknown versions")
	}
	if !wingetCannotUpdate(int(int32(-1978335189))) || !wingetCannotUpdate(0x8A15008E) || wingetCannotUpdate(1) {
		t.Fatal("winget codes")
	}
}
