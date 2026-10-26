package agent

import "testing"

func TestParseChoco(t *testing.T) {
	got := parseChoco("Chocolatey v2.7.4\r\n7zip|25.1.0\r\nbad id|1\r\nfirefox|144.0\r\n", false)
	if len(got) != 2 || got[0].ID != "7zip" || got[0].Version != "25.1.0" || got[1].ID != "firefox" {
		t.Fatalf("search: %+v", got)
	}
	got = parseChoco("notepadplusplus|8.6|8.7.1|false\nvlc|3.0.20\n", true)
	if len(got) != 1 || got[0].Available != "8.7.1" {
		t.Fatalf("outdated: %+v", got)
	}
}
