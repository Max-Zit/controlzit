package legacy

import "testing"

func TestGetenv(t *testing.T) {
	t.Setenv("RMMZIT_X", "")
	t.Setenv("CONTROLZIT_X", "old")
	if Getenv("X") != "old" {
		t.Fatal("old name not read")
	}
	t.Setenv("RMMZIT_X", "new")
	if Getenv("X") != "new" {
		t.Fatal("new name does not win")
	}
	if Lookup(map[string]string{"CONTROLZIT_DB": "a"}, "DB") != "a" || Lookup(map[string]string{"RMMZIT_DB": "b", "CONTROLZIT_DB": "a"}, "DB") != "b" {
		t.Fatal("Lookup")
	}
}
