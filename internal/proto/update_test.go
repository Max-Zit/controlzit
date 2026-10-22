package proto

import "testing"

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"0.2.7", "0.2.7", 0}, {"0.2.10", "0.2.9", 1}, {"0.2.9", "0.2.10", -1}, {"1.0.0", "0.9.9", 1},
		{"0.2.7-dev", "0.2.7", -1}, {"dev", "0.0.1", -1}, {"v0.3.0", "0.3.0", 0}, {"0.3", "0.3.0", 0},
	} {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("%s vs %s = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	if !ValidVersion("0.2.8") || ValidVersion("0.2") || ValidVersion("0.2.8-dev") || ValidVersion("x") {
		t.Error("ValidVersion")
	}
}
