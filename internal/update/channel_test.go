package update

import "testing"

func TestChannelBase(t *testing.T) {
	for _, c := range []struct{ source, version, want string }{
		{DefaultSource, "", DefaultSource + "/latest/download"},
		{DefaultSource, "0.12.0", DefaultSource + "/download/v0.12.0"},
		{TestingSource, "0.12.1", TestingSource},
		{TestingSource, "", TestingSource},
		{"https://mirror.example/cz", "0.12.0", "https://mirror.example/cz"},
	} {
		if got := Base(c.source, c.version); got != c.want {
			t.Errorf("Base(%q, %q) = %q, want %q", c.source, c.version, got, c.want)
		}
	}
	if ChannelSource("testing") != TestingSource || ChannelSource("") != DefaultSource || ChannelSource("x") != DefaultSource {
		t.Fatal("channel sources")
	}
}
