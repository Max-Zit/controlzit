package proto

import "testing"

func TestNetCheckValid(t *testing.T) {
	for _, c := range []struct {
		c  NetCheck
		ok bool
	}{
		{NetCheck{Name: "Router", Kind: NetPing, Target: "192.168.1.1"}, true},
		{NetCheck{Name: "v6", Kind: NetPing, Target: "[fe80::1%eth0]"}, true},
		{NetCheck{Name: "SQL", Kind: NetTCP, Target: "sql.local", Port: 1433}, true},
		{NetCheck{Name: "SQL", Kind: NetTCP, Target: "sql.local"}, false},
		{NetCheck{Name: "Web", Kind: NetHTTP, Target: "https://example.com/health"}, true},
		{NetCheck{Name: "Web", Kind: NetHTTP, Target: "file:///etc/passwd"}, false},
		{NetCheck{Name: "Bad", Kind: NetPing, Target: "-c 9 host"}, false},
		{NetCheck{Name: "", Kind: NetPing, Target: "host"}, false},
		{NetCheck{Name: "x", Kind: "udp", Target: "host"}, false},
	} {
		if err := c.c.Valid(); (err == nil) != c.ok {
			t.Errorf("%+v: %v", c.c, err)
		}
	}
}
