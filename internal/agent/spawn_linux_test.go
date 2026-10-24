//go:build linux

package agent

import "testing"

func TestParseXServer(t *testing.T) {
	cases := []struct {
		argv          []string
		ok            bool
		display, auth string
	}{
		{[]string{"/usr/lib/xorg/Xorg", ":0", "-seat", "seat0", "-auth", "/var/run/lightdm/root/:0", "-nolisten", "tcp", "vt7"}, true, ":0", "/var/run/lightdm/root/:0"},
		{[]string{"/usr/lib/xorg/Xorg", "vt2", "-displayfd", "3", "-auth", "/run/user/1000/gdm/Xauthority"}, true, ":0", "/run/user/1000/gdm/Xauthority"},
		{[]string{"Xvfb", ":5", "-screen", "0", "1280x800x24"}, true, ":5", ""},
		{[]string{"/usr/bin/Xwayland", ":0", "-rootless"}, false, "", ""},
		{[]string{"/bin/bash"}, false, "", ""},
	}
	for _, c := range cases {
		s, ok := parseXServer(c.argv)
		if ok != c.ok || (ok && (s.display != c.display || s.auth != c.auth)) {
			t.Errorf("%v: got %+v %v", c.argv, s, ok)
		}
	}
	p := parseProps("Type=wayland\nActive=yes\nRemote=no\nDisplay=\n")
	if p["Type"] != "wayland" || p["Active"] != "yes" || p["Display"] != "" {
		t.Errorf("props %v", p)
	}
}
