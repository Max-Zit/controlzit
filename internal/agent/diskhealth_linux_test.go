//go:build linux

package agent

import "testing"

func TestParseMdstat(t *testing.T) {
	s := `Personalities : [raid1]
md0 : active raid1 sdb1[1] sda1[0]
      1048512 blocks [2/2] [UU]

md1 : active raid1 sdc1[0]
      2096064 blocks [2/1] [U_]
      [===>.................]  recovery = 17.0%

unused devices: <none>
`
	a := parseMdstat(s)
	if len(a) != 2 || a[0].Name != "md0" || a[0].Level != "raid1" || a[0].Health != "ok" || a[1].Health != "warning" {
		t.Fatalf("%+v", a)
	}
}
