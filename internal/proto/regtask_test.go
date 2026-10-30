package proto

import "testing"

func TestValidTaskControl(t *testing.T) {
	ok := TaskControl{Path: `\Vendor\`, Name: "Nightly job", Action: "run"}
	if err := ValidTaskControl(ok); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"x'; rm", "x\u2019; Remove-Item C:\\", "x\u2018", "x\u201b", "a$b", "a`b", "a\"b", ""} {
		bad := ok
		bad.Name = name
		if ValidTaskControl(bad) == nil {
			t.Errorf("%q accepted", name)
		}
	}
	if ValidTaskControl(TaskControl{Path: `\`, Name: "x", Action: "format"}) == nil {
		t.Error("unknown action accepted")
	}
}
