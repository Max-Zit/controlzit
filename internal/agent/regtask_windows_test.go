//go:build windows

package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/max-zit/controlzit/internal/proto"
)

func callKind(t *testing.T, fn func(context.Context, json.RawMessage) (any, error), a any) (any, error) {
	t.Helper()
	raw, _ := json.Marshal(a)
	return fn(context.Background(), raw)
}

// The editor creates a key, writes values of each type, reads them back,
// deletes a value and the whole key (under the test user's own hive).
func TestRegistryEditor(t *testing.T) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	base := `HKU\` + u.User.Sid.String() + `\Software`
	if _, err := callKind(t, regNewKey, proto.RegNewKey{Path: base, Name: "ControlZitTest"}); err != nil {
		t.Fatal(err)
	}
	key := base + `\ControlZitTest`
	defer func() { _, _ = callKind(t, regDelete, proto.RegDelete{Path: key, Key: true}) }()
	if _, err := callKind(t, regNewKey, proto.RegNewKey{Path: key, Name: "Sub"}); err != nil {
		t.Fatal(err)
	}
	for _, v := range []proto.RegValue{{Name: "Text", Type: "REG_SZ", Data: "čćž text"}, {Name: "Num", Type: "REG_DWORD", Data: "0x10"},
		{Name: "Big", Type: "REG_QWORD", Data: "5000000000"}, {Name: "Lines", Type: "REG_MULTI_SZ", Data: "a\nb\n"}, {Name: "", Type: "REG_EXPAND_SZ", Data: "%TEMP%"}} {
		if _, err := callKind(t, regSet, proto.RegSet{Path: key, RegValue: v}); err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
	}
	res, err := callKind(t, regSet, proto.RegSet{Path: key, RegValue: proto.RegValue{Name: "Num", Type: "REG_DWORD", Data: "17"}})
	if err != nil || res.(RegSetResult).Old == nil || res.(RegSetResult).Old.Data != "16" {
		t.Fatalf("old value not returned: %+v %v", res, err)
	}
	if _, err := callKind(t, regSet, proto.RegSet{Path: key, RegValue: proto.RegValue{Name: "Bad", Type: "REG_DWORD", Data: "-1"}}); err == nil {
		t.Fatal("a negative DWORD accepted")
	}
	got, err := callKind(t, regList, proto.RegPath{Path: key})
	if err != nil {
		t.Fatal(err)
	}
	k := got.(*proto.RegKey)
	vals := map[string]proto.RegValue{}
	for _, v := range k.Values {
		vals[v.Name] = v
	}
	if len(k.Subkeys) != 1 || k.Subkeys[0] != "Sub" || vals["Text"].Data != "čćž text" || vals["Num"].Data != "17" ||
		vals["Big"].Data != "5000000000" || vals["Lines"].Data != "a\nb" || vals[""].Type != "REG_EXPAND_SZ" {
		t.Fatalf("listed %+v", k)
	}
	if _, err := callKind(t, regDelete, proto.RegDelete{Path: key, Name: "Text"}); err != nil {
		t.Fatal(err)
	}
	if _, err := callKind(t, regDelete, proto.RegDelete{Path: `HKLM\SOFTWARE`, Key: true}); err == nil || !strings.Contains(err.Error(), "protected") {
		t.Fatalf("protected key: %v", err)
	}
	if _, err := callKind(t, regDelete, proto.RegDelete{Path: key, Key: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := callKind(t, regList, proto.RegPath{Path: key}); err == nil {
		t.Fatal("deleted key still opens")
	}
	if _, err := callKind(t, regList, proto.RegPath{Path: `HKCU\Software`}); err == nil {
		t.Fatal("HKCU accepted")
	}
}

func TestTaskList(t *testing.T) {
	got, err := callKind(t, taskList, proto.TaskList{All: true})
	if err != nil {
		t.Fatal(err)
	}
	list := got.([]proto.SchedTask)
	ms := 0
	for _, x := range list {
		if strings.HasPrefix(x.Path, `\Microsoft\`) {
			ms++
		}
	}
	if ms == 0 {
		t.Fatalf("no Windows tasks among %d", len(list))
	}
	if _, err := callKind(t, taskControl, proto.TaskControl{Path: `\`, Name: "x'; Remove-Item C:\\", Action: "run"}); err == nil {
		t.Fatal("a name with a quote accepted")
	}
	if _, err := callKind(t, taskControl, proto.TaskControl{Path: `\`, Name: "ControlZitNoSuchTask", Action: "run"}); err == nil {
		t.Fatal("a missing task ran")
	}
}
