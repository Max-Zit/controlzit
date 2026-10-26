//go:build windows

package agent

import (
	"testing"

	"github.com/max-zit/controlzit/internal/proto"
)

func TestSplitCommand(t *testing.T) {
	for _, c := range []struct{ in, exe, rest string }{
		{`"C:\Program Files (x86)\Winamp\UninstWA.exe"`, `C:\Program Files (x86)\Winamp\UninstWA.exe`, ""},
		{`"C:\Program Files\7-Zip\Uninstall.exe" /S`, `C:\Program Files\7-Zip\Uninstall.exe`, "/S"},
		{`C:\Program Files\App\unins000.exe /SILENT`, `C:\Program Files\App\unins000.exe`, "/SILENT"},
		{`MsiExec.exe /X{11111111-1111-1111-1111-111111111111}`, `MsiExec.exe`, "/X{11111111-1111-1111-1111-111111111111}"},
		{`"C:\broken`, "", ""},
		{`rundll32 something`, "", ""},
	} {
		if exe, rest := splitCommand(c.in); exe != c.exe || rest != c.rest {
			t.Errorf("%q: %q %q", c.in, exe, rest)
		}
	}
}

// The list of this computer: names, valid keys, no duplicates.
func TestListPrograms(t *testing.T) {
	res := listPrograms()
	if len(res.Programs) == 0 {
		t.Fatal("no programs")
	}
	keys := map[string]bool{}
	for _, p := range res.Programs {
		if p.Name == "" || !proto.ValidProgramKey(p.Key) || keys[p.Key] {
			t.Fatalf("bad entry %+v", p)
		}
		keys[p.Key] = true
	}
}

func TestValidProgramKey(t *testing.T) {
	for k, want := range map[string]bool{
		"HKLM64:Winamp": true, "HKLM32:{11111111-1111-1111-1111-111111111111}": true,
		"HKU:S-1-5-21-1-2-3-1001:Spotify": true,
		`HKLM64:..\Run`:                   false, "HKLM64:": false, "HKCU:Winamp": false, "HKU:S-1-5-18:X": false,
	} {
		if proto.ValidProgramKey(k) != want {
			t.Errorf("%q: want %v", k, want)
		}
	}
}
