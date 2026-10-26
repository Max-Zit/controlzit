package proto

import "testing"

func TestPackageInstallValid(t *testing.T) {
	ok := PackageInstall{Name: "7-Zip", FileName: "7z2501-x64.msi", Kind: "msi", SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Size: 1, Args: "/qn /norestart"}
	if !ok.Valid() {
		t.Fatal("valid package refused")
	}
	for name, change := range map[string]func(p *PackageInstall){
		"kind mismatch":   func(p *PackageInstall) { p.Kind = "exe" },
		"path in name":    func(p *PackageInstall) { p.FileName = `..\x.msi` },
		"newline in args": func(p *PackageInstall) { p.Args = "/qn\r\nfoo" },
		"short hash":      func(p *PackageInstall) { p.SHA256 = "abc" },
		"too big":         func(p *PackageInstall) { p.Size = MaxLibraryPackage + 1 },
	} {
		p := ok
		change(&p)
		if p.Valid() {
			t.Errorf("%s: accepted", name)
		}
	}
	if !ValidChocoID("notepadplusplus.install") || ValidChocoID("-x") || ValidChocoID("a b") {
		t.Fatal("choco IDs")
	}
}
