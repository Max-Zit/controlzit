// relsign makes the signed manifest of a release.
//
//	go run ./tools/relsign keygen -out release.key        new key; prints the public key
//	go run ./tools/relsign sign -key release.key -version 0.3.0 -dir dist/release-0.3.0 [-notes notes.md]
//	go run ./tools/relsign verify -dir DIR -file NAME                 checks a downloaded file against the signed manifest in DIR
//
// sign lists every file of the directory with its SHA-256 (kind, format and
// platform from the file name), writes manifest.json and manifest.json.sig.
// Keep the key offline; only its public half goes into internal/update.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/max-zit/rmmzit/internal/update"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: relsign keygen|sign|verify …|sign …")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	out := fs.String("out", "", "key file to write (keygen)")
	keyFile := fs.String("key", "", "release key (sign)")
	version := fs.String("version", "", "release version (sign)")
	dir := fs.String("dir", "", "directory with the release files (sign)")
	notes := fs.String("notes", "", "release notes file (sign)")
	file := fs.String("file", "", "release file to check (verify)")
	_ = fs.Parse(os.Args[2:])
	switch os.Args[1] {
	case "keygen":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		check(err)
		if _, err := os.Stat(*out); err == nil { // #nosec G703 -- the operator's files
			check(fmt.Errorf("%s exists", *out))
		}
		check(os.WriteFile(*out, []byte(base64.StdEncoding.EncodeToString(priv.Seed())+"\n"), 0o600)) // #nosec G703 -- the operator's files
		fmt.Println(base64.StdEncoding.EncodeToString(pub))
	case "sign":
		raw, err := os.ReadFile(*keyFile) // #nosec G304 G703 -- the operator's key file
		check(err)
		seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		check(err)
		if len(seed) != ed25519.SeedSize {
			check(fmt.Errorf("bad key file"))
		}
		key := ed25519.NewKeyFromSeed(seed)
		m := update.Manifest{Product: update.ManifestProduct, Version: *version, Released: time.Now().UTC().Truncate(time.Second)}
		if *notes != "" {
			b, err := os.ReadFile(*notes) // #nosec G304 G703 -- the operator's notes file
			check(err)
			m.Notes = strings.TrimSpace(string(b))
		}
		ents, err := os.ReadDir(*dir)
		check(err)
		for _, e := range ents {
			n := e.Name()
			if e.IsDir() || strings.HasPrefix(n, "manifest.json") {
				continue
			}
			f := describe(n)
			f.SHA256, f.Size = sum(filepath.Join(*dir, n))
			m.Files = append(m.Files, f)
		}
		sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Name < m.Files[j].Name })
		b, err := json.MarshalIndent(m, "", "  ")
		check(err)
		b = append(b, '\n')
		if _, err := update.Verify(b, update.Sign(b, key), []string{base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}); err != nil {
			check(err)
		}
		check(os.WriteFile(filepath.Join(*dir, "manifest.json"), b, 0o644))                       // #nosec G306 G703 -- published
		check(os.WriteFile(filepath.Join(*dir, "manifest.json.sig"), update.Sign(b, key), 0o644)) // #nosec G306 G703 -- published
		fmt.Printf("signed %d files of %s\n", len(m.Files), *version)
	case "verify":
		// The manifest must carry a signature of a trusted release key, and the
		// file the size and SHA-256 the manifest lists for it.
		raw, err := os.ReadFile(filepath.Join(*dir, "manifest.json")) // #nosec G304 G703 -- the operator's files
		check(err)
		sig, err := os.ReadFile(filepath.Join(*dir, "manifest.json.sig")) // #nosec G304 G703 -- the operator's files
		check(err)
		m, err := update.Verify(raw, sig, update.TrustedKeys)
		check(err)
		for _, f := range m.Files {
			if f.Name == *file {
				if h, n := sum(filepath.Join(*dir, f.Name)); h != f.SHA256 || n != f.Size {
					check(fmt.Errorf("%s does not match the signed manifest", f.Name))
				}
				fmt.Printf("%s of %s: signature and checksum OK\n", f.Name, m.Version)
				return
			}
		}
		check(fmt.Errorf("%s is not in the manifest of %s", *file, m.Version))
	default:
		check(fmt.Errorf("unknown command %s", os.Args[1]))
	}
}

// describe derives kind, format and platform from a release file name.
func describe(n string) update.File {
	f := update.File{Name: n, Kind: "other"}
	switch {
	case strings.HasPrefix(n, "rmmzit-server"):
		f.Kind = "server"
	case strings.HasPrefix(n, "rmmzit-agent"):
		f.Kind = "agent"
	}
	switch {
	case strings.HasSuffix(n, ".deb"):
		f.Format = "deb"
	case strings.HasSuffix(n, ".rpm"):
		f.Format = "rpm"
	case strings.HasSuffix(n, ".msi"):
		f.Format = "msi"
	case strings.HasSuffix(n, ".exe"):
		f.Format = "exe"
	case !strings.Contains(n, "."):
		f.Format = "bin"
	}
	for _, p := range []string{"linux-amd64", "linux-arm64", "windows-amd64"} {
		if strings.Contains(n, p) || (p == "linux-amd64" && (strings.Contains(n, "_amd64.deb") || strings.Contains(n, ".x86_64.rpm"))) ||
			(p == "linux-arm64" && (strings.Contains(n, "_arm64.deb") || strings.Contains(n, ".aarch64.rpm"))) {
			f.Platform = p
		}
	}
	if strings.HasSuffix(n, "-x64.msi") {
		f.Platform = "windows-amd64"
	}
	return f
}

func sum(path string) (string, int64) {
	in, err := os.Open(path) // #nosec G304 G703 -- release files
	check(err)
	defer in.Close()
	h := sha256.New()
	n, err := io.Copy(h, in)
	check(err)
	return hex.EncodeToString(h.Sum(nil)), n
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
