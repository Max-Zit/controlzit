package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/max-zit/controlzit/internal/proto"
)

func call(t *testing.T, kind string, a any) (any, error) {
	t.Helper()
	raw, _ := json.Marshal(a)
	return handlers[kind](context.Background(), raw)
}

func TestCleanPath(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows paths")
	}
	for in, want := range map[string]string{`C:\Users\x\..\y`: `C:\Users\y`, `c:/temp/a`: `c:\temp\a`, `D:`: `D:\`} {
		if got, err := cleanPath(in); err != nil || got != want {
			t.Errorf("%q → %q %v", in, got, err)
		}
	}
	for _, bad := range []string{``, `temp\a`, `\\server\share\x`, `\\?\C:\x`, `\\.\PhysicalDrive0`, `C:\a.txt:stream`, `1:\x`, "C:\\a\x00b"} {
		if _, err := cleanPath(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestFileOperations(t *testing.T) {
	dir := t.TempDir()
	// Upload in two chunks.
	target := filepath.Join(dir, "report.bin")
	data := bytes.Repeat([]byte("controlzit"), 200000) // 2 MB
	half := proto.FSChunk
	if _, err := call(t, proto.KindFSWrite, proto.FSWrite{Path: target, Offset: 0, Data: data[:half]}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatal("target visible before the final chunk")
	}
	if _, err := call(t, proto.KindFSWrite, proto.FSWrite{Path: target, Offset: 123, Data: data[half:]}); err == nil {
		t.Fatal("out-of-order chunk accepted")
	}
	// The failed chunk removed the partial file; start again.
	call(t, proto.KindFSWrite, proto.FSWrite{Path: target, Offset: 0, Data: data[:half]})
	if _, err := call(t, proto.KindFSWrite, proto.FSWrite{Path: target, Offset: int64(half), Data: data[half:], Final: true}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(target)
	if !bytes.Equal(got, data) {
		t.Fatal("uploaded content differs")
	}
	if _, err := call(t, proto.KindFSWrite, proto.FSWrite{Path: target, Data: []byte("x"), Final: true}); err == nil {
		t.Fatal("existing file overwritten without overwrite")
	}

	// Download.
	var all []byte
	for off := int64(0); ; {
		out, err := call(t, proto.KindFSRead, proto.FSRead{Path: target, Offset: off, Length: proto.FSChunk})
		if err != nil {
			t.Fatal(err)
		}
		r := out.(proto.FSReadResult)
		all = append(all, r.Data...)
		off += int64(len(r.Data))
		if r.EOF {
			break
		}
	}
	if !bytes.Equal(all, data) {
		t.Fatal("downloaded content differs")
	}

	// Folder, rename, list, delete.
	sub := filepath.Join(dir, "Folder")
	if _, err := call(t, proto.KindFSMkdir, proto.FSPath{Path: sub}); err != nil {
		t.Fatal(err)
	}
	if _, err := call(t, proto.KindFSRename, proto.FSRename{From: target, To: filepath.Join(sub, "r.bin")}); err != nil {
		t.Fatal(err)
	}
	out, err := call(t, proto.KindFSList, proto.FSPath{Path: dir})
	if err != nil {
		t.Fatal(err)
	}
	l := out.(proto.FSListing)
	if len(l.Entries) != 1 || !l.Entries[0].Dir || l.Entries[0].Name != "Folder" {
		t.Fatalf("listing: %+v", l.Entries)
	}
	if _, err := call(t, proto.KindFSDelete, proto.FSPath{Path: sub}); err == nil {
		t.Fatal("non-empty folder deleted without recursive")
	}
	if _, err := call(t, proto.KindFSDelete, proto.FSPath{Path: sub, Recursive: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := call(t, proto.KindFSList, proto.FSPath{Path: sub}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("deleted folder: %v", err)
	}
	// Strict arguments.
	if _, err := handlers[proto.KindFSList](context.Background(), json.RawMessage(`{"path":"C:\\","evil":1}`)); err == nil {
		t.Fatal("unknown argument accepted")
	}
}

func TestProtectedPaths(t *testing.T) {
	root := filepath.VolumeName(os.TempDir()) + string(filepath.Separator)
	if runtime.GOOS != "windows" {
		root = "/"
	}
	if _, err := call(t, proto.KindFSDelete, proto.FSPath{Path: root, Recursive: true}); err == nil || !strings.Contains(err.Error(), "cannot be deleted") {
		t.Fatalf("drive root: %v", err)
	}
	if runtime.GOOS == "windows" {
		if _, err := call(t, proto.KindFSDelete, proto.FSPath{Path: os.Getenv("SystemRoot"), Recursive: true}); err == nil {
			t.Fatal("Windows folder deletable")
		}
		out, err := call(t, proto.KindFSDrives, nil)
		if err != nil || len(out.([]proto.FSDrive)) == 0 {
			t.Fatalf("drives: %v", err)
		}
	}
}
