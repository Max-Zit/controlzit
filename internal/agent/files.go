package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/max-zit/rmmzit/internal/proto"
)

// File manager commands. The agent runs as SYSTEM, so it can reach every
// file; the server allows these commands only to technicians and audits
// each one.

// maxListing limits one folder listing.
const maxListing = 5000

func init() {
	register(proto.KindFSDrives, func(ctx context.Context, _ json.RawMessage) (any, error) { return drives() })
	register(proto.KindFSList, fsList)
	register(proto.KindFSRead, fsRead)
	register(proto.KindFSWrite, fsWrite)
	register(proto.KindFSMkdir, fsMkdir)
	register(proto.KindFSRename, fsRename)
	register(proto.KindFSDelete, fsDelete)
}

// cleanPath accepts only absolute local paths (C:\… on Windows, /… elsewhere):
// no relative paths, device namespaces (\\?\, \\.\), UNC shares or
// alternate data streams.
func cleanPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" || strings.ContainsRune(p, 0) {
		return "", errors.New("no path given")
	}
	if isWindows {
		p = strings.ReplaceAll(p, "/", `\`)
		if strings.HasPrefix(p, `\\`) {
			return "", errors.New("network and device paths are not allowed")
		}
		if len(p) == 2 && p[1] == ':' {
			p += `\`
		}
		if len(p) < 3 || p[1] != ':' || p[2] != '\\' || !isLetter(p[0]) {
			return "", fmt.Errorf("%q is not an absolute path such as C:\\Users", p)
		}
		if strings.Contains(p[2:], ":") {
			return "", errors.New("alternate data streams are not allowed")
		}
	} else if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("%q is not an absolute path", p)
	}
	return filepath.Clean(p), nil
}

func isLetter(c byte) bool { return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' }

// friendly turns OS errors into short messages for the console.
func friendly(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, os.ErrNotExist):
		return errors.New("not found")
	case errors.Is(err, os.ErrExist):
		return errors.New("already exists")
	case errors.Is(err, os.ErrPermission):
		return errors.New("access denied")
	}
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		return le.Err
	}
	return err
}

func fsList(ctx context.Context, raw json.RawMessage) (any, error) {
	var a proto.FSPath
	if err := args(raw, &a); err != nil {
		return nil, err
	}
	p, err := cleanPath(a.Path)
	if err != nil {
		return nil, err
	}
	des, err := os.ReadDir(p)
	if err != nil && len(des) == 0 {
		return nil, friendly(err)
	}
	out := proto.FSListing{Path: p}
	for _, de := range des {
		if len(out.Entries) >= maxListing {
			out.Truncated = true
			break
		}
		e := proto.FSEntry{Name: de.Name(), Dir: de.IsDir()}
		if info, err := de.Info(); err == nil {
			e.Modified = info.ModTime().UTC()
			if !e.Dir {
				e.Size = info.Size()
			}
			e.Hidden = hidden(info)
			e.Link = de.Type()&os.ModeSymlink != 0 || isLink(info)
		}
		out.Entries = append(out.Entries, e)
	}
	sort.Slice(out.Entries, func(i, j int) bool {
		a, b := out.Entries[i], out.Entries[j]
		if a.Dir != b.Dir {
			return a.Dir
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	return out, nil
}

func fsRead(ctx context.Context, raw json.RawMessage) (any, error) {
	var a proto.FSRead
	if err := args(raw, &a); err != nil {
		return nil, err
	}
	p, err := cleanPath(a.Path)
	if err != nil {
		return nil, err
	}
	if a.Length <= 0 || a.Length > proto.FSChunk || a.Offset < 0 {
		return nil, errors.New("bad read range")
	}
	f, err := os.Open(p) // #nosec G304 -- the file manager reads files chosen by the technician
	if err != nil {
		return nil, friendly(err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, friendly(err)
	}
	if st.IsDir() {
		return nil, errors.New("this is a folder")
	}
	buf := make([]byte, a.Length)
	n, err := f.ReadAt(buf, a.Offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, friendly(err)
	}
	return proto.FSReadResult{Data: buf[:n], Size: st.Size(), EOF: a.Offset+int64(n) >= st.Size()}, nil
}

const partSuffix = ".czpart"

func fsWrite(ctx context.Context, raw json.RawMessage) (any, error) {
	var a proto.FSWrite
	if err := args(raw, &a); err != nil {
		return nil, err
	}
	p, err := cleanPath(a.Path)
	if err != nil {
		return nil, err
	}
	if len(a.Data) > proto.FSChunk || a.Offset < 0 {
		return nil, errors.New("bad write range")
	}
	part := p + partSuffix
	if a.Offset == 0 {
		if st, err := os.Stat(p); err == nil {
			if st.IsDir() {
				return nil, errors.New("a folder with this name exists")
			}
			if !a.Overwrite {
				return nil, errors.New("the file already exists")
			}
		}
		if err := os.WriteFile(part, nil, 0o600); err != nil {
			return nil, friendly(err)
		}
	}
	f, err := os.OpenFile(part, os.O_WRONLY, 0) // #nosec G304 -- upload target chosen by the technician
	if err != nil {
		return nil, friendly(err)
	}
	st, err := f.Stat()
	if err == nil && st.Size() != a.Offset {
		err = fmt.Errorf("upload out of order (have %d bytes, got offset %d)", st.Size(), a.Offset)
	}
	if err == nil {
		_, err = f.WriteAt(a.Data, a.Offset)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(part)
		return nil, friendly(err)
	}
	if a.Final {
		if err := os.Rename(part, p); err != nil {
			_ = os.Remove(part)
			return nil, friendly(err)
		}
	}
	return nil, nil
}

func fsMkdir(ctx context.Context, raw json.RawMessage) (any, error) {
	var a proto.FSPath
	if err := args(raw, &a); err != nil {
		return nil, err
	}
	p, err := cleanPath(a.Path)
	if err != nil {
		return nil, err
	}
	return nil, friendly(os.Mkdir(p, 0o755)) // #nosec G301 -- normal folder permissions on the managed machine
}

func fsRename(ctx context.Context, raw json.RawMessage) (any, error) {
	var a proto.FSRename
	if err := args(raw, &a); err != nil {
		return nil, err
	}
	from, err := cleanPath(a.From)
	if err != nil {
		return nil, err
	}
	to, err := cleanPath(a.To)
	if err != nil {
		return nil, err
	}
	if protected(from) {
		return nil, errors.New("this folder cannot be renamed from the console")
	}
	if _, err := os.Lstat(to); err == nil && !strings.EqualFold(from, to) {
		return nil, errors.New("the target already exists")
	}
	return nil, friendly(os.Rename(from, to))
}

func fsDelete(ctx context.Context, raw json.RawMessage) (any, error) {
	var a proto.FSPath
	if err := args(raw, &a); err != nil {
		return nil, err
	}
	p, err := cleanPath(a.Path)
	if err != nil {
		return nil, err
	}
	if protected(p) {
		return nil, errors.New("this folder cannot be deleted from the console")
	}
	st, err := os.Lstat(p)
	if err != nil {
		return nil, friendly(err)
	}
	if st.IsDir() && a.Recursive {
		return nil, friendly(os.RemoveAll(p))
	}
	return nil, friendly(os.Remove(p))
}

// protected are paths whose removal would break the machine: drive roots
// and the system folders themselves (their contents stay reachable).
func protected(p string) bool {
	if filepath.Dir(p) == p {
		return true
	}
	for _, s := range systemFolders() {
		if s != "" && strings.EqualFold(filepath.Clean(s), p) {
			return true
		}
	}
	return false
}
