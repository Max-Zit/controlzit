package web

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
	"github.com/max-zit/controlzit/internal/store"
)

// File manager: browse, download, upload, rename and delete files of a
// device through its agent, without a remote desktop session. Every
// operation needs the technician role and is written to the audit log.

const (
	fsTimeout = 60 * time.Second
	// maxUpload limits one uploaded file.
	maxUpload = 4 << 30
)

// Paths of managed machines are Windows paths (the server may run on Linux,
// so path/filepath cannot be used for them).
func winParent(p string) string {
	p = strings.TrimRight(p, `\`)
	i := strings.LastIndex(p, `\`)
	if i < 0 {
		return ""
	}
	if i == 2 && p[1] == ':' { // C:\x → C:\
		return p[:3]
	}
	return p[:i]
}

func winJoin(dir, name string) string { return strings.TrimRight(dir, `\`) + `\` + name }

func winBase(p string) string {
	p = strings.TrimRight(p, `\`)
	if i := strings.LastIndex(p, `\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// validName checks a file or folder name typed in the console.
func validName(n string) error {
	n = strings.TrimSpace(n)
	if n == "" || n == "." || n == ".." || len(n) > 255 || strings.ContainsAny(n, "\\/:*?\"<>|\x00") || strings.TrimRight(n, ". ") != n {
		return errors.New("not a valid file name")
	}
	return nil
}

type crumb struct{ Name, Path string }

func crumbs(p string) []crumb {
	var out []crumb
	parts := strings.Split(strings.TrimRight(p, `\`), `\`)
	acc := ""
	for i, part := range parts {
		if part == "" {
			continue
		}
		if i == 0 {
			acc = part + `\`
		} else {
			acc = winJoin(acc, part)
		}
		out = append(out, crumb{Name: part, Path: acc})
	}
	return out
}

type filesData struct {
	D       *store.Device
	Path    string
	Parent  string
	Crumbs  []crumb
	Drives  []proto.FSDrive
	List    *proto.FSListing
	Err     string
	Offline bool
}

// Join is the full path of an entry.
func (d *filesData) Join(name string) string { return winJoin(d.Path, name) }

// deviceForFiles loads the device and checks the role.
func (s *Server) deviceForFiles(w http.ResponseWriter, r *http.Request) *store.Device {
	d := s.deviceFor(w, r)
	if d == nil {
		return nil
	}
	if !userFrom(r).CanWrite() {
		s.forbidden(w, r)
		return nil
	}
	return d
}

func (s *Server) issuer(r *http.Request) string { return userFrom(r).Username }

func (s *Server) handleFiles(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	fd := &filesData{D: d, Path: strings.TrimSpace(r.FormValue("path"))}
	lang := s.lang(r, userFrom(r))
	if fd.Path == "" {
		var drives []proto.FSDrive
		err := s.call(r.Context(), d.ID, s.issuer(r), proto.KindFSDrives, nil, &drives, fsTimeout)
		fd.Drives = drives
		s.fsError(fd, lang, err)
	} else {
		var l proto.FSListing
		err := s.call(r.Context(), d.ID, s.issuer(r), proto.KindFSList, proto.FSPath{Path: fd.Path}, &l, fsTimeout)
		if err == nil {
			fd.List, fd.Path = &l, l.Path
			s.audit(r, "file.list", "device:"+strconv.FormatInt(d.ID, 10), "listed %s on %q", l.Path, d.Hostname)
		}
		s.fsError(fd, lang, err)
		fd.Parent, fd.Crumbs = winParent(fd.Path), crumbs(fd.Path)
	}
	s.render(w, r, http.StatusOK, "files", &Page{Title: d.Hostname, Nav: "devices", Data: fd})
}

func (s *Server) fsError(fd *filesData, lang string, err error) {
	if err == nil {
		return
	}
	if errors.Is(err, ErrOffline) {
		fd.Offline = true
	}
	fd.Err = translate(lang, err.Error())
}

func (s *Server) filesURL(d *store.Device, path string) string {
	return "/devices/" + strconv.FormatInt(d.ID, 10) + "/files?path=" + url.QueryEscape(path)
}

// fsDone redirects back to the folder with a message.
func (s *Server) fsDone(w http.ResponseWriter, r *http.Request, d *store.Device, dir string, err error, ok string) {
	if err != nil {
		s.redirect(w, r, s.filesURL(d, dir), err.Error())
		return
	}
	s.redirect(w, r, s.filesURL(d, dir), ok)
}

func (s *Server) handleFileDownload(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	p := r.FormValue("path")
	// Large files take longer than the server's default write timeout.
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	var first proto.FSReadResult
	if err := s.call(r.Context(), d.ID, s.issuer(r), proto.KindFSRead, proto.FSRead{Path: p, Length: proto.FSChunk}, &first, fsTimeout); err != nil {
		s.redirect(w, r, s.filesURL(d, winParent(p)), err.Error())
		return
	}
	s.audit(r, "file.download", "device:"+strconv.FormatInt(d.ID, 10), "downloaded %s (%d bytes) from %q", p, first.Size, d.Hostname)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": winBase(p)}))
	w.Header().Set("Content-Length", strconv.FormatInt(first.Size, 10))
	w.Header().Set("Cache-Control", "no-store")
	if _, err := w.Write(first.Data); err != nil {
		return
	}
	off := int64(len(first.Data))
	for !first.EOF && off < first.Size {
		var c proto.FSReadResult
		if err := s.call(r.Context(), d.ID, s.issuer(r), proto.KindFSRead, proto.FSRead{Path: p, Offset: off, Length: proto.FSChunk}, &c, fsTimeout); err != nil {
			s.log.Warn("download interrupted", "device", d.ID, "path", p, "err", err)
			return // the browser sees a short download
		}
		if len(c.Data) == 0 {
			break
		}
		if _, err := w.Write(c.Data); err != nil {
			return
		}
		off += int64(len(c.Data))
		first.EOF = c.EOF
	}
}

func (s *Server) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})
	r.Body = http.MaxBytesReader(w, r.Body, maxUpload+1<<20)
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "bad upload", http.StatusBadRequest)
		return
	}
	var dir string
	overwrite := false
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			s.redirect(w, r, s.filesURL(d, dir), "No file was chosen.")
			return
		}
		if err != nil {
			http.Error(w, "bad upload", http.StatusBadRequest)
			return
		}
		switch part.FormName() {
		case "dir":
			b, _ := io.ReadAll(io.LimitReader(part, 4096))
			dir = string(b)
			continue
		case "overwrite":
			overwrite = true
			continue
		case "file":
		default:
			continue
		}
		name := winBase(strings.ReplaceAll(part.FileName(), "/", `\`))
		if dir == "" || validName(name) != nil {
			s.redirect(w, r, s.filesURL(d, dir), "Choose a folder and a file with a valid name.")
			return
		}
		target := winJoin(dir, name)
		n, err := s.uploadTo(r, d, target, part, overwrite)
		if err != nil {
			s.audit(r, "file.upload.failed", "device:"+strconv.FormatInt(d.ID, 10), "upload of %s to %q failed after %d bytes: %v", target, d.Hostname, n, err)
			s.redirect(w, r, s.filesURL(d, dir), "Upload failed: "+err.Error())
			return
		}
		s.audit(r, "file.upload", "device:"+strconv.FormatInt(d.ID, 10), "uploaded %s (%d bytes) to %q", target, n, d.Hostname)
		s.redirect(w, r, s.filesURL(d, dir), "File uploaded.")
		return
	}
}

// uploadTo sends a file to the agent in chunks.
func (s *Server) uploadTo(r *http.Request, d *store.Device, target string, src io.Reader, overwrite bool) (int64, error) {
	buf := make([]byte, proto.FSChunk)
	var off int64
	for {
		n, rerr := io.ReadFull(src, buf)
		if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
			return off, rerr
		}
		if off+int64(n) > maxUpload {
			return off, fmt.Errorf("the file is larger than %d GB", maxUpload>>30)
		}
		final := rerr != nil
		if err := s.call(r.Context(), d.ID, s.issuer(r), proto.KindFSWrite,
			proto.FSWrite{Path: target, Offset: off, Data: buf[:n], Final: final, Overwrite: overwrite}, nil, fsTimeout); err != nil {
			return off, err
		}
		off += int64(n)
		if final {
			return off, nil
		}
	}
}

func (s *Server) handleFileMkdir(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	dir, name := r.FormValue("dir"), strings.TrimSpace(r.FormValue("name"))
	if err := validName(name); err != nil {
		s.fsDone(w, r, d, dir, err, "")
		return
	}
	p := winJoin(dir, name)
	err := s.call(r.Context(), d.ID, s.issuer(r), proto.KindFSMkdir, proto.FSPath{Path: p}, nil, fsTimeout)
	if err == nil {
		s.audit(r, "file.mkdir", "device:"+strconv.FormatInt(d.ID, 10), "created folder %s on %q", p, d.Hostname)
	}
	s.fsDone(w, r, d, dir, err, "Folder created.")
}

func (s *Server) handleFileRename(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	from, name := r.FormValue("path"), strings.TrimSpace(r.FormValue("name"))
	dir := winParent(from)
	if err := validName(name); err != nil {
		s.fsDone(w, r, d, dir, err, "")
		return
	}
	to := winJoin(dir, name)
	err := s.call(r.Context(), d.ID, s.issuer(r), proto.KindFSRename, proto.FSRename{From: from, To: to}, nil, fsTimeout)
	if err == nil {
		s.audit(r, "file.rename", "device:"+strconv.FormatInt(d.ID, 10), "renamed %s to %s on %q", from, to, d.Hostname)
	}
	s.fsDone(w, r, d, dir, err, "Renamed.")
}

func (s *Server) handleFileDelete(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	p := r.FormValue("path")
	rec := r.FormValue("recursive") == "1"
	err := s.call(r.Context(), d.ID, s.issuer(r), proto.KindFSDelete, proto.FSPath{Path: p, Recursive: rec}, nil, 5*time.Minute)
	if err == nil {
		s.audit(r, "file.delete", "device:"+strconv.FormatInt(d.ID, 10), "deleted %s (recursive %v) on %q", p, rec, d.Hostname)
	}
	s.fsDone(w, r, d, winParent(p), err, "Deleted.")
}
