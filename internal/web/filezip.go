package web

import (
	"archive/zip"
	"context"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
	"github.com/max-zit/controlzit/internal/store"
)

// Download a folder as one ZIP file (built while it is sent).

const (
	zipMaxFiles = 50000
	zipMaxDepth = 32
)

type zipJob struct {
	s      *Server
	r      *http.Request
	d      *store.Device
	zw     *zip.Writer
	files  int
	bytes  int64
	failed []string
}

func (s *Server) handleFolderZip(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	dir := r.FormValue("path")
	var top proto.FSListing
	if err := s.call(r.Context(), d.ID, s.issuer(r), proto.KindFSList, proto.FSPath{Path: dir}, &top, fsTimeout); err != nil {
		s.redirect(w, r, s.filesURL(d, winParent(dir)), err.Error())
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	name := winBase(top.Path)
	if name == "" || len(name) == 2 && name[1] == ':' {
		name = "drive-" + string(top.Path[0])
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name + ".zip"}))
	w.Header().Set("Cache-Control", "no-store")
	j := &zipJob{s: s, r: r, d: d, zw: zip.NewWriter(w)}
	j.folder(r.Context(), top, "", 0)
	if len(j.failed) > 0 {
		if f, err := j.zw.Create("_controlzit-skipped.txt"); err == nil {
			for _, p := range j.failed {
				_, _ = f.Write([]byte(p + "\r\n"))
			}
		}
	}
	_ = j.zw.Close()
	s.audit(r, "file.download.folder", "device:"+strconv.FormatInt(d.ID, 10), "downloaded folder %s as ZIP from %q: %d files, %d bytes, %d skipped",
		top.Path, d.Hostname, j.files, j.bytes, len(j.failed))
}

// folder adds the entries of one listing under prefix.
func (j *zipJob) folder(ctx context.Context, l proto.FSListing, prefix string, depth int) {
	for _, e := range l.Entries {
		if ctx.Err() != nil {
			return
		}
		full := winJoin(l.Path, e.Name)
		rel := prefix + e.Name
		if e.Link {
			j.failed = append(j.failed, full+" (link, not followed)")
			continue
		}
		if e.Dir {
			if depth >= zipMaxDepth {
				j.failed = append(j.failed, full+" (too deep)")
				continue
			}
			var sub proto.FSListing
			if err := j.s.call(ctx, j.d.ID, j.s.issuer(j.r), proto.KindFSList, proto.FSPath{Path: full}, &sub, fsTimeout); err != nil {
				j.failed = append(j.failed, full+" ("+err.Error()+")")
				continue
			}
			_, _ = j.zw.Create(rel + "/")
			j.folder(ctx, sub, rel+"/", depth+1)
			continue
		}
		if j.files >= zipMaxFiles {
			j.failed = append(j.failed, full+" (file limit reached)")
			continue
		}
		j.file(ctx, full, rel, e)
	}
	if l.Truncated {
		j.failed = append(j.failed, l.Path+" (only the first 5000 entries)")
	}
}

// file copies one file into the archive in chunks.
func (j *zipJob) file(ctx context.Context, full, rel string, e proto.FSEntry) {
	h := &zip.FileHeader{Name: rel, Method: zip.Deflate, Modified: e.Modified}
	var off int64
	var out interface{ Write([]byte) (int, error) }
	for {
		var c proto.FSReadResult
		if err := j.s.call(ctx, j.d.ID, j.s.issuer(j.r), proto.KindFSRead, proto.FSRead{Path: full, Offset: off, Length: proto.FSChunk}, &c, fsTimeout); err != nil {
			j.failed = append(j.failed, full+" ("+err.Error()+")")
			return // a partly written entry stays as far as it got
		}
		if out == nil {
			w, err := j.zw.CreateHeader(h)
			if err != nil {
				return
			}
			out = w
			j.files++
		}
		if _, err := out.Write(c.Data); err != nil {
			return
		}
		off += int64(len(c.Data))
		j.bytes += int64(len(c.Data))
		if c.EOF || len(c.Data) == 0 {
			return
		}
	}
}
