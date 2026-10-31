package web

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Files the technician pastes into a remote desktop session (Ctrl+V or drag
// and drop): the viewer uploads them here into the staging folder the
// helper made, then asks the helper to put them on the remote clipboard.
// The answer is JSON, since the viewer stays on its page.

type rdUploadResult struct {
	Paths []string `json:"paths,omitempty"`
	Error string   `json:"error,omitempty"`
}

func (s *Server) handleRDUpload(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	lang := s.lang(r, userFrom(r))
	answer := func(status int, res rdUploadResult) {
		if res.Error != "" {
			res.Error = translate(lang, res.Error)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(res)
	}
	if !d.IsWindows() || !s.Remote(r.Context()).Clipboard {
		answer(http.StatusForbidden, rdUploadResult{Error: "Copying files through the clipboard is switched off or not available for this device."})
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})
	r.Body = http.MaxBytesReader(w, r.Body, maxUpload+1<<20)
	mr, err := r.MultipartReader()
	if err != nil {
		answer(http.StatusBadRequest, rdUploadResult{Error: "bad upload"})
		return
	}
	var dir string
	var res rdUploadResult
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			answer(http.StatusBadRequest, rdUploadResult{Error: "bad upload"})
			return
		}
		switch part.FormName() {
		case "dir":
			b, _ := io.ReadAll(io.LimitReader(part, 4096))
			dir = string(b)
			continue
		case "file":
		default:
			continue
		}
		name := winBase(strings.ReplaceAll(part.FileName(), "/", `\`))
		// Only the helper's staging folders, in a user's Temp (ControlZit:
		// agents from before the rename to RMMZit).
		low := strings.ToLower(dir)
		staged := strings.Contains(low, `\appdata\local\temp\rmmzit\`) || strings.Contains(low, `\appdata\local\temp\controlzit\`)
		if !isWinAbs(dir) || !staged || strings.Contains(dir, "..") || validName(name) != nil {
			answer(http.StatusBadRequest, rdUploadResult{Error: "Choose a folder and a file with a valid name."})
			return
		}
		target := winJoin(dir, name)
		n, err := s.uploadTo(r, d, target, part, true)
		if err != nil {
			s.audit(r, "file.upload.failed", "device:"+strconv.FormatInt(d.ID, 10), "paste of %s to %q failed after %d bytes: %v", target, d.Hostname, n, err)
			answer(http.StatusBadGateway, rdUploadResult{Error: "Upload failed: " + err.Error()})
			return
		}
		s.audit(r, "file.upload", "device:"+strconv.FormatInt(d.ID, 10), "pasted %s (%d bytes) into the remote desktop of %q", target, n, d.Hostname)
		res.Paths = append(res.Paths, target)
	}
	if len(res.Paths) == 0 {
		answer(http.StatusBadRequest, rdUploadResult{Error: "No file was chosen."})
		return
	}
	answer(http.StatusOK, res)
}

// isWinAbs reports whether p is an absolute Windows path (C:\…).
func isWinAbs(p string) bool {
	return len(p) >= 3 && p[1] == ':' && p[2] == '\\' && (p[0]|0x20) >= 'a' && (p[0]|0x20) <= 'z'
}
