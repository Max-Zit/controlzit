//go:build windows

package rd

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/max-zit/controlzit/internal/proto"
)

// Files on the clipboard, the way Explorer copies them: CF_HDROP (a
// DROPFILES header followed by the paths) and "Preferred DropEffect" = copy,
// so a paste copies instead of moving.

const (
	cfHDrop       = 15
	gmemZeroInit  = 0x0040
	dropFilesSize = 20 // pFiles, pt.x, pt.y, fNC, fWide
	dropEffectCpy = 1
)

var (
	pRegisterClipboardFormat = user32.NewProc("RegisterClipboardFormatW")
)

// SetFiles puts files on the clipboard as copied files.
func (c *Clipboard) SetFiles(paths []string) error {
	done := make(chan error, 1)
	c.req <- func() { done <- c.setFiles(paths) }
	return <-done
}

func globalBytes(b []byte) (uintptr, error) {
	h, _, _ := pGlobalAlloc.Call(gmemMoveable|gmemZeroInit, uintptr(len(b)))
	if h == 0 {
		return 0, errors.New("out of memory")
	}
	p, _, _ := pGlobalLock.Call(h)
	if p == 0 {
		_, _, _ = pGlobalFree.Call(h)
		return 0, errors.New("GlobalLock failed")
	}
	copy(unsafe.Slice((*byte)(ptrOf(p)), len(b)), b) // #nosec G103 -- allocated for len(b) bytes
	_, _, _ = pGlobalUnlock.Call(h)
	return h, nil
}

func (c *Clipboard) setFiles(paths []string) error {
	var u []uint16
	for _, p := range paths {
		u = append(u, utf16.Encode([]rune(p))...)
		u = append(u, 0)
	}
	u = append(u, 0)
	b := make([]byte, dropFilesSize+2*len(u))
	binary.LittleEndian.PutUint32(b[0:], dropFilesSize) // the paths follow the header
	binary.LittleEndian.PutUint32(b[16:], 1)            // fWide: UTF-16 paths
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[dropFilesSize+2*i:], v)
	}
	hDrop, err := globalBytes(b)
	if err != nil {
		return err
	}
	effect := make([]byte, 4)
	binary.LittleEndian.PutUint32(effect, dropEffectCpy)
	hEffect, err := globalBytes(effect)
	if err != nil {
		_, _, _ = pGlobalFree.Call(hDrop)
		return err
	}
	name, _ := windows.UTF16PtrFromString("Preferred DropEffect")
	cfEffect, _, _ := pRegisterClipboardFormat.Call(uintptr(unsafe.Pointer(name))) // #nosec G103 -- Win32 string
	if err := c.open(); err != nil {
		_, _, _ = pGlobalFree.Call(hDrop)
		_, _, _ = pGlobalFree.Call(hEffect)
		return err
	}
	_, _, _ = pEmptyClipboard.Call()
	r, _, serr := pSetClipboardData.Call(cfHDrop, hDrop)
	if r == 0 {
		_, _, _ = pCloseClipboard.Call()
		_, _, _ = pGlobalFree.Call(hDrop)
		_, _, _ = pGlobalFree.Call(hEffect)
		return errors.New("SetClipboardData: " + serr.Error())
	}
	if cfEffect == 0 || func() bool { r, _, _ := pSetClipboardData.Call(cfEffect, hEffect); return r == 0 }() {
		_, _, _ = pGlobalFree.Call(hEffect)
	}
	_, _, _ = pCloseClipboard.Call()
	// Do not report these files back as copied on the remote computer.
	c.lastSeq, _, _ = pGetClipboardSequenceNumber.Call()
	return nil
}

// readFiles returns the copied files, if the clipboard holds files (on the
// clipboard thread).
func (c *Clipboard) readFiles() ([]string, error) {
	if r, _, _ := pIsClipboardFormatAvailable.Call(cfHDrop); r == 0 {
		return nil, nil
	}
	if err := c.open(); err != nil {
		return nil, err
	}
	defer func() { _, _, _ = pCloseClipboard.Call() }()
	h, _, _ := pGetClipboardData.Call(cfHDrop)
	if h == 0 {
		return nil, nil
	}
	p, _, _ := pGlobalLock.Call(h)
	if p == 0 {
		return nil, nil
	}
	defer func() { _, _, _ = pGlobalUnlock.Call(h) }()
	size, _, _ := pGlobalSize.Call(h)
	if size < dropFilesSize+2 || size > 16<<20 {
		return nil, nil
	}
	b := unsafe.Slice((*byte)(ptrOf(p)), int(size)) // #nosec G103 -- locked global memory of size bytes
	off := int(binary.LittleEndian.Uint32(b[0:]))
	wide := binary.LittleEndian.Uint32(b[16:]) != 0
	if !wide || off < dropFilesSize || off >= len(b) {
		return nil, nil // ANSI file lists are not used by current Windows programs
	}
	var out []string
	var cur []uint16
	for i := off; i+1 < len(b); i += 2 {
		v := binary.LittleEndian.Uint16(b[i:])
		if v != 0 {
			cur = append(cur, v)
			continue
		}
		if len(cur) == 0 {
			break // the double zero at the end
		}
		out = append(out, string(utf16.Decode(cur)))
		cur = cur[:0]
		if len(out) >= proto.MaxClipFiles {
			break
		}
	}
	return out, nil
}

// FileItems marks which copied paths are folders.
func FileItems(paths []string) []proto.RDFileItem {
	out := make([]proto.RDFileItem, 0, len(paths))
	for _, p := range paths {
		st, err := os.Stat(p)
		out = append(out, proto.RDFileItem{Path: p, Dir: err == nil && st.IsDir()})
	}
	return out
}

// StageDir makes a fresh folder for files the technician pastes, in the
// Temp folder of the user signed in to this session, so that the user's
// programs can read them (the helper itself runs as SYSTEM). Staging
// folders older than a day are removed.
func StageDir() (string, error) {
	base, err := userTemp()
	if err != nil {
		return "", err
	}
	base = filepath.Join(base, "ControlZit")
	if old, err := os.ReadDir(base); err == nil {
		for _, e := range old {
			if info, err := e.Info(); err == nil && e.IsDir() && time.Since(info.ModTime()) > 24*time.Hour {
				_ = os.RemoveAll(filepath.Join(base, e.Name()))
			}
		}
	}
	dir := filepath.Join(base, time.Now().Format("20060102-150405.000"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// InStage reports whether every path lies in a staging folder.
func InStage(paths []string) bool {
	base, err := userTemp()
	if err != nil || len(paths) == 0 || len(paths) > proto.MaxClipFiles {
		return false
	}
	base = strings.ToLower(filepath.Join(base, "ControlZit")) + `\`
	for _, p := range paths {
		if !strings.HasPrefix(strings.ToLower(filepath.Clean(p)), base) || strings.Contains(p, "..") {
			return false
		}
	}
	return true
}

// userTemp is %LOCALAPPDATA%\Temp of the user signed in to this session.
func userTemp() (string, error) {
	var sid uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sid); err != nil {
		return "", err
	}
	var tok windows.Token
	if err := windows.WTSQueryUserToken(sid, &tok); err != nil {
		// Not SYSTEM (a test run): this process's own Temp.
		if t := os.Getenv("TEMP"); t != "" && !isSystemToken() {
			return t, nil
		}
		return "", errors.New("nobody is signed in to the remote computer")
	}
	defer tok.Close()
	prof, err := tok.GetUserProfileDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(prof, "AppData", "Local", "Temp"), nil
}

func isSystemToken() bool {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && tu.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}
