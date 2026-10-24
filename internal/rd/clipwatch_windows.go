//go:build windows

package rd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// The helper runs as SYSTEM, and Windows does not show a SYSTEM process the
// files that Explorer (or any program of the user) puts on the clipboard
// through OLE: text arrives, CF_HDROP does not. So a small process of the
// signed-in user (controlzit-agent clipwatch) watches for copied files and
// reports them to the helper as JSON lines on its standard output.

// WatchFiles is the clipwatch command: it writes one JSON array of paths per
// copy of files until ctx ends or standard input closes (the helper ended).
func WatchFiles(ctx context.Context, out io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _, _ = io.Copy(io.Discard, os.Stdin); cancel() }()
	enc := json.NewEncoder(out)
	if _, err := StartClipboard(ctx, nil, func(paths []string) { _ = enc.Encode(paths) }); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}

// startFileWatcher runs clipwatch as the user signed in to this session and
// calls onFiles for each copy. It returns false when that is not possible
// (nobody signed in, or the helper does not run as SYSTEM).
func startFileWatcher(ctx context.Context, onFiles func([]string)) (bool, error) {
	if !isSystemToken() {
		return false, nil
	}
	var sid uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sid); err != nil {
		return false, err
	}
	var tok windows.Token
	if err := windows.WTSQueryUserToken(sid, &tok); err != nil {
		return false, errors.New("nobody is signed in")
	}
	exe, err := os.Executable()
	if err != nil {
		_ = tok.Close()
		return false, err
	}
	cmd := exec.CommandContext(ctx, exe, "clipwatch") // #nosec G204 -- our own executable
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(tok), HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		_ = tok.Close()
		return false, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = tok.Close()
		return false, err
	}
	if err := cmd.Start(); err != nil {
		_ = tok.Close()
		return false, err
	}
	_ = tok.Close()
	go func() {
		defer func() { _ = stdin.Close(); _ = cmd.Wait() }()
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			var paths []string
			if json.Unmarshal(sc.Bytes(), &paths) == nil && len(paths) > 0 {
				onFiles(paths)
			}
		}
	}()
	return true, nil
}
