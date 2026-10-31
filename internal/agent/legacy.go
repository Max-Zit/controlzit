package agent

import (
	"os"
	"path/filepath"
	"runtime"
)

// Before the rename to RMMZit the agent was the ControlZit Agent. An agent
// installed then keeps its enrollment: when the new version starts as the
// service, the old data directory is moved to the new place
// (AdoptLegacyDir). Other commands only find it (DefaultDir): an agent of
// the old version runs the new program ("version") before it installs it,
// while it still uses the old directory itself.

// legacyDir is the data directory of agents from before the rename.
func legacyDir() string {
	if runtime.GOOS == "windows" {
		if p := os.Getenv("ProgramData"); p != "" {
			return filepath.Join(p, "ControlZit Agent")
		}
		return `C:\ProgramData\ControlZit Agent`
	}
	return "/var/lib/controlzit-agent"
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// currentDir is the directory that holds the enrollment: dir, or the old
// one when only that one has it.
func currentDir(dir string) string {
	old := legacyDir()
	switch {
	case exists(filepath.Join(dir, configFile)):
		return dir
	case exists(filepath.Join(old, configFile)):
		return old
	case !exists(dir) && exists(old):
		return old
	}
	return dir
}

// AdoptLegacyDir is DefaultDir for the service: it moves the old data
// directory to the new place when that does not exist yet, and removes an
// old directory that holds no enrollment any more. When the move fails
// (a file in use), the old directory is used where it is.
func AdoptLegacyDir() string {
	dir, old := newDir(), legacyDir()
	oldEnrolled := exists(filepath.Join(old, configFile)) || exists(filepath.Join(old, keyFile))
	switch {
	case !exists(old):
		return dir
	case !exists(dir):
		if os.Rename(old, dir) != nil {
			return old
		}
		if exists(filepath.Join(dir, configFile)) {
			markEnrolled(true) // under the new name, for the next installer
		}
		return dir
	case !oldEnrolled && exists(filepath.Join(dir, configFile)):
		_ = os.RemoveAll(old) // left-overs (downloaded updates) of the old version
		return dir
	}
	return currentDir(dir)
}
