package agent

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

// Before the rename to RMMZit the agent was the ControlZit Agent. An agent
// installed then keeps its enrollment: the first time the new version
// looks for its data directory, the old one is moved to the new place.

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

// adoptLegacyDir moves the old data directory to dir when only the old one
// exists. When it cannot be moved (another user, a file in use), the old
// directory is used where it is.
func adoptLegacyDir(dir string) string {
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		return dir
	}
	old := legacyDir()
	fi, err := os.Stat(old)
	if err != nil || !fi.IsDir() {
		return dir
	}
	if os.Rename(old, dir) != nil {
		return old
	}
	if _, err := os.Stat(filepath.Join(dir, configFile)); err == nil {
		markEnrolled(true) // under the new name, for the next installer
	}
	return dir
}
