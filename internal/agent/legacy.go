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
// old directory that holds no enrollment any more.
func AdoptLegacyDir() string {
	if runtime.GOOS == "windows" {
		// The status folder of the old tray.
		if d := os.Getenv("ProgramData"); filepath.IsAbs(d) {
			_ = os.RemoveAll(filepath.Join(d, "ControlZit")) // #nosec G703 -- a fixed folder under ProgramData
		}
	}
	dir, old := newDir(), legacyDir()
	oldEnrolled := exists(filepath.Join(old, configFile)) || exists(filepath.Join(old, keyFile))
	switch {
	case !exists(old):
		return dir
	case !exists(dir):
		// Right after an upgrade the installer still writes its log into
		// the old folder (Windows), so it cannot be moved: copy it, and take
		// the enrollment out of the old folder; the next start removes what
		// is left of it.
		if os.Rename(old, dir) != nil {
			if err := copyDir(old, dir); err != nil {
				_ = os.RemoveAll(dir)
				return old // used where it is; the next start tries again
			}
			_ = ProtectDir(dir)
			_ = os.Remove(filepath.Join(old, configFile))
			_ = os.Remove(filepath.Join(old, keyFile))
			_ = os.RemoveAll(old)
		}
		if exists(filepath.Join(dir, configFile)) {
			markEnrolled(true) // under the new name, for the next installer
		}
		return dir
	case !oldEnrolled && exists(filepath.Join(dir, configFile)):
		_ = os.RemoveAll(old) // left-overs (downloaded updates, logs) of the old version
		return dir
	}
	return currentDir(dir)
}

// copyDir copies a directory tree. Files that cannot be read (in use) are
// skipped, except the enrollment itself.
func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p) // #nosec G304 G122 -- the agent's own folder, writable only by SYSTEM and administrators
		if err == nil {
			err = os.WriteFile(target, b, 0o600) // #nosec G703 -- inside the agent's own folder
		}
		if err != nil && (rel == configFile || rel == keyFile) {
			return err
		}
		return nil
	})
}
