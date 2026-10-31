// Package legacy keeps installations from before the rename to RMMZit
// working: the product was called ControlZit until version 0.12.
package legacy

import (
	"os"
	"path/filepath"
	"strings"
)

// Getenv reads RMMZIT_<name>, or CONTROLZIT_<name> when that is not set
// (configuration files of older installations).
func Getenv(name string) string {
	if v := os.Getenv("RMMZIT_" + name); v != "" {
		return v
	}
	return os.Getenv("CONTROLZIT_" + name)
}

// Lookup is Getenv for a configuration file read into a map.
func Lookup(env map[string]string, name string) string {
	if v := env["RMMZIT_"+name]; v != "" {
		return v
	}
	return env["CONTROLZIT_"+name]
}

// ProgramName is the name a program reports with -version: the old one when
// it was started under it. Installers from before the rename check the name
// of the program they installed.
func ProgramName(newName, oldName string) string {
	if strings.HasPrefix(filepath.Base(os.Args[0]), oldName) {
		return oldName
	}
	return newName
}
