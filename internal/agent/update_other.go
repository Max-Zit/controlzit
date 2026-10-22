//go:build !windows

package agent

import "errors"

const packageExt = ".pkg"

func startInstaller(string, string) error {
	return errors.New("self-update is only available on Windows")
}
