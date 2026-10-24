//go:build !windows

package agent

// ApplyWUPolicy does nothing outside Windows.
func ApplyWUPolicy(string) error { return nil }

// RestoreWUPolicy does nothing outside Windows.
func RestoreWUPolicy(string) error { return nil }
