package proto

import (
	"errors"
	"fmt"
	"strings"
)

// Monitors of policies (agents 0.12+): the server asks a device every few
// minutes how many matching events its Windows event logs got and whether
// some processes run.
const KindMonitorCheck = "monitor.check"

// Monitor limits.
const (
	MaxEventMonitors   = 20
	MaxProcessMonitors = 30
	MaxEventIDs        = 10
)

// EventMonitor counts the events of Log in the last Minutes with one of IDs
// (none: any), from Source (empty: any) and at Level or more severe
// (0: any; 1 critical, 2 error, 3 warning).
type EventMonitor struct {
	Key     string `json:"key"`
	Log     string `json:"log"`
	IDs     []int  `json:"ids,omitempty"`
	Source  string `json:"source,omitempty"`
	Level   int    `json:"level,omitempty"`
	Minutes int    `json:"minutes"`
}

// Valid checks an event monitor.
func (e EventMonitor) Valid() error {
	known := false
	for _, l := range EventLogs {
		known = known || l == e.Log
	}
	switch {
	case !known:
		return fmt.Errorf("unknown event log %q", e.Log)
	case len(e.IDs) > MaxEventIDs:
		return fmt.Errorf("at most %d event IDs per rule", MaxEventIDs)
	case e.Level < 0 || e.Level > 3:
		return errors.New("unknown event level")
	case e.Minutes < 5 || e.Minutes > 1440:
		return errors.New("an event rule looks back 5–1440 minutes")
	case len(e.Source) > 200 || strings.ContainsAny(e.Source, `'"<>&[]`):
		return errors.New("the event source must not hold quotes or brackets")
	}
	for _, id := range e.IDs {
		if id < 0 || id > 65535 {
			return errors.New("event IDs are 0–65535")
		}
	}
	return nil
}

// MonitorRun is the argument of monitor.check.
type MonitorRun struct {
	Events    []EventMonitor `json:"events,omitempty"`
	Processes []string       `json:"processes,omitempty"`
}

// MonitorResults is the answer: per event monitor the count (or an error),
// per process whether it runs.
type MonitorResults struct {
	Events    []EventCount   `json:"events"`
	Processes []ProcessState `json:"processes"`
}

// EventCount is how many events an event monitor found.
type EventCount struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
	Error string `json:"error,omitempty"`
}

// ProcessState tells whether a process runs.
type ProcessState struct {
	Name    string `json:"name"`
	Running bool   `json:"running"`
}

// SameProcess compares process names without case and without ".exe".
func SameProcess(a, b string) bool {
	trim := func(s string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".exe") }
	return trim(a) == trim(b)
}
