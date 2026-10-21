package proto

import "time"

// Remote actions: services, processes, power and scripts.
const (
	KindSvcList   = "svc.list"
	KindSvcCtl    = "svc.control"
	KindProcList  = "proc.list"
	KindProcKill  = "proc.kill"
	KindPower     = "power"
	KindScriptRun = "script.run"
)

// Service is a Windows service.
type Service struct {
	Name      string `json:"name"`
	Display   string `json:"display"`
	State     string `json:"state"` // running, stopped, starting, stopping, paused
	StartType string `json:"start"` // automatic, manual, disabled, boot, system
	PID       uint32 `json:"pid,omitempty"`
}

// SvcControl starts, stops or restarts a service.
type SvcControl struct {
	Name   string `json:"name"`
	Action string `json:"action"` // start, stop, restart
}

// Process is a running process.
type Process struct {
	PID     uint32 `json:"pid"`
	PPID    uint32 `json:"ppid"`
	Name    string `json:"name"`
	Session uint32 `json:"session"`
	Memory  uint64 `json:"mem"` // working set, bytes
	Threads uint32 `json:"threads"`
}

// ProcKill ends a process.
type ProcKill struct {
	PID  uint32 `json:"pid"`
	Name string `json:"name"` // must still match, so a reused PID is not hit
}

// Power restarts or shuts down the machine.
type Power struct {
	Action  string `json:"action"` // restart, shutdown, cancel
	Delay   int    `json:"delay"`  // seconds, 0–3600
	Message string `json:"message,omitempty"`
}

// ScriptRun runs a script as SYSTEM and returns its output.
type ScriptRun struct {
	Shell   string `json:"shell"` // powershell, cmd
	Script  string `json:"script"`
	Timeout int    `json:"timeout"` // seconds, 5–3600
}

// ScriptResult is the outcome of a script.
type ScriptResult struct {
	ExitCode  int           `json:"exit_code"`
	Output    string        `json:"output"` // stdout and stderr, capped
	Truncated bool          `json:"truncated,omitempty"`
	TimedOut  bool          `json:"timed_out,omitempty"`
	Duration  time.Duration `json:"duration"`
}

// MaxScriptOutput caps the output kept from a script.
const MaxScriptOutput = 1 << 20

// MaxScriptSize caps the script text.
const MaxScriptSize = 256 << 10
