package proto

import "time"

// Windows event logs.
const KindEventQuery = "evt.query"

// EventQuery asks for recent events of one log.
type EventQuery struct {
	Log   string `json:"log"`   // System, Application, Security, Setup
	Level int    `json:"level"` // 0 all, 1 critical, 2 error and worse, 3 warning and worse
	Hours int    `json:"hours"` // 1–720
	Max   int    `json:"max"`   // 1–1000
	Text  string `json:"text,omitempty"`
	ID    int    `json:"id,omitempty"` // event ID (0: any)
}

// EventLogs are the logs the console offers.
var EventLogs = []string{"System", "Application", "Security", "Setup"}

// Event is one entry of a Windows event log.
type Event struct {
	Time     time.Time `json:"time"`
	Level    int       `json:"level"` // 1 critical, 2 error, 3 warning, 4 information (0 and 5: other)
	ID       int       `json:"id"`
	Provider string    `json:"provider"`
	Message  string    `json:"message"`
}

// EventResult is the answer to evt.query.
type EventResult struct {
	Events    []Event `json:"events"`
	Truncated bool    `json:"truncated,omitempty"`
}
