package proto

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"
)

// Commands are signed by the server with its command key (ed25519) and
// verified by the agent, in addition to the pinned TLS channel. A command
// is bound to one agent, expires quickly and is accepted once.

// Command is what the server signs.
type Command struct {
	ID       string          `json:"id"`
	AgentID  string          `json:"agent_id"`
	Kind     string          `json:"kind"`
	Args     json.RawMessage `json:"args,omitempty"`
	IssuedAt time.Time       `json:"issued_at"`
	Expires  time.Time       `json:"expires"`
	// Issuer is the console user, for the agent's log.
	Issuer string `json:"issuer,omitempty"`
}

// SignedCommand carries the exact signed bytes.
type SignedCommand struct {
	Command []byte `json:"command"` // JSON of Command
	Sig     []byte `json:"sig"`
}

// Result answers a command.
type Result struct {
	ID    string          `json:"id"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// MaxCommandAge is how long a command may travel; agents also allow this
// much clock difference.
const MaxCommandAge = 2 * time.Minute

const sigContext = "controlzit-command-v1\n"

// Sign makes a SignedCommand.
func Sign(key ed25519.PrivateKey, c Command) (SignedCommand, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return SignedCommand{}, err
	}
	return SignedCommand{Command: b, Sig: ed25519.Sign(key, append([]byte(sigContext), b...))}, nil
}

// Errors of Verify.
var (
	ErrBadSignature = errors.New("command signature is not valid")
	ErrWrongAgent   = errors.New("command is for another agent")
	ErrExpired      = errors.New("command expired or issued in the future")
)

// Verify checks signature, recipient and time window and returns the command.
func Verify(pub ed25519.PublicKey, sc SignedCommand, agentID string, now time.Time) (*Command, error) {
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, append([]byte(sigContext), sc.Command...), sc.Sig) {
		return nil, ErrBadSignature
	}
	var c Command
	if err := json.Unmarshal(sc.Command, &c); err != nil {
		return nil, err
	}
	if c.AgentID != agentID || c.ID == "" {
		return nil, ErrWrongAgent
	}
	if now.After(c.Expires.Add(MaxCommandAge)) || c.IssuedAt.After(now.Add(MaxCommandAge)) || c.Expires.Sub(c.IssuedAt) > 30*time.Minute {
		return nil, ErrExpired
	}
	return &c, nil
}

// ---- file manager

// Command kinds of the file manager.
const (
	KindFSDrives = "fs.drives"
	KindFSList   = "fs.list"
	KindFSRead   = "fs.read"
	KindFSWrite  = "fs.write"
	KindFSMkdir  = "fs.mkdir"
	KindFSRename = "fs.rename"
	KindFSDelete = "fs.delete"
)

// FSChunk is the size of one read or write.
const FSChunk = 1 << 20

// FSPath is the argument of list, mkdir and delete.
type FSPath struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive,omitempty"`
}

// FSEntry is a file or folder.
type FSEntry struct {
	Name     string    `json:"name"`
	Dir      bool      `json:"dir"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
	Hidden   bool      `json:"hidden,omitempty"`
}

// FSListing is the answer of fs.list.
type FSListing struct {
	Path    string    `json:"path"`
	Entries []FSEntry `json:"entries"`
	// Truncated: the folder has more entries than were sent.
	Truncated bool `json:"truncated,omitempty"`
}

// FSDrive is a drive of the machine.
type FSDrive struct {
	Path  string `json:"path"` // C:\
	Label string `json:"label"`
	Type  string `json:"type"` // fixed, removable, network, cdrom
	Size  uint64 `json:"size"`
	Free  uint64 `json:"free"`
}

// FSRead reads part of a file.
type FSRead struct {
	Path   string `json:"path"`
	Offset int64  `json:"offset"`
	Length int    `json:"length"`
}

// FSReadResult is a chunk of a file.
type FSReadResult struct {
	Data []byte `json:"data"`
	Size int64  `json:"size"` // whole file
	EOF  bool   `json:"eof"`
}

// FSWrite writes a chunk of an upload. The agent writes to Path+".czpart"
// and renames it to Path with the Final chunk.
type FSWrite struct {
	Path      string `json:"path"`
	Offset    int64  `json:"offset"`
	Data      []byte `json:"data"`
	Final     bool   `json:"final"`
	Overwrite bool   `json:"overwrite"`
}

// FSRename moves or renames.
type FSRename struct {
	From string `json:"from"`
	To   string `json:"to"`
}
