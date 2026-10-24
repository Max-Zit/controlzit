package proto

// Terminal (Linux). The console sends the signed term.start command; the
// agent opens a shell on a pseudo-terminal and connects a stream to
// PathStream with the one-time session token, like a remote desktop helper.
// Shell output goes to the browser as binary messages; keystrokes and the
// window size come back as JSON text messages (TermInput).

// KindTermStart starts a terminal session.
const KindTermStart = "term.start"

// TermStart is the argument of term.start.
type TermStart struct {
	Session    string `json:"session"`
	Token      string `json:"token"`
	Technician string `json:"technician"`
	Cols       int    `json:"cols"`
	Rows       int    `json:"rows"`
}

// TermInput is a text message from the browser: "i" types D, "r" resizes
// to Cols×Rows. The agent sends {"t":"exit","code":N} when the shell ends.
type TermInput struct {
	T    string `json:"t"`
	D    string `json:"d,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

// ValidTermSize reports whether a terminal size is sane.
func ValidTermSize(cols, rows int) bool { return cols >= 10 && cols <= 500 && rows >= 3 && rows <= 300 }
