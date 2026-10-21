package agent

import (
	"io"
	"os"
	"path/filepath"
	"sync"
)

// maxLog is the size at which agent.log is rotated to agent.log.1.
const maxLog = 10 << 20

// OpenLog returns a writer to dir/agent.log with simple size rotation;
// it never fails (falls back to discarding).
func OpenLog(dir string) io.Writer {
	if err := EnsureDir(dir); err != nil {
		return io.Discard
	}
	return &rotLog{path: filepath.Join(dir, LogFile)}
}

type rotLog struct {
	mu   sync.Mutex
	path string
	f    *os.File
	n    int64
}

func (l *rotLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil || l.n > maxLog {
		if l.f != nil {
			_ = l.f.Close()
			_ = os.Rename(l.path, l.path+".1")
		}
		f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- fixed name in the data directory
		if err != nil {
			return len(p), nil
		}
		st, _ := f.Stat()
		l.f, l.n = f, 0
		if st != nil {
			l.n = st.Size()
		}
	}
	n, err := l.f.Write(p)
	l.n += int64(n)
	return n, err
}
