package agent

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
)

// self is the running agent (set by Run) for commands that need its
// identity, such as downloading an update.
var self *Agent

var updating atomic.Bool

// RunInstaller starts the downloaded installer (tests replace it).
var RunInstaller = startInstaller

// UpdateResult tells the server what the agent did with agent.update.
type UpdateResult struct {
	Started bool   `json:"started"`
	Current string `json:"current"`
}

func init() {
	register(proto.KindAgentUpdate, func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a proto.AgentUpdate
		if err := args(raw, &a); err != nil {
			return nil, err
		}
		return selfUpdate(ctx, a)
	})
}

func selfUpdate(ctx context.Context, a proto.AgentUpdate) (*UpdateResult, error) {
	want, err := hex.DecodeString(a.SHA256)
	if !proto.ValidVersion(a.Version) || err != nil || len(want) != sha256.Size || a.Size <= 0 || a.Size > proto.MaxPackageSize {
		return nil, errors.New("bad update request")
	}
	if proto.CompareVersions(a.Version, Version) <= 0 {
		return &UpdateResult{Current: Version}, nil // already this version or newer
	}
	if self == nil {
		return nil, errors.New("the agent is not running")
	}
	if !updating.CompareAndSwap(false, true) {
		return nil, errors.New("an update is already running")
	}
	path, err := self.downloadPackage(ctx, a, want)
	if err != nil {
		updating.Store(false)
		return nil, err
	}
	self.Log.Info("installing agent update", "version", a.Version, "file", path)
	if err := RunInstaller(path, filepath.Join(filepath.Dir(path), "update-"+a.Version+".log")); err != nil {
		updating.Store(false)
		return nil, fmt.Errorf("cannot start the installer: %w", err)
	}
	// The installer stops and replaces this service; if that does not
	// happen, allow another attempt later.
	time.AfterFunc(15*time.Minute, func() { updating.Store(false) })
	return &UpdateResult{Started: true, Current: Version}, nil
}

// downloadPackage fetches the installer over the pinned channel identity and
// checks it against the signed hash.
func (a *Agent) downloadPackage(ctx context.Context, u proto.AgentUpdate, want []byte) (string, error) {
	cert, err := clientCert(a.key)
	if err != nil {
		return "", err
	}
	hc := httpClient(pinnedTLS(a.Cfg.Fingerprint, cert))
	hc.Timeout = 10 * time.Minute
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.Cfg.ServerURL+proto.PathPackage, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "controlzit-agent/"+Version)
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download: server answered %s", resp.Status)
	}
	dir := filepath.Join(a.Dir, "updates")
	_ = os.RemoveAll(dir) // older downloads
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "controlzit-agent-"+u.Version+packageExt)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- our own directory and a validated version
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, u.Size+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n != u.Size {
		err = fmt.Errorf("the installer has %d bytes, expected %d", n, u.Size)
	}
	if err == nil && subtle.ConstantTimeCompare(h.Sum(nil), want) != 1 {
		err = errors.New("the installer does not match the signed update (SHA-256)")
	}
	if err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}
