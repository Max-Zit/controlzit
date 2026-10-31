package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/max-zit/rmmzit/internal/backup"
	"github.com/max-zit/rmmzit/internal/helper"
	"github.com/max-zit/rmmzit/internal/legacy"
	"github.com/max-zit/rmmzit/internal/store"
)

// The server in the container image (the image sets RMMZIT_CONTAINER): it
// is updated by pulling a new image, not by the root helper. Before a new
// image changes the database, a backup of the console goes to the backup
// folder, so the previous image can restore it.

func inContainer() bool { return legacy.Getenv("CONTAINER") != "" }

// imageDownloads holds the agent installers that come with the image.
const imageDownloads = "/usr/share/rmmzit/downloads"

// versionFile records the version that last started on the data directory.
const versionFile = "version"

// backupBeforeUpgrade writes a backup when another version than the last one
// starts on an existing console. It returns the backup's file name, or ""
// when none was needed.
func backupBeforeUpgrade(ctx context.Context, dbURL, dataDir, version string) (string, error) {
	vf := filepath.Join(dataDir, versionFile)
	prev, _ := os.ReadFile(vf) // #nosec G304 -- our own file
	from := strings.TrimSpace(string(prev))
	if from == version {
		return "", nil
	}
	st, err := store.Connect(ctx, dbURL)
	if err != nil {
		return "", err
	}
	defer st.Close()
	exists, err := st.HasSchema(ctx)
	if err != nil {
		return "", fmt.Errorf("database: %w", err)
	}
	name := ""
	if exists {
		if from == "" {
			from = "unknown"
		}
		dir := filepath.Join(dataDir, "backups")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		name = "rmmzit-backup-" + time.Now().Format("20060102-150405") + backup.Ext
		tmp := filepath.Join(dir, name+".part")
		f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- our own folder and name
		if err != nil {
			return "", err
		}
		_, err = backup.Create(ctx, st, dataDir, dir, from, "", f)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			err = os.Rename(tmp, filepath.Join(dir, name))
		}
		if err != nil {
			_ = os.Remove(tmp)
			return "", fmt.Errorf("backup before the update from %s: %w", from, err)
		}
	}
	return name, os.WriteFile(vf, []byte(version+"\n"), 0o600)
}

// syncImageDownloads copies the agent installers of the image into the data
// volume, where the console offers them for new agents and updates.
func syncImageDownloads(dst string) error {
	entries, err := os.ReadDir(imageDownloads)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := os.MkdirAll(dst, 0o750); err != nil {
		return err
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(imageDownloads, e.Name())) // #nosec G304 -- the image's own files
		if err != nil {
			return err
		}
		tmp := filepath.Join(dst, e.Name()+".tmp")
		if err := os.WriteFile(tmp, b, 0o600); err != nil { // #nosec G703 -- names of the image's own files
			return err
		}
		if err := os.Rename(tmp, filepath.Join(dst, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// checkHealth is the container's HEALTHCHECK: the console of this data
// directory answers its sign-in page.
func checkHealth(dataDir string) error {
	var info helper.ServerInfo
	b, err := os.ReadFile(filepath.Join(dataDir, "helper", helper.ServerFile)) // #nosec G304 -- our own file
	if err != nil || json.Unmarshal(b, &info) != nil {
		return errors.New("the server has not started yet")
	}
	_, port, err := net.SplitHostPort(info.MgmtListen)
	if err != nil {
		return err
	}
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // #nosec G402 -- the local console, only checked for an answer
	resp, err := hc.Get("https://" + net.JoinHostPort("127.0.0.1", port) + "/login")
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the console answered HTTP %d", resp.StatusCode)
	}
	return nil
}
