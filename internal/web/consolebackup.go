package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/max-zit/rmmzit/internal/backup"
)

// Backups of the console itself: the database with the secret key, the
// certificates and the software library, written to data-dir/backups on a
// schedule (and on request), optionally encrypted and copied to an SFTP
// folder. A restore runs with the server stopped (rmmzit-server
// -restore, or the appliance's setup menu).

const (
	settingBackup = "backup"
	backupPrefix  = "rmmzit-backup-"
	legacyPrefix  = "controlzit-backup-" // backups made before the rename to RMMZit
	sealBackupKey = "settings.backup.passphrase"
	sealSFTPPass  = "settings.backup.sftp.password"
	sealSFTPKey   = "settings.backup.sftp.key"
)

// BackupSettings control the console backups. The passphrase and the SFTP
// password and key are sealed with the server's secret key.
type BackupSettings struct {
	Enabled    bool   `json:"enabled"`
	Hour       int    `json:"hour"`
	Keep       int    `json:"keep"`
	Passphrase string `json:"passphrase,omitempty"`
	SFTP       struct {
		Enabled  bool   `json:"enabled"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		User     string `json:"user"`
		Password string `json:"password,omitempty"`
		Key      string `json:"key,omitempty"`
		Dir      string `json:"dir"`
		HostKey  string `json:"host_key"`
	} `json:"sftp"`
	LastRun   time.Time `json:"last_run"`
	LastOK    bool      `json:"last_ok"`
	LastError string    `json:"last_error,omitempty"`
	LastFile  string    `json:"last_file,omitempty"`
	LastSize  int64     `json:"last_size,omitempty"`
	LastCopy  string    `json:"last_copy,omitempty"` // SFTP result of the last backup
}

func (s *Server) backupSettings(ctx context.Context) BackupSettings {
	b := BackupSettings{Hour: 2, Keep: 7}
	_ = s.store.GetSetting(ctx, settingBackup, &b)
	if b.Keep < 1 {
		b.Keep = 7
	}
	return b
}

// backupRunner allows one backup at a time.
type backupRunner struct {
	mu      sync.Mutex
	running bool
}

func (s *Server) backupDir() string { return filepath.Join(s.DataDir, "backups") }

// RunBackups starts the scheduled backup once a day at the set hour.
func (s *Server) RunBackups(ctx context.Context) {
	if s.DataDir == "" {
		return
	}
	b := s.backupSettings(ctx)
	now := s.now().Local()
	if !b.Enabled || now.Hour() != b.Hour {
		return
	}
	if last := b.LastRun.Local(); last.Year() == now.Year() && last.YearDay() == now.YearDay() {
		return
	}
	s.startBackup("system")
}

// startBackup runs a backup in the background; false when one runs.
func (s *Server) startBackup(by string) bool {
	s.backups.mu.Lock()
	if s.backups.running {
		s.backups.mu.Unlock()
		return false
	}
	s.backups.running = true
	s.backups.mu.Unlock()
	go func() { // #nosec G118 -- a backup outlives the request or tick that started it
		defer func() {
			s.backups.mu.Lock()
			s.backups.running = false
			s.backups.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
		defer cancel()
		s.runBackup(ctx, by)
	}()
	return true
}

func (s *Server) backupRunning() bool {
	s.backups.mu.Lock()
	defer s.backups.mu.Unlock()
	return s.backups.running
}

// runBackup writes one backup, prunes the old ones, copies it to SFTP and
// records the outcome (audit log; an alert email when it fails).
func (s *Server) runBackup(ctx context.Context, by string) {
	b := s.backupSettings(ctx)
	start := s.now()
	name, size, err := s.writeBackup(ctx, b, start)
	b.LastRun, b.LastOK, b.LastError, b.LastCopy = start, err == nil, "", ""
	if err != nil {
		b.LastError = clip(err.Error(), 500)
	} else {
		b.LastFile, b.LastSize = name, size
		s.pruneBackups(b.Keep)
		if b.SFTP.Enabled {
			if cerr := s.copyBackup(ctx, b, name); cerr != nil {
				b.LastOK, b.LastCopy = false, clip("SFTP: "+cerr.Error(), 500)
			} else {
				b.LastCopy = "ok"
			}
		}
	}
	fresh := s.backupSettings(ctx) // keep settings saved meanwhile
	fresh.LastRun, fresh.LastOK, fresh.LastError, fresh.LastFile, fresh.LastSize, fresh.LastCopy = b.LastRun, b.LastOK, b.LastError, b.LastFile, b.LastSize, b.LastCopy
	_ = s.store.SetSetting(ctx, settingBackup, fresh)
	switch {
	case err != nil:
		s.log.Error("console backup failed", "err", err)
		_ = s.store.Audit(ctx, by, "", "backup.failed", "settings", "console backup failed: "+b.LastError)
		s.mailAdmins(ctx, "RMMZit: the console backup failed", "The backup of "+start.Local().Format("2006-01-02 15:04")+" failed:\n\n"+b.LastError+"\n\nSettings → Console backup shows the details.\n")
	case b.LastCopy != "" && b.LastCopy != "ok":
		_ = s.store.Audit(ctx, by, "", "backup.create", "settings", "console backup "+name+" ("+formatBytes(uint64(size))+"); copy failed: "+b.LastCopy) // #nosec G115 -- a file size
		s.mailAdmins(ctx, "RMMZit: the backup copy failed", "The backup "+name+" was written on the server, but the copy to the SFTP folder failed:\n\n"+b.LastCopy+"\n")
	default:
		_ = s.store.Audit(ctx, by, "", "backup.create", "settings", "console backup "+name+" ("+formatBytes(uint64(size))+")") // #nosec G115 -- a file size
	}
}

// mailAdmins sends a notice to the alert email recipients, when set up.
func (s *Server) mailAdmins(ctx context.Context, subject, body string) {
	m := s.Monitoring(ctx)
	e := s.Email(ctx)
	if len(m.Recipients) == 0 || !e.Configured() {
		return
	}
	mctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := sendMail(mctx, e, m.Recipients, subject, body); err != nil {
		s.log.Warn("notice email failed", "err", err)
	}
}

// writeBackup writes the backup file through a temporary name.
func (s *Server) writeBackup(ctx context.Context, b BackupSettings, at time.Time) (string, int64, error) {
	dir := s.backupDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", 0, err
	}
	pass := ""
	if b.Passphrase != "" {
		p, err := s.store.OpenSecret(sealBackupKey, b.Passphrase)
		if err != nil {
			return "", 0, errors.New("the backup passphrase cannot be read; set it again")
		}
		pass = p
	}
	name := backupPrefix + at.Local().Format("20060102-150405") + backup.Ext
	tmp := filepath.Join(dir, name+".part")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- our own folder and name
	if err != nil {
		return "", 0, err
	}
	_, err = backup.Create(ctx, s.store, s.DataDir, dir, s.Version, pass, f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return "", 0, err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return "", 0, err
	}
	st, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		return "", 0, err
	}
	return name, st.Size(), nil
}

// backupFile is a backup in the local folder.
type backupFile struct {
	Name      string
	Size      uint64
	At        time.Time
	Encrypted bool
}

// localBackups lists the backups, newest first.
func (s *Server) localBackups() []backupFile {
	ents, err := os.ReadDir(s.backupDir())
	if err != nil {
		return nil
	}
	var out []backupFile
	for _, e := range ents {
		n := e.Name()
		if !e.Type().IsRegular() || backupStamp(n) == "" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		bf := backupFile{Name: n, Size: uint64(info.Size()), At: info.ModTime()} // #nosec G115 -- a file size
		if f, err := os.Open(filepath.Join(s.backupDir(), n)); err == nil {      // #nosec G304 -- our own folder
			head := make([]byte, 7)
			_, _ = io.ReadFull(f, head)
			bf.Encrypted = string(head) == "CZENC1\n"
			_ = f.Close()
		}
		out = append(out, bf)
	}
	slices.SortFunc(out, func(a, b backupFile) int { return strings.Compare(backupStamp(b.Name), backupStamp(a.Name)) })
	return out
}

// pruneBackups keeps the newest keep backups (and removes left-over parts).
func (s *Server) pruneBackups(keep int) {
	list := s.localBackups()
	for i := keep; i < len(list); i++ {
		_ = os.Remove(filepath.Join(s.backupDir(), list[i].Name))
	}
	if ents, err := os.ReadDir(s.backupDir()); err == nil {
		for _, e := range ents {
			if strings.HasSuffix(e.Name(), ".part") || strings.HasSuffix(e.Name(), ".tmp") {
				if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > 7*time.Hour {
					_ = os.Remove(filepath.Join(s.backupDir(), e.Name()))
				}
			}
		}
	}
}

// sftpOf opens the sealed SFTP secrets of the settings.
func (s *Server) sftpOf(b BackupSettings) (backup.SFTP, error) {
	c := backup.SFTP{Host: b.SFTP.Host, Port: b.SFTP.Port, User: b.SFTP.User, Dir: b.SFTP.Dir, HostKey: b.SFTP.HostKey}
	var err error
	if b.SFTP.Password != "" {
		if c.Password, err = s.store.OpenSecret(sealSFTPPass, b.SFTP.Password); err != nil {
			return c, uiErr("The SFTP password cannot be read; set it again.")
		}
	}
	if b.SFTP.Key != "" {
		if c.Key, err = s.store.OpenSecret(sealSFTPKey, b.SFTP.Key); err != nil {
			return c, uiErr("The SFTP key cannot be read; set it again.")
		}
	}
	return c, nil
}

func (s *Server) copyBackup(ctx context.Context, b BackupSettings, name string) error {
	c, err := s.sftpOf(b)
	if err != nil {
		return err
	}
	f, err := os.Open(filepath.Join(s.backupDir(), name)) // #nosec G304 -- our own folder and name
	if err != nil {
		return err
	}
	defer f.Close()
	return backup.UploadSFTP(ctx, c, name, backupPrefix, b.Keep, f)
}

// ---- pages

type backupData struct {
	S       BackupSettings
	Files   []backupFile
	Hours   []int
	Running bool
	HasPass bool
	HasPw   bool
	HasKey  bool
}

func (s *Server) handleBackupSettings(w http.ResponseWriter, r *http.Request) {
	b := s.backupSettings(r.Context())
	hours := make([]int, 24)
	for i := range hours {
		hours[i] = i
	}
	d := &backupData{S: b, Files: s.localBackups(), Hours: hours, Running: s.backupRunning(),
		HasPass: b.Passphrase != "", HasPw: b.SFTP.Password != "", HasKey: b.SFTP.Key != ""}
	d.S.Passphrase, d.S.SFTP.Password, d.S.SFTP.Key = "", "", ""
	s.render(w, r, http.StatusOK, "backup", &Page{Title: "Console backup", Nav: "settings", Data: d})
}

func (s *Server) handleBackupSave(w http.ResponseWriter, r *http.Request) {
	const back = "/settings/backup"
	b := s.backupSettings(r.Context())
	b.Enabled = r.FormValue("enabled") == "1"
	b.Hour, _ = strconv.Atoi(r.FormValue("hour"))
	b.Keep, _ = strconv.Atoi(r.FormValue("keep"))
	if b.Hour < 0 || b.Hour > 23 || b.Keep < 1 || b.Keep > 90 {
		s.redirectErr(w, r, back, uiErr("Keep 1–90 backups."))
		return
	}
	switch p := r.FormValue("passphrase"); {
	case r.FormValue("passphrase_clear") == "1":
		b.Passphrase = ""
	case p != "":
		if len(p) < 12 {
			s.redirectErr(w, r, back, uiErr("The passphrase needs at least 12 characters."))
			return
		}
		if p != r.FormValue("passphrase2") {
			s.redirectErr(w, r, back, uiErr("The passphrases do not match."))
			return
		}
		b.Passphrase = s.store.SealSecret(sealBackupKey, p)
	}
	b.SFTP.Enabled = r.FormValue("sftp_enabled") == "1"
	host := strings.TrimSpace(r.FormValue("sftp_host"))
	if host != b.SFTP.Host {
		b.SFTP.HostKey = "" // another server: trust its key again
	}
	b.SFTP.Host = host
	b.SFTP.Port, _ = strconv.Atoi(r.FormValue("sftp_port"))
	b.SFTP.User = strings.TrimSpace(r.FormValue("sftp_user"))
	b.SFTP.Dir = strings.TrimSpace(r.FormValue("sftp_dir"))
	if pw := r.FormValue("sftp_password"); pw != "" {
		b.SFTP.Password = s.store.SealSecret(sealSFTPPass, pw)
	} else if r.FormValue("sftp_password_clear") == "1" {
		b.SFTP.Password = ""
	}
	if k := strings.TrimSpace(r.FormValue("sftp_key")); k != "" {
		b.SFTP.Key = s.store.SealSecret(sealSFTPKey, k+"\n")
	} else if r.FormValue("sftp_key_clear") == "1" {
		b.SFTP.Key = ""
	}
	if b.SFTP.Port == 0 {
		b.SFTP.Port = 22
	}
	if b.SFTP.Enabled && (b.SFTP.Host == "" || b.SFTP.User == "" || (b.SFTP.Password == "" && b.SFTP.Key == "") || b.SFTP.Port < 1 || b.SFTP.Port > 65535) {
		s.redirectErr(w, r, back, uiErr("The SFTP copy needs a server, a user and a password or key."))
		return
	}
	if strings.ContainsAny(b.SFTP.Host+b.SFTP.User+b.SFTP.Dir, "\r\n\x00") {
		s.redirectErr(w, r, back, uiErr("Unknown action."))
		return
	}
	if err := s.store.SetSetting(r.Context(), settingBackup, b); err != nil {
		s.serverError(w, r, err)
		return
	}
	_ = s.store.Audit(r.Context(), s.issuer(r), clientIP(r), "settings.backup", "settings",
		fmt.Sprintf("console backup: daily %v at %02d:00, keep %d, encrypted %v, SFTP %v %s", b.Enabled, b.Hour, b.Keep, b.Passphrase != "", b.SFTP.Enabled, b.SFTP.Host))
	if b.SFTP.Enabled && b.SFTP.HostKey == "" {
		s.redirect(w, r, back, "Saved. Test the SFTP connection to trust the server's key.")
		return
	}
	s.redirect(w, r, back, "Saved.")
}

func (s *Server) handleBackupRun(w http.ResponseWriter, r *http.Request) {
	if !s.startBackup(s.issuer(r)) {
		s.redirectErr(w, r, "/settings/backup", uiErr("A backup is running already."))
		return
	}
	s.redirect(w, r, "/settings/backup", "The backup runs; this page shows the result when it is done.")
}

// handleBackupTest connects to the SFTP folder; the first successful test
// trusts the server's host key (the administrator sees its fingerprint).
func (s *Server) handleBackupTest(w http.ResponseWriter, r *http.Request) {
	const back = "/settings/backup"
	b := s.backupSettings(r.Context())
	c, err := s.sftpOf(b)
	if err != nil {
		s.redirectErr(w, r, back, err)
		return
	}
	if c.Host == "" {
		s.redirectErr(w, r, back, uiErr("Save the SFTP server first."))
		return
	}
	trust := r.FormValue("trust") == "1"
	if trust {
		c.HostKey = r.FormValue("fingerprint")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	fp, err := backup.TestSFTP(ctx, c)
	var hk *backup.ErrHostKey
	switch {
	case errors.As(err, &hk) && b.SFTP.HostKey == "" && !trust:
		s.render(w, r, http.StatusOK, "backuptrust", &Page{Title: "Console backup", Nav: "settings", Data: map[string]string{"Host": c.Host, "Fingerprint": hk.Fingerprint}})
		return
	case err != nil:
		s.redirectErr(w, r, back, uiErrf("SFTP test failed: %v", err))
		return
	}
	if b.SFTP.HostKey != fp {
		b.SFTP.HostKey = fp
		if err := s.store.SetSetting(r.Context(), settingBackup, b); err != nil {
			s.serverError(w, r, err)
			return
		}
		_ = s.store.Audit(r.Context(), s.issuer(r), clientIP(r), "settings.backup", "settings", "trusted the SFTP host key "+fp+" of "+c.Host)
	}
	s.redirect(w, r, back, "The SFTP folder works.")
}

// backupByName finds a local backup by its name (only names from the list).
func (s *Server) backupByName(name string) *backupFile {
	for _, f := range s.localBackups() {
		if f.Name == name {
			return &f
		}
	}
	return nil
}

func (s *Server) handleBackupDownload(w http.ResponseWriter, r *http.Request) {
	f := s.backupByName(r.PathValue("name"))
	if f == nil {
		s.notFound(w, r)
		return
	}
	file, err := os.Open(filepath.Join(s.backupDir(), f.Name)) // #nosec G304 -- a name from our own list
	if err != nil {
		s.notFound(w, r)
		return
	}
	defer file.Close()
	_ = s.store.Audit(r.Context(), s.issuer(r), clientIP(r), "backup.download", "settings", "downloaded the console backup "+f.Name)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": f.Name}))
	w.Header().Set("Content-Length", strconv.FormatUint(f.Size, 10))
	_, _ = io.Copy(w, file)
}

func (s *Server) handleBackupDelete(w http.ResponseWriter, r *http.Request) {
	f := s.backupByName(r.FormValue("name"))
	if f == nil {
		s.redirectErr(w, r, "/settings/backup", uiErr("Unknown action."))
		return
	}
	if err := os.Remove(filepath.Join(s.backupDir(), f.Name)); err != nil {
		s.redirectErr(w, r, "/settings/backup", err)
		return
	}
	_ = s.store.Audit(r.Context(), s.issuer(r), clientIP(r), "backup.delete", "settings", "deleted the console backup "+f.Name)
	s.redirect(w, r, "/settings/backup", "Deleted.")
}

// LastBytes is the size of the last backup, for the page.
func (b BackupSettings) LastBytes() uint64 { return uint64(max(b.LastSize, 0)) } // #nosec G115 -- non-negative

// backupStamp is the time part (YYYYMMDD-HHMMSS) of a backup's file name,
// or "" when the name is not one of a backup.
func backupStamp(n string) string {
	for _, p := range []string{backupPrefix, legacyPrefix} {
		rest, ok := strings.CutPrefix(n, p)
		if !ok {
			continue
		}
		for _, ext := range []string{backup.Ext, backup.LegacyExt} {
			if stamp, ok := strings.CutSuffix(rest, ext); ok {
				return stamp
			}
		}
	}
	return ""
}
