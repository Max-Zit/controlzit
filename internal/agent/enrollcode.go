package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/max-zit/rmmzit/internal/proto"
)

// EnrollCodePrefix and EnrollData are defined in proto (the console makes codes).
const EnrollCodePrefix = proto.EnrollCodePrefix

// EnrollData is what an enrollment code carries.
type EnrollData = proto.EnrollData

// MakeEnrollCode encodes an enrollment code.
func MakeEnrollCode(d EnrollData) string { return proto.MakeEnrollCode(d) }

// ParseEnrollCode decodes and validates a code.
func ParseEnrollCode(code string) (EnrollData, error) {
	var d EnrollData
	code = strings.TrimSpace(code)
	body, ok := strings.CutPrefix(code, EnrollCodePrefix)
	if !ok {
		body, ok = strings.CutPrefix(code, proto.LegacyEnrollCodePrefix)
	}
	if !ok {
		return d, errors.New("an enrollment code starts with " + EnrollCodePrefix)
	}
	b, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil || json.Unmarshal(b, &d) != nil {
		return d, errors.New("the enrollment code is damaged; copy it again from the console")
	}
	return checkEnroll(d)
}

func checkEnroll(d EnrollData) (EnrollData, error) {
	var err error
	if d.Server, err = CheckServerURL(d.Server); err != nil {
		return d, err
	}
	if d.Fingerprint, err = CheckFingerprint(d.Fingerprint); err != nil {
		return d, err
	}
	if d.Token = strings.TrimSpace(d.Token); d.Token == "" {
		return d, errors.New("an enrollment token is required")
	}
	return d, nil
}

// pendingFile holds an enrollment that could not reach the server yet
// (for example an MSI installed at boot before the network was up).
const pendingFile = "pending-enrollment.json"

// SavePending stores an enrollment for the service to finish later.
func SavePending(dir string, d EnrollData) error {
	d, err := checkEnroll(d)
	if err != nil {
		return err
	}
	if err := EnsureDir(dir); err != nil {
		return err
	}
	b, _ := json.Marshal(d)
	return os.WriteFile(filepath.Join(dir, pendingFile), b, 0o600)
}

// LoadPending returns a stored enrollment, or ok=false.
func LoadPending(dir string) (EnrollData, bool) {
	var d EnrollData
	b, err := os.ReadFile(filepath.Join(dir, pendingFile)) // #nosec G304 -- fixed name in the data directory
	if err != nil || json.Unmarshal(b, &d) != nil {
		return d, false
	}
	d, err = checkEnroll(d)
	return d, err == nil
}

// EnrollWith enrolls with the data of a code or of the pending file.
func EnrollWith(ctx context.Context, dir string, d EnrollData) (*Config, error) {
	return Enroll(ctx, dir, d.Server, d.Fingerprint, d.Token)
}

// Forget removes the enrollment (uninstall): the configuration, the key and
// a pending enrollment. The log stays.
func Forget(dir string) error {
	var errs []error
	// Windows Update gets its own settings back.
	if err := RestoreWUPolicy(dir); err != nil {
		errs = append(errs, err)
	}
	for _, f := range []string{configFile, keyFile, pendingFile} {
		if err := os.Remove(filepath.Join(dir, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	markEnrolled(false)
	return errors.Join(errs...)
}

// SetAside moves the current enrollment (configuration and key) out of the
// way for a new enrollment and returns a function that puts it back.
func SetAside(dir string) (restore func(), err error) {
	var moved []string
	for _, f := range []string{configFile, keyFile} {
		p := filepath.Join(dir, f)
		if err := os.Rename(p, p+".old"); err == nil {
			moved = append(moved, p)
		} else if !errors.Is(err, os.ErrNotExist) {
			for _, m := range moved {
				_ = os.Rename(m+".old", m)
			}
			return nil, err
		}
	}
	return func() {
		for _, f := range []string{configFile, keyFile, pendingFile} {
			_ = os.Remove(filepath.Join(dir, f))
		}
		for _, m := range moved {
			_ = os.Rename(m+".old", m)
		}
		if len(moved) > 0 {
			markEnrolled(true)
		}
	}, nil
}

// DropSetAside deletes the enrollment kept by SetAside.
func DropSetAside(dir string) {
	for _, f := range []string{configFile, keyFile} {
		_ = os.Remove(filepath.Join(dir, f+".old"))
	}
}
