package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
	"github.com/max-zit/controlzit/internal/store"
)

// BitLocker: the server keeps the recovery keys of its Windows devices
// (sealed, collected once a day from devices with BitLocker on, shown only to
// administrators who confirm their password, each time audited), and a
// policy can require BitLocker on the system drive: the agent first adds a
// recovery key, the server stores it, and only then does the encryption
// start.

const (
	sealBitLocker = "bitlocker"
	keysEvery     = 24 * time.Hour
	enableRetry   = 6 * time.Hour
)

// BitLockerPolicy is the BitLocker part of a policy.
type BitLockerPolicy struct {
	Require bool `json:"require"` // encrypt the system drive (TPM), keep the recovery key
}

func (pr *policyResolver) bitlocker(deviceID int64) (*BitLockerPolicy, *policyLevel) {
	if l := pr.part(deviceID, func(p *PolicySettings) bool { return p.BitLocker != nil }); l != nil {
		return l.Settings.BitLocker, l
	}
	return nil, nil
}

// collectKeys asks a device for its BitLocker volumes and stores their
// recovery keys; it returns the report and how many keys were new.
func (s *Server) collectKeys(ctx context.Context, d *store.Device, by string, action string) (*proto.BitLockerReport, int, error) {
	var rep proto.BitLockerReport
	if err := s.call(ctx, d.ID, by, proto.KindBitLocker, proto.BitLockerArgs{Action: action}, &rep, 4*time.Minute); err != nil {
		return nil, 0, err
	}
	added := 0
	for _, v := range rep.Volumes {
		for _, k := range v.Keys {
			if k.ID == "" || k.Password == "" {
				continue
			}
			isNew, err := s.store.SaveRecoveryKey(ctx, d.ID, k.ID, v.Mount, s.store.SealSecret(sealBitLocker, k.Password))
			if err != nil {
				return nil, added, err
			}
			if isNew {
				added++
			}
		}
	}
	if added > 0 {
		_ = s.store.Audit(context.WithoutCancel(ctx), by, "", "bitlocker.keys", deviceTarget(d), fmt.Sprintf("stored %d new BitLocker recovery keys of %q", added, d.Hostname))
	}
	_ = s.store.Mark(ctx, "bitlocker-keys:"+strconv.FormatInt(d.ID, 10))
	return &rep, added, nil
}

func init() {
	taskKinds["bitlocker.keys"] = taskBitLockerKeys
	taskKinds["bitlocker.enable"] = taskBitLockerEnable
}

func taskBitLockerKeys(s *Server, ctx context.Context, d *store.Device, t *store.DeviceTask) (taskOutcome, error) {
	rep, added, err := s.collectKeys(ctx, d, t.CreatedBy, proto.BitLockerKeys)
	if err != nil {
		return taskOutcome{}, err
	}
	n := 0
	for _, v := range rep.Volumes {
		n += len(v.Keys)
	}
	return outcome(true, s.deviceURL(d, "/bitlocker"), "%s recovery keys, %s new", n, added), nil
}

func taskBitLockerEnable(s *Server, ctx context.Context, d *store.Device, t *store.DeviceTask) (taskOutcome, error) {
	link := s.deviceURL(d, "/bitlocker")
	// Step 1: the agent checks the TPM and adds a recovery key; the server
	// stores it before anything is encrypted.
	rep, _, err := s.collectKeys(ctx, d, t.CreatedBy, proto.BitLockerPrepare)
	if err != nil {
		return taskOutcome{Link: link}, err
	}
	sys := systemVolume(rep)
	if sys == nil || len(sys.Keys) == 0 {
		return outcome(false, link, "the system drive has no recovery key; the encryption was not started"), nil
	}
	if _, err := s.store.RecoveryKey(ctx, d.ID, sys.Keys[0].ID); err != nil {
		return outcome(false, link, "the recovery key could not be stored; the encryption was not started"), nil
	}
	// Step 2: start the encryption.
	var after proto.BitLockerReport
	if err := s.call(ctx, d.ID, t.CreatedBy, proto.KindBitLocker, proto.BitLockerArgs{Action: proto.BitLockerEnable}, &after, 4*time.Minute); err != nil {
		return taskOutcome{Link: link}, err
	}
	s.taskAudit(ctx, t, d, "bitlocker.enable", "BitLocker on %q: encryption of %s started (TPM, XTS-AES 256); recovery key stored", d.Hostname, sys.Mount)
	s.requestInventory(ctx, d.ID)
	if after.Started {
		return outcome(true, link, "encryption of %s started; the recovery key is stored", sys.Mount), nil
	}
	return outcome(true, link, "%s is already encrypted; the recovery key is stored", sys.Mount), nil
}

func systemVolume(rep *proto.BitLockerReport) *proto.BitLockerVolume {
	for i := range rep.Volumes {
		if rep.Volumes[i].Type == "OperatingSystem" {
			return &rep.Volumes[i]
		}
	}
	return nil
}

// bitlockerOn reports whether the inventory shows BitLocker on any volume.
func bitlockerOn(inv *proto.Inventory) bool {
	if inv == nil {
		return false
	}
	for _, b := range inv.BitLocker {
		if b.Protection == "on" || strings.Contains(b.Status, "encrypt") {
			return true
		}
	}
	return false
}

// systemUnprotected reports whether the inventory shows the system drive (C:)
// without BitLocker protection (decrypted, or encrypted but waiting for
// activation or suspended).
func systemUnprotected(inv *proto.Inventory) bool {
	if inv == nil {
		return false
	}
	for _, b := range inv.BitLocker {
		if strings.EqualFold(strings.TrimSuffix(b.Drive, ":"), "C") {
			return b.Protection == "off" && !strings.Contains(b.Status, "decrypting")
		}
	}
	return false
}

// RunBitLocker collects the recovery keys of devices with BitLocker once a
// day and starts the encryption where a policy requires it (monitor loop,
// every few minutes).
func (s *Server) RunBitLocker(ctx context.Context) {
	pr, err := s.cachedPolicies(ctx)
	if err != nil {
		return
	}
	for id, sc := range pr.scopes {
		if !s.Connected(id) || (sc.OS != "" && !strings.Contains(sc.OS, "Windows")) {
			continue
		}
		d, err := s.store.Device(ctx, id)
		if err != nil || d.Inventory == nil {
			continue
		}
		if bitlockerOn(d.Inventory) {
			if t, err := s.store.Marked(ctx, "bitlocker-keys:"+strconv.FormatInt(id, 10)); err == nil && s.now().Sub(t) >= keysEvery {
				cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
				if _, _, err := s.collectKeys(cctx, d, "system", proto.BitLockerKeys); err != nil {
					s.log.Warn("bitlocker: cannot collect the recovery keys", "device", id, "err", err)
					_ = s.store.Mark(ctx, "bitlocker-keys:"+strconv.FormatInt(id, 10)) // try again tomorrow
				}
				cancel()
			}
		}
		bp, l := pr.bitlocker(id)
		if bp == nil || !bp.Require || !systemUnprotected(d.Inventory) {
			continue
		}
		key := "bitlocker-enable:" + strconv.FormatInt(id, 10)
		if t, err := s.store.Marked(ctx, key); err != nil || s.now().Sub(t) < enableRetry {
			continue
		}
		if _, err := s.queueTask(ctx, d, "policy "+l.Policy.Name, "bitlocker.enable", "Switch on BitLocker", nil, struct{}{}); err != nil {
			continue
		}
		_ = s.store.Mark(ctx, key)
	}
}

// ---- the page

type bitlockerData struct {
	D        *store.Device
	Keys     []store.RecoveryKey
	Revealed map[string]string // protector ID → key, after a confirmed reveal
	Policy   *policyLevel
	Require  bool
}

func (s *Server) handleBitLocker(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	s.showBitLocker(w, r, d, nil)
}

func (s *Server) showBitLocker(w http.ResponseWriter, r *http.Request, d *store.Device, revealed map[string]string) {
	keys, err := s.store.RecoveryKeys(r.Context(), d.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	bd := &bitlockerData{D: d, Keys: keys, Revealed: revealed}
	if pr, err := s.loadPolicies(r.Context()); err == nil {
		if bp, l := pr.bitlocker(d.ID); bp != nil {
			bd.Policy, bd.Require = l, bp.Require
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, r, http.StatusOK, "bitlocker", &Page{Title: d.Hostname, Nav: "devices", Data: bd})
}

func (s *Server) handleBitLockerCollect(w http.ResponseWriter, r *http.Request) {
	d := s.deviceForFiles(w, r)
	if d == nil {
		return
	}
	s.startTask(w, r, d, "bitlocker.keys", "Read the BitLocker recovery keys", nil, struct{}{})
}

func (s *Server) handleBitLockerEnable(w http.ResponseWriter, r *http.Request) {
	d := s.deviceFor(w, r)
	if d == nil {
		return
	}
	s.startTask(w, r, d, "bitlocker.enable", "Switch on BitLocker", nil, struct{}{})
}

// handleBitLockerReveal shows one recovery key to an administrator who
// confirms the password.
func (s *Server) handleBitLockerReveal(w http.ResponseWriter, r *http.Request) {
	d := s.deviceFor(w, r)
	if d == nil {
		return
	}
	u := userFrom(r)
	back := s.deviceURL(d, "/bitlocker")
	k, err := s.store.RecoveryKey(r.Context(), d.ID, r.FormValue("protector"))
	if errors.Is(err, store.ErrNotFound) {
		s.redirect(w, r, back, "Unknown action.")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if _, err := s.store.CheckPassword(r.Context(), u.Username, r.FormValue("password")); err != nil {
		s.guard.fail(r.Context(), clientIP(r), u.Username, "password for a BitLocker recovery key")
		s.auditAs(r, u.Username, "bitlocker.reveal", deviceTarget(d), "refused: wrong password for the recovery key of %s on %s", k.Volume, d.Hostname)
		s.redirect(w, r, back, "The password is wrong.")
		return
	}
	key, err := s.store.OpenSecret(sealBitLocker, k.Sealed)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "bitlocker.reveal", deviceTarget(d), "showed the BitLocker recovery key of %s on %q (protector %s)", k.Volume, d.Hostname, k.ProtectorID)
	s.showBitLocker(w, r, d, map[string]string{k.ProtectorID: key})
}
