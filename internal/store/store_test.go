package store_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/max-zit/rmmzit/internal/auth"
	"github.com/max-zit/rmmzit/internal/store"
	"github.com/max-zit/rmmzit/internal/testdb"
)

func TestMain(m *testing.M) { os.Exit(testdb.Main(m)) }

func open(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if err := s.UseSecretKey(bytes.Repeat([]byte{9}, 32)); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestUsersAndTwoFactor(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, store.NewUser{Username: "x", Password: "long enough password", Role: store.RoleAdmin}); err == nil {
		t.Fatal("1-character username accepted")
	}
	if _, err := s.CreateUser(ctx, store.NewUser{Username: "admin", Password: "short", Role: store.RoleAdmin}); err == nil {
		t.Fatal("short password accepted")
	}
	u, err := s.CreateUser(ctx, store.NewUser{Username: "Admin", Password: "long enough password", Role: store.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, store.NewUser{Username: "admin", Password: "long enough password", Role: store.RoleAdmin}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate username (case-insensitive): %v", err)
	}
	if _, err := s.CheckPassword(ctx, "ADMIN", "long enough password"); err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	if _, err := s.CheckPassword(ctx, "admin", "wrong password!!"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := s.CheckPassword(ctx, "nobody", "long enough password"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}

	secret := auth.NewTOTPSecret()
	if err := s.SetPendingTOTP(ctx, u.ID, secret); err != nil {
		t.Fatal(err)
	}
	_, hashes := auth.NewRecoveryCodes()
	if err := s.EnableTOTP(ctx, u.ID, 100, hashes); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPendingTOTP(ctx, u.ID, auth.NewTOTPSecret()); err == nil {
		t.Fatal("an enabled factor was replaced")
	}
	tf, err := s.GetTwoFactor(ctx, u.ID)
	if err != nil || !tf.Enabled || tf.Secret != secret || tf.LastStep != 100 {
		t.Fatalf("two factor: %+v %v", tf, err)
	}
	var raw string
	s.Pool().QueryRow(ctx, `SELECT totp_secret FROM users WHERE id=$1`, u.ID).Scan(&raw)
	if raw == secret || raw == "" {
		t.Fatal("TOTP secret not encrypted at rest")
	}
	if ok, _ := s.UseTOTPStep(ctx, u.ID, 100); ok {
		t.Fatal("step replay accepted")
	}
	if ok, _ := s.UseTOTPStep(ctx, u.ID, 101); !ok {
		t.Fatal("next step rejected")
	}
	plain, hashes := auth.NewRecoveryCodes()
	s.SetRecoveryCodes(ctx, u.ID, hashes)
	if ok, _ := s.UseRecoveryCode(ctx, u.ID, plain[3]); !ok {
		t.Fatal("recovery code rejected")
	}
	if ok, _ := s.UseRecoveryCode(ctx, u.ID, plain[3]); ok {
		t.Fatal("recovery code used twice")
	}

	// The last administrator cannot be demoted or disabled.
	if err := s.UpdateUser(ctx, u.ID, "", store.RoleTechnician, false, false, nil); err == nil {
		t.Fatal("last admin demoted")
	}
	if err := s.UpdateUser(ctx, u.ID, "", store.RoleAdmin, false, true, nil); err == nil {
		t.Fatal("last admin disabled")
	}
}

func TestSessions(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return now })
	u, _ := s.CreateUser(ctx, store.NewUser{Username: "tech", Password: "long enough password", Role: store.RoleTechnician})
	tok, x, err := s.CreateSession(ctx, u.ID, store.StageMFA, store.MFATimeout, "10.0.0.5", "test")
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	s.Pool().QueryRow(ctx, `SELECT token_hash FROM sessions`).Scan(&stored)
	if stored == tok || stored != x.Hash {
		t.Fatal("session token stored in plain")
	}
	full, err := s.PromoteSession(ctx, x, 8*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionByToken(ctx, tok, 0); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("pre-auth token still valid after promotion")
	}
	got, err := s.SessionByToken(ctx, full, time.Hour)
	if err != nil || got.Stage != store.StageFull {
		t.Fatalf("full session: %v", err)
	}
	now = now.Add(61 * time.Minute)
	if _, err := s.SessionByToken(ctx, full, time.Hour); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("idle session still valid")
	}
}

func TestCustomersSitesTokens(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return now })
	c1, err := s.CreateCustomer(ctx, "Acme d.o.o.", "")
	if err != nil {
		t.Fatal(err)
	}
	c2, _ := s.CreateCustomer(ctx, "Beta", "")
	if _, err := s.CreateCustomer(ctx, "acme D.O.O.", ""); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate customer: %v", err)
	}
	site, err := s.CreateSite(ctx, c1, "Beograd", "Knez Mihailova 1", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateSite(ctx, 9999, "X", "", ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("site for missing customer: %v", err)
	}
	if err := s.DeleteCustomer(ctx, c1); !errors.Is(err, store.ErrInUse) {
		t.Fatalf("customer with sites deleted: %v", err)
	}

	// Per-customer visibility.
	tech, _ := s.CreateUser(ctx, store.NewUser{Username: "tech", Password: "long enough password", Role: store.RoleTechnician, CustomerIDs: []int64{c2}})
	list, _ := s.Customers(ctx, tech)
	if len(list) != 1 || list[0].ID != c2 || !tech.SeesCustomer(c2) || tech.SeesCustomer(c1) {
		t.Fatalf("technician sees %v", list)
	}

	tok, err := s.CreateEnrollToken(ctx, site, "office PCs", "admin", 24*time.Hour, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if id, err := s.UseEnrollToken(ctx, tok); err != nil || id != site {
			t.Fatalf("use %d: %v", i, err)
		}
	}
	if _, err := s.UseEnrollToken(ctx, tok); !errors.Is(err, store.ErrTokenInvalid) {
		t.Fatal("token used more than max uses")
	}
	tok2, _ := s.CreateEnrollToken(ctx, site, "", "admin", time.Hour, 10)
	now = now.Add(2 * time.Hour)
	if _, err := s.UseEnrollToken(ctx, tok2); !errors.Is(err, store.ErrTokenInvalid) {
		t.Fatal("expired token accepted")
	}
	tok3, _ := s.CreateEnrollToken(ctx, site, "", "admin", time.Hour*48, 10)
	toks, _ := s.EnrollTokens(ctx, site)
	if err := s.RevokeEnrollToken(ctx, site, toks[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UseEnrollToken(ctx, tok3); !errors.Is(err, store.ErrTokenInvalid) {
		t.Fatal("revoked token accepted")
	}
	if err := s.DeleteSite(ctx, site); err != nil {
		t.Fatalf("delete site with tokens: %v", err)
	}
}

func TestAuditChain(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	for i, a := range []string{"login", "customer.create", "site.create"} {
		if err := s.Audit(ctx, "admin", "10.0.0.1", a, "x", string(rune('a'+i))); err != nil {
			t.Fatal(err)
		}
	}
	c, err := s.VerifyAudit(ctx)
	if err != nil || !c.OK || c.Entries != 3 {
		t.Fatalf("verify: %+v %v", c, err)
	}
	// Tampering with an entry breaks the chain there.
	var second int64
	s.Pool().QueryRow(ctx, `SELECT id FROM audit_log ORDER BY id OFFSET 1 LIMIT 1`).Scan(&second)
	s.Pool().Exec(ctx, `UPDATE audit_log SET detail='edited' WHERE id=$1`, second)
	c, _ = s.VerifyAudit(ctx)
	if c.OK || c.BrokenAt != second {
		t.Fatalf("tampering not detected: %+v", c)
	}
	s.Pool().Exec(ctx, `UPDATE audit_log SET detail='b' WHERE id=$1`, second)
	// Deleting an entry breaks the link of the next one.
	s.Pool().Exec(ctx, `DELETE FROM audit_log WHERE id=$1`, second)
	c, _ = s.VerifyAudit(ctx)
	if c.OK || c.BrokenAt != second+1 {
		t.Fatalf("deletion not detected: %+v", c)
	}
	list, _ := s.AuditEntries(ctx, store.AuditFilter{Query: "site"})
	if len(list) != 1 || list[0].Action != "site.create" {
		t.Fatalf("filter: %+v", list)
	}
}

func TestBlocks(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return now })
	d := func(n int) time.Duration { return time.Duration(n) * 30 * time.Minute }
	b, _ := s.BlockIP(ctx, "10.0.0.9", d, "test")
	b2, _ := s.BlockIP(ctx, "10.0.0.9", d, "test")
	if b.Strikes != 1 || b2.Strikes != 2 || !b2.Until.Equal(now.Add(time.Hour)) {
		t.Fatalf("strikes %d %d until %v", b.Strikes, b2.Strikes, b2.Until)
	}
	if u, _ := s.BlockedUntil(ctx, "10.0.0.9"); u.IsZero() {
		t.Fatal("not blocked")
	}
	if n, _ := s.Unblock(ctx, "all"); n != 1 {
		t.Fatal("unblock all")
	}
}

func TestSettingsAndSecretKey(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	type X struct{ A int }
	x := X{A: 1}
	s.GetSetting(ctx, "missing", &x)
	if x.A != 1 {
		t.Fatal("missing setting changed the value")
	}
	s.SetSetting(ctx, "k", X{A: 5})
	s.GetSetting(ctx, "k", &x)
	if x.A != 5 {
		t.Fatal("setting not stored")
	}
	dir := t.TempDir()
	k1, created, err := store.LoadOrCreateSecretKey(dir)
	if err != nil || !created {
		t.Fatal(err)
	}
	k2, created, _ := store.LoadOrCreateSecretKey(dir)
	if created || !bytes.Equal(k1, k2) {
		t.Fatal("secret key not reloaded")
	}
}
