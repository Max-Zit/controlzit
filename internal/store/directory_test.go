package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/max-zit/controlzit/internal/store"
)

func TestDirectoryUsers(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	c1, _ := s.CreateCustomer(ctx, "Acme", "")
	u, err := s.UpsertDirectoryUser(ctx, store.DirectoryUser{Source: "ldap", Username: "pera", DisplayName: "Pera Perić", Role: store.RoleTechnician, CustomerIDs: []int64{c1}})
	if err != nil || u.Source != "ldap" || u.Role != store.RoleTechnician || len(u.CustomerIDs) != 1 || u.TOTPEnabled {
		t.Fatalf("first sign-in: %+v %v", u, err)
	}
	// The directory decides the role and the customers at every sign-in.
	u2, err := s.UpsertDirectoryUser(ctx, store.DirectoryUser{Source: "ldap", Username: "PERA", Role: store.RoleReadOnly, AllCustomers: true})
	if err != nil || u2.ID != u.ID || u2.Role != store.RoleReadOnly || !u2.AllCustomers || len(u2.CustomerIDs) != 0 {
		t.Fatalf("second sign-in: %+v %v", u2, err)
	}
	// No local password for a directory account.
	if _, err := s.CheckPassword(ctx, "pera", ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("password sign-in of a directory account: %v", err)
	}
	// A local account cannot be taken over, nor an LDAP one by SSO.
	if _, err := s.CreateUser(ctx, store.NewUser{Username: "admin", Password: "long enough password", Role: store.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertDirectoryUser(ctx, store.DirectoryUser{Source: "sso", Username: "admin", Role: store.RoleAdmin}); !errors.Is(err, store.ErrOtherSource) {
		t.Fatalf("local account taken over: %v", err)
	}
	if _, err := s.UpsertDirectoryUser(ctx, store.DirectoryUser{Source: "sso", Username: "pera", Role: store.RoleAdmin}); !errors.Is(err, store.ErrOtherSource) {
		t.Fatalf("LDAP account taken over by SSO: %v", err)
	}
	if s.UserSource(ctx, "Pera") != "ldap" || s.UserSource(ctx, "nobody") != "" {
		t.Fatal("UserSource")
	}
}
