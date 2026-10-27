package web

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/max-zit/controlzit/internal/store"
)

// Every customer gets its own policy "Default" when it is created, with the
// built-in Windows Update and alert settings, assigned to the customer. It
// is changed like any other policy; sites and devices can get their own.
// Devices without any policy for a part use the built-in values.

const (
	defaultPolicyName = "Default"
	defaultPolicyNote = "Created with the customer. Change it, or assign other policies to its sites and devices."
	movedPolicyNote   = "Made from the server's former settings for Windows Update and alerts. Change it, or assign other policies to its sites and devices."
	// settingCustomerPolicies marks the one-time move of the former server
	// settings into a Default policy for each existing customer.
	settingCustomerPolicies = "policies.customer_defaults"
)

// builtinAlerts are the alert thresholds of devices without a policy for
// them; the alert emails stay those of the server.
func builtinAlerts(m MonitoringSettings) MonitoringSettings {
	return alertRulesOf(defaultMonitoring()).apply(m)
}

// createDefaultPolicy adds a customer's Default policy and assigns it.
func (s *Server) createDefaultPolicy(ctx context.Context, customerID int64, set PolicySettings, note, by string) error {
	raw, err := json.Marshal(set)
	if err != nil {
		return err
	}
	p := &store.Policy{Name: defaultPolicyName, Description: note, Settings: raw, UpdatedBy: by, CustomerID: &customerID}
	if err := s.store.SavePolicy(ctx, p); err != nil {
		return err
	}
	return s.store.Assign(ctx, "customer", customerID, p.ID, by)
}

// newCustomerPolicy is the Default policy of a new customer.
func newCustomerPolicy() PolicySettings {
	u, a := defaultPatchPolicy(), alertRulesOf(defaultMonitoring())
	return PolicySettings{Updates: &u, Alerts: &a}
}

// MigrateCustomerPolicies runs once: each customer without a policy of its
// own gets a Default policy with the server's former Windows Update and
// alert settings, so nothing changes for its devices.
func (s *Server) MigrateCustomerPolicies(ctx context.Context) error {
	var done bool
	if err := s.store.GetSetting(ctx, settingCustomerPolicies, &done); err != nil || done {
		return err
	}
	customers, err := s.store.AllCustomers(ctx)
	if err != nil {
		return err
	}
	as, err := s.store.Assignments(ctx)
	if err != nil {
		return err
	}
	has := map[int64]bool{}
	for _, a := range as {
		if a.TargetType == "customer" {
			has[a.TargetID] = true
		}
	}
	u, a := s.Patches(ctx), alertRulesOf(s.Monitoring(ctx))
	set := PolicySettings{Updates: &u, Alerts: &a}
	for _, c := range customers {
		if has[c.ID] {
			continue
		}
		if err := s.createDefaultPolicy(ctx, c.ID, set, movedPolicyNote, "system"); errors.Is(err, store.ErrConflict) {
			s.log.Warn("customer already has a policy named Default; none added", "customer", c.Name)
		} else if err != nil {
			return err
		}
	}
	return s.store.SetSetting(ctx, settingCustomerPolicies, true)
}
