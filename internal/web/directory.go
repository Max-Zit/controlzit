package web

import (
	"context"
	"strings"

	"github.com/max-zit/controlzit/internal/store"
)

// Groups of a directory (Active Directory / LDAP or single sign-on) decide
// the role and the customers of its users at every sign-in.

// GroupMapping maps directory groups to a role and to customers.
type GroupMapping struct {
	// Groups (names, DNs or IDs) per role; the highest role wins.
	AdminGroup      string `json:"admin_group,omitempty"`
	TechnicianGroup string `json:"technician_group,omitempty"`
	ReadOnlyGroup   string `json:"readonly_group,omitempty"`
	// DefaultRole for users in none of these groups ("" = they cannot
	// sign in).
	DefaultRole string `json:"default_role,omitempty"`
	// CustomerGroups: "group = customer" lines. Technicians and read-only
	// users in such groups see those customers; others see all customers
	// when AllByDefault, else none.
	CustomerGroups []string `json:"customer_groups,omitempty"`
	AllByDefault   bool     `json:"all_by_default"`
}

func (m *GroupMapping) validate() error {
	switch m.DefaultRole {
	case "", store.RoleAdmin, store.RoleTechnician, store.RoleReadOnly:
	default:
		return uiErr("Unknown default role.")
	}
	if m.AdminGroup == "" && m.TechnicianGroup == "" && m.ReadOnlyGroup == "" && m.DefaultRole == "" {
		return uiErr("Map at least one group to a role, or choose a role for every user of the directory.")
	}
	for _, l := range m.CustomerGroups {
		if g, c, ok := strings.Cut(l, "="); !ok || strings.TrimSpace(g) == "" || strings.TrimSpace(c) == "" {
			return uiErrf("Write customer groups as \"group = customer\", one per line (%s).", l)
		}
	}
	return nil
}

func inGroups(groups []string, g string) bool {
	g = strings.TrimSpace(g)
	if g == "" {
		return false
	}
	for _, x := range groups {
		x = strings.TrimSpace(x)
		// A full DN matches, and so does its first name (CN=Admins,… ↔ Admins).
		if strings.EqualFold(x, g) || strings.EqualFold(cnOf(x), g) {
			return true
		}
	}
	return false
}

// cnOf is the first RDN value of a DN ("Admins" of "CN=Admins,OU=…").
func cnOf(dn string) string {
	first, _, _ := strings.Cut(dn, ",")
	if _, v, ok := strings.Cut(first, "="); ok {
		return strings.TrimSpace(v)
	}
	return dn
}

// resolve decides the role and the customers of a user with these groups.
func (s *Server) resolve(ctx context.Context, m GroupMapping, groups []string) (role string, all bool, ids []int64, err error) {
	switch {
	case inGroups(groups, m.AdminGroup):
		role = store.RoleAdmin
	case inGroups(groups, m.TechnicianGroup):
		role = store.RoleTechnician
	case inGroups(groups, m.ReadOnlyGroup):
		role = store.RoleReadOnly
	case m.DefaultRole != "":
		role = m.DefaultRole
	default:
		return "", false, nil, uiErr("Your directory account is in no group that may use ControlZit.")
	}
	if role == store.RoleAdmin {
		return role, true, nil, nil
	}
	var names []string
	for _, l := range m.CustomerGroups {
		g, c, _ := strings.Cut(l, "=")
		if inGroups(groups, g) {
			names = append(names, strings.TrimSpace(c))
		}
	}
	if len(names) == 0 {
		if m.AllByDefault {
			return role, true, nil, nil
		}
		return "", false, nil, uiErr("Your directory account is in no group of a ControlZit customer.")
	}
	cs, err := s.store.AllCustomers(ctx)
	if err != nil {
		return "", false, nil, err
	}
	for _, n := range names {
		for _, c := range cs {
			if strings.EqualFold(c.Name, n) {
				ids = append(ids, c.ID)
			}
		}
	}
	if len(ids) == 0 {
		return "", false, nil, uiErr("The customers of your directory groups do not exist in ControlZit.")
	}
	return role, false, ids, nil
}

// splitLines turns a textarea into trimmed, non-empty lines.
func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// mappingFromForm reads the group fields shared by the LDAP and SSO pages.
func mappingFromForm(get func(string) string) GroupMapping {
	return GroupMapping{AdminGroup: strings.TrimSpace(get("admin_group")), TechnicianGroup: strings.TrimSpace(get("technician_group")),
		ReadOnlyGroup: strings.TrimSpace(get("readonly_group")), DefaultRole: get("default_role"),
		CustomerGroups: splitLines(get("customer_groups")), AllByDefault: get("all_by_default") == "1"}
}

// customerNames describes the customers a directory user would see.
func (s *Server) customerNames(ctx context.Context, all bool, ids []int64) string {
	if all {
		return "all"
	}
	var names []string
	for _, id := range ids {
		if c, err := s.store.Customer(ctx, id); err == nil {
			names = append(names, c.Name)
		}
	}
	return strings.Join(names, ", ")
}

// groupMappingData is the argument of the groupmapping template.
type groupMappingData struct {
	P     *Page
	G     GroupMapping
	Lines string
}
