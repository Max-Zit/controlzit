package web_test

import (
	"net/http"
	"strings"
	"testing"
)

// Administrators define custom fields; technicians fill them in on the
// device and customer pages (checked by type); the API reads and sets
// device fields by name.
func TestCustomFields(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupAdmin("192.168.1.10")
	d := e.device(t, "PC-7", "Microsoft Windows 11 Pro")

	for _, f := range [][]string{{"device", "Asset number", "text"}, {"device", "Warranty end", "date"}, {"customer", "Contract", "text"}} {
		if r := admin.post("/settings/fields", "action", "add", "scope", f[0], "name", f[1], "kind", f[2]); r.code != http.StatusSeeOther {
			t.Fatalf("add %s: %d", f[1], r.code)
		}
	}
	if r := admin.post("/settings/fields", "action", "add", "scope", "device", "name", "asset NUMBER", "kind", "text"); !strings.Contains(admin.get(r.loc).body, "A field with this name exists.") {
		t.Fatal("duplicate field name accepted")
	}
	b := admin.get("/devices/" + itoa(d.ID)).body
	if !strings.Contains(b, "Asset number") || !strings.Contains(b, `type="date"`) {
		t.Fatal("fields on the device page")
	}
	page := admin.get("/settings/fields").body
	ids := fieldIDs(page)
	if len(ids) != 3 {
		t.Fatalf("field ids %v", ids)
	}
	// Fields are sorted by name: Asset number, Warranty end (device), Contract.
	asset, warranty, contract := ids[0], ids[1], ids[2]
	r := admin.post("/devices/"+itoa(d.ID)+"/fields", "f"+warranty, "31.12.2027")
	if !strings.Contains(admin.get(r.loc).body, "Warranty end: enter a date as YYYY-MM-DD") {
		t.Fatal("a bad date was accepted")
	}
	admin.post("/devices/"+itoa(d.ID)+"/fields", "f"+asset, "INV-0042", "f"+warranty, "2027-12-31")
	if b := admin.get("/devices/" + itoa(d.ID)).body; !strings.Contains(b, `value="INV-0042"`) || !strings.Contains(b, `value="2027-12-31"`) {
		t.Fatal("values not saved")
	}
	admin.post("/customers/"+itoa(d.CustomerID)+"/fields", "f"+contract, "Gold 2026")
	if !strings.Contains(admin.get("/customers/"+itoa(d.CustomerID)).body, `value="Gold 2026"`) {
		t.Fatal("customer field not saved")
	}

	r = admin.post("/account/tokens", "name", "fields", "role", "technician", "days", "1")
	tok := tokenRE.FindString(r.body)
	if c, body := apiCall(e, tok, "GET", "/api/v1/devices", ""); c != http.StatusOK || !strings.Contains(body, `"Asset number": "INV-0042"`) {
		t.Fatalf("API list: %d %s", c, body)
	}
	if c, body := apiCall(e, tok, "PUT", "/api/v1/devices/"+itoa(d.ID)+"/fields", `{"asset number":"INV-0043","Warranty end":""}`); c != http.StatusOK ||
		!strings.Contains(body, `"Asset number": "INV-0043"`) || strings.Contains(body, "Warranty") {
		t.Fatalf("API set: %d %s", c, body)
	}
	if c, _ := apiCall(e, tok, "PUT", "/api/v1/devices/"+itoa(d.ID)+"/fields", `{"Nope":"x"}`); c != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", c)
	}
	admin.post("/settings/fields", "action", "delete", "id", asset)
	if strings.Contains(admin.get("/devices/"+itoa(d.ID)).body, "INV-0043") {
		t.Fatal("values of a removed field stay")
	}
}

// fieldIDs returns the field IDs of the settings page in order.
func fieldIDs(page string) []string {
	var ids []string
	for _, part := range strings.Split(page, `name="id" value="`)[1:] {
		ids = append(ids, part[:strings.IndexByte(part, '"')])
	}
	return ids
}
