package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/controlzit/internal/store"
)

// Custom fields of devices and customers: defined by administrators under
// Settings, filled in on the device and customer pages and through the API.

// fieldValue checks and normalizes a value of a field.
func fieldValue(f store.CustomField, v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil
	}
	if len(v) > 500 || strings.ContainsAny(v, "\x00\r\n") {
		return "", fmt.Errorf("%s: at most 500 characters on one line", f.Name)
	}
	switch f.Kind {
	case "number":
		if _, err := strconv.ParseFloat(strings.ReplaceAll(v, ",", "."), 64); err != nil {
			return "", fmt.Errorf("%s: enter a number", f.Name)
		}
		v = strings.ReplaceAll(v, ",", ".")
	case "date":
		if _, err := time.Parse("2006-01-02", v); err != nil {
			return "", fmt.Errorf("%s: enter a date as YYYY-MM-DD", f.Name)
		}
	}
	return v, nil
}

type fieldsData struct {
	Scopes []fieldScope
}

type fieldScope struct {
	Name   string
	Fields []store.CustomField
}

func (s *Server) handleCustomFields(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d := &fieldsData{}
	for _, scope := range []string{"device", "customer"} {
		list, err := s.store.CustomFields(ctx, scope)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		d.Scopes = append(d.Scopes, fieldScope{Name: scope, Fields: list})
	}
	s.render(w, r, http.StatusOK, "customfields", &Page{Title: "Custom fields", Nav: "settings", Data: d})
}

func (s *Server) handleCustomFieldsSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	back := "/settings/fields"
	switch r.FormValue("action") {
	case "add":
		scope, kind := r.FormValue("scope"), r.FormValue("kind")
		if (scope != "device" && scope != "customer") || (kind != "text" && kind != "number" && kind != "date") {
			s.redirect(w, r, back, "Unknown action.")
			return
		}
		name := strings.TrimSpace(r.FormValue("name"))
		if _, err := s.store.AddCustomField(ctx, scope, name, kind); errors.Is(err, store.ErrConflict) {
			s.redirect(w, r, back, "A field with this name exists.")
			return
		} else if err != nil {
			s.redirect(w, r, back, err.Error())
			return
		}
		s.audit(r, "fields.add", "settings", "custom %s field %q (%s) added", scope, name, kind)
		s.redirect(w, r, back, "Saved.")
	case "delete":
		id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
		if err := s.store.DeleteCustomField(ctx, id); err != nil {
			s.serverError(w, r, err)
			return
		}
		s.audit(r, "fields.delete", "settings", "custom field #%d and its values removed", id)
		s.redirect(w, r, back, "Removed.")
	default:
		s.redirect(w, r, back, "Unknown action.")
	}
}

// saveFields stores the values of a form ("f<ID>") for a device or customer.
func (s *Server) saveFields(r *http.Request, scope string, id int64) error {
	fields, err := s.store.CustomFields(r.Context(), scope)
	if err != nil {
		return err
	}
	vals := map[int64]string{}
	for _, f := range fields {
		raw, ok := r.Form["f"+strconv.FormatInt(f.ID, 10)]
		if !ok || len(raw) == 0 {
			continue
		}
		v, err := fieldValue(f, raw[0])
		if err != nil {
			return err
		}
		vals[f.ID] = v
	}
	return s.store.SetFieldValues(r.Context(), scope, id, vals)
}

func (s *Server) handleDeviceFields(w http.ResponseWriter, r *http.Request) {
	d := s.deviceFor(w, r)
	if d == nil {
		return
	}
	if !userFrom(r).CanWrite() {
		s.forbidden(w, r)
		return
	}
	_ = r.ParseForm()
	to := "/devices/" + strconv.FormatInt(d.ID, 10)
	if err := s.saveFields(r, "device", d.ID); err != nil {
		s.redirect(w, r, to, err.Error())
		return
	}
	s.audit(r, "device.fields", deviceTarget(d), "custom fields of %q changed", d.Hostname)
	s.redirect(w, r, to, "Saved.")
}

func (s *Server) handleCustomerFields(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r, "id")
	if !ok || !userFrom(r).SeesCustomer(id) {
		s.notFound(w, r)
		return
	}
	if !userFrom(r).CanWrite() {
		s.forbidden(w, r)
		return
	}
	_ = r.ParseForm()
	to := "/customers/" + strconv.FormatInt(id, 10)
	if err := s.saveFields(r, "customer", id); err != nil {
		s.redirect(w, r, to, err.Error())
		return
	}
	s.audit(r, "customer.fields", "customer:"+strconv.FormatInt(id, 10), "custom fields changed")
	s.redirect(w, r, to, "Saved.")
}

// apiDeviceFields sets custom fields of a device by name ({"name": "value"};
// an empty value removes it) and returns them.
func (s *Server) apiDeviceFields(r *http.Request, u *store.User) (int, any, error) {
	d, err := s.apiDeviceFor(r, u)
	if err != nil {
		return 0, nil, err
	}
	var in map[string]string
	if err := apiBody(r, &in); err != nil {
		return 0, nil, err
	}
	fields, err := s.store.CustomFields(r.Context(), "device")
	if err != nil {
		return 0, nil, err
	}
	byName := map[string]store.CustomField{}
	for _, f := range fields {
		byName[strings.ToLower(f.Name)] = f
	}
	vals := map[int64]string{}
	for name, v := range in {
		f, ok := byName[strings.ToLower(name)]
		if !ok {
			return 0, nil, apiErr(http.StatusBadRequest, "unknown field %q", name)
		}
		if vals[f.ID], err = fieldValue(f, v); err != nil {
			return 0, nil, apiErr(http.StatusBadRequest, "%s", err.Error())
		}
	}
	if err := s.store.SetFieldValues(r.Context(), "device", d.ID, vals); err != nil {
		return 0, nil, err
	}
	s.audit(r, "device.fields", deviceTarget(d), "custom fields of %q changed (API)", d.Hostname)
	all, err := s.store.AllFieldValues(r.Context(), "device")
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"custom_fields": all[d.ID]}, nil
}
