package web

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	for _, c := range []struct{ in, gone, kept string }{
		{"db=postgres://rmmzit:S3cretPass99@127.0.0.1/rmmzit", "S3cretPass99", "postgres://rmmzit:***@127.0.0.1"},
		{`level=INFO msg=login password=hunter2hunter user=pera`, "hunter2hunter", "user=pera"},
		{`args="{\"session\":\"abc\",\"token\":\"tkn-123456\"}"`, "tkn-123456", "session"},
		{"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abcdef", "eyJhbGciOiJIUzI1NiJ9", "Authorization: "},
		{"code CZ1-eyJ1IjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0NCIsImYiOi used", "eyJ1Ijoi", "RZ1-***"},
		{"-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEI\n-----END EC PRIVATE KEY-----", "MHcCAQEEI", "PEM block removed"},
		{"secret key PN4k0FwwUIjaVht58ouaDRmO6TzJPZiISY1TB47KmzI3", "PN4k0Fww", "secret"},
		{"file /var/lib/rmmzit/downloads/rmmzit-agent-linux-amd64.json", "", "/var/lib/rmmzit/downloads/rmmzit-agent-linux-amd64.json"},
		{"device DESKTOP-NBB66OQ online, version 0.2.33", "", "DESKTOP-NBB66OQ online, version 0.2.33"},
	} {
		got := redact(c.in)
		if c.gone != "" && strings.Contains(got, c.gone) {
			t.Errorf("%q still contains %q: %q", c.in, c.gone, got)
		}
		if !strings.Contains(got, c.kept) {
			t.Errorf("%q lost %q: %q", c.in, c.kept, got)
		}
	}
}
