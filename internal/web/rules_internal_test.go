package web

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
	"github.com/max-zit/controlzit/internal/store"
)

func kinds(conds []store.Condition) map[string]store.Condition {
	out := map[string]store.Condition{}
	for _, c := range conds {
		out[c.Kind+"/"+c.Key] = c
	}
	return out
}

func TestEvaluateRules(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-30 * time.Second)
	old := now.Add(-40 * time.Minute)
	boot := now.Add(-10 * 24 * time.Hour)
	m := defaultMonitoring()
	m.WatchServices = []string{"spooler"}
	states := []store.MonitorState{
		{ID: 1, Connected: true, LastSeen: &recent, BootTime: &boot, AvgCPU: 97, AvgMem: 50, Samples: 15,
			Metrics: &proto.Metrics{Disks: []proto.Disk{{Drive: "C:", Size: 100 << 30, Free: 3 << 30}, {Drive: "D:", Size: 100 << 30, Free: 60 << 30}, {Drive: "E:", Size: 10 << 30, Free: 512 << 20}, {Drive: "F:", Size: 4 << 30, Free: 3700 << 20}}},
			Security: &proto.SecurityState{DefenderPresent: true, DefenderAV: true, DefenderRealTime: false, PendingReboot: true,
				Firewall: []proto.Firewall{{Profile: "Domain", Enabled: true}, {Profile: "Public", Enabled: false}}},
			StoppedAuto: []string{"Spooler", "gupdate"}},
		{ID: 2, Connected: false, LastSeen: &old},
		{ID: 3, Connected: true, LastSeen: &recent, AvgCPU: 99, Samples: 3}, // too few samples
		{ID: 4}, // never connected
	}
	conds, keep := evaluate(m, states, now)
	k := kinds(conds)
	for _, want := range []string{"cpu/", "disk/C:", "disk/E:", "defender/", "firewall/Public", "reboot/", "service/Spooler", "offline/"} {
		if _, ok := k[want]; !ok {
			t.Errorf("missing alert %s", want)
		}
	}
	for _, not := range []string{"memory/", "disk/D:", "disk/F:", "firewall/Domain", "service/gupdate"} {
		if _, ok := k[not]; ok {
			t.Errorf("unexpected alert %s", not)
		}
	}
	if k["disk/E:"].Severity != "critical" || k["disk/C:"].Severity != "warning" {
		t.Errorf("disk severities: %+v %+v", k["disk/C:"], k["disk/E:"])
	}
	if !keep[2] || keep[1] {
		t.Errorf("keep: %v", keep)
	}
	for _, c := range conds {
		if c.DeviceID == 3 || c.DeviceID == 4 {
			t.Errorf("alert for device %d: %+v", c.DeviceID, c)
		}
	}
	m.DefenderOff, m.FirewallOff = false, false
	conds, _ = evaluate(m, states, now)
	if _, ok := kinds(conds)["defender/"]; ok {
		t.Error("Defender alert although switched off")
	}
}

func TestMonitoringValidate(t *testing.T) {
	m := defaultMonitoring()
	if m.Validate() != nil {
		t.Fatal("defaults invalid")
	}
	m.Recipients = []string{"not an address"}
	if m.Validate() == nil {
		t.Fatal("bad recipient accepted")
	}
	e := EmailSettings{Host: "smtp.example.com", Port: 25, Security: "none", Username: "u", From: "rmm@example.com"}
	if e.Validate() == nil {
		t.Fatal("password over a plain connection accepted")
	}
	e.Security = "starttls"
	if e.Validate() != nil {
		t.Fatal("valid settings refused")
	}
}

// fakeSMTP accepts one message and returns it.
func fakeSMTP(t *testing.T) (string, <-chan string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	got := make(chan string, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		w := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
		w("220 test ESMTP")
		var data strings.Builder
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if line == ".\r\n" {
					inData = false
					w("250 queued")
					got <- data.String()
					continue
				}
				data.WriteString(line)
				continue
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				w("250 test")
			case cmd == "DATA":
				inData = true
				w("354 go ahead")
			case cmd == "QUIT":
				w("221 bye")
				return
			default:
				w("250 ok")
			}
		}
	}()
	return l.Addr().String(), got
}

func TestSendMail(t *testing.T) {
	addr, got := fakeSMTP(t)
	host, port, _ := net.SplitHostPort(addr)
	p := 0
	for _, c := range port {
		p = p*10 + int(c-'0')
	}
	e := EmailSettings{Host: host, Port: p, Security: "none", From: "ControlZit <rmm@example.com>"}
	devs := map[int64]store.MonitorState{7: {ID: 7, Hostname: "PC-07", Customer: "Acme", Site: "HQ"}}
	subject, body := alertEmail([]store.Alert{{DeviceID: 7, Kind: AlertDisk, Key: "C:", Severity: "critical", Message: "0.5 GB free", OpenedAt: time.Now()}}, devs)
	if err := sendMail(context.Background(), e, []string{"it@example.com"}, subject, body); err != nil {
		t.Fatal(err)
	}
	msg := <-got
	for _, want := range []string{"Subject: ControlZit critical: Low disk space on PC-07", "PC-07", "Acme / HQ", "0.5 GB free", "To: it@example.com"} {
		if !strings.Contains(msg, want) {
			t.Errorf("mail lacks %q:\n%s", want, msg)
		}
	}
}

func TestSendMailHTML(t *testing.T) {
	addr, got := fakeSMTP(t)
	host, port, _ := net.SplitHostPort(addr)
	p := 0
	for _, c := range port {
		p = p*10 + int(c-'0')
	}
	e := EmailSettings{Host: host, Port: p, Security: "none", From: "rmm@example.com"}
	html := "<html><body><h1>Izveštaj čćž</h1>" + strings.Repeat("<p>line</p>", 50) + "</body></html>"
	if err := sendMailHTML(context.Background(), e, []string{"it@example.com"}, "Report", "plain text", html); err != nil {
		t.Fatal(err)
	}
	msg := <-got
	m, err := mail.ReadMessage(strings.NewReader(msg))
	if err != nil {
		t.Fatal(err)
	}
	mt, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/alternative" {
		t.Fatalf("content type %q %v", mt, err)
	}
	mr := multipart.NewReader(m.Body, params["boundary"])
	var parts []string
	for {
		pt, err := mr.NextPart()
		if err != nil {
			break
		}
		b, _ := io.ReadAll(pt)
		if pt.Header.Get("Content-Transfer-Encoding") == "base64" {
			b, _ = base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.ReplaceAll(string(b), "\r\n", ""), "\n", ""))
		}
		parts = append(parts, pt.Header.Get("Content-Type")+"|"+string(b))
	}
	if len(parts) != 2 || !strings.Contains(parts[0], "plain text") || !strings.Contains(parts[1], "text/html") || !strings.Contains(parts[1], "Izveštaj čćž") {
		t.Fatalf("parts: %q", parts)
	}
}

func TestPackagePlatform(t *testing.T) {
	elf := func(machine byte) []byte {
		h := make([]byte, 20)
		copy(h, "\x7fELF")
		h[4], h[5], h[18] = 2, 1, machine
		return h
	}
	for _, c := range []struct {
		head []byte
		want string
	}{
		{[]byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1rest-of-header"), proto.PlatformWindows},
		{elf(0x3e), proto.PlatformLinuxAMD64},
		{elf(0xb7), proto.PlatformLinuxARM64},
		{elf(0x28), ""}, // 32-bit ARM
		{[]byte("MZ\x90\x00 windows exe......"), ""},
		{[]byte("short"), ""},
	} {
		if got := packagePlatform(c.head); got != c.want {
			t.Errorf("%q: %q, want %q", c.head[:4], got, c.want)
		}
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"/devices/4":            "/devices/4",
		"/audit?q=x":            "/audit?q=x",
		"//evil.example":        "/",
		"/\\evil.example":       "/",
		"/\t/evil.example":      "/",
		"/\n/evil.example":      "/",
		"/\x00/evil.example":    "/",
		"https://evil.example/": "/",
		"evil.example":          "/",
		"":                      "/",
	} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDevicePaths(t *testing.T) {
	for _, c := range []struct{ in, parent, base string }{
		{`C:\Users\ana`, `C:\Users`, "ana"},
		{`C:\Users`, `C:\`, "Users"},
		{`C:\`, "", "C:"},
		{"/etc/ssh", "/etc", "ssh"},
		{"/etc", "/", "etc"},
		{"/", "", ""},
	} {
		if p := winParent(c.in); p != c.parent {
			t.Errorf("parent(%q) = %q, want %q", c.in, p, c.parent)
		}
		if b := winBase(c.in); b != c.base {
			t.Errorf("base(%q) = %q, want %q", c.in, b, c.base)
		}
	}
	if j := winJoin("/", "etc"); j != "/etc" {
		t.Errorf("join / etc = %q", j)
	}
	if j := winJoin("/etc", "ssh"); j != "/etc/ssh" {
		t.Errorf("join /etc ssh = %q", j)
	}
	if j := winJoin(`C:\`, "Users"); j != `C:\Users` {
		t.Errorf("join C: = %q", j)
	}
	cr := crumbs("/etc/ssh")
	if len(cr) != 3 || cr[0].Path != "/" || cr[1].Path != "/etc" || cr[2].Path != "/etc/ssh" {
		t.Errorf("crumbs: %+v", cr)
	}
}
