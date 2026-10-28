//go:build linux

package agent

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/max-zit/controlzit/internal/proto"
)

// Linux: everything comes from /proc, /sys, /etc/os-release and the
// package manager; no extra tools are needed.

// osRelease reads /etc/os-release.
func osRelease() map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		b, _ = os.ReadFile("/usr/lib/os-release")
	}
	for _, l := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if ok {
			out[k] = strings.Trim(v, `"'`)
		}
	}
	return out
}

func kernel() string {
	b, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	return strings.TrimSpace(string(b))
}

func bootTime() time.Time {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return time.Time{}
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if v, ok := strings.CutPrefix(s.Text(), "btime "); ok {
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				return time.Unix(n, 0).UTC()
			}
		}
	}
	return time.Time{}
}

// loggedOnUser is the first user with a session (who), or "".
func loggedOnUser() string {
	out, err := exec.Command("who").Output() // #nosec G204 -- fixed command
	if err != nil {
		return ""
	}
	if f := strings.Fields(string(out)); len(f) > 0 {
		return f[0]
	}
	return ""
}

func osName() string {
	r := osRelease()
	if n := r["PRETTY_NAME"]; n != "" {
		return n
	}
	return "Linux"
}

func basicInfo() SysInfo {
	r := osRelease()
	return SysInfo{OS: osName(), OSVersion: r["VERSION_ID"], OSBuild: kernel(), BootTime: bootTime(), LoggedOnUser: loggedOnUser()}
}

func readTrim(p string) string {
	b, _ := os.ReadFile(p) // #nosec G304 -- fixed /sys and /proc paths
	return strings.TrimSpace(string(b))
}

// meminfo returns total and available memory in bytes.
func meminfo() (total, avail uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fl := strings.Fields(s.Text())
		if len(fl) < 2 {
			continue
		}
		n, _ := strconv.ParseUint(fl[1], 10, 64)
		switch fl[0] {
		case "MemTotal:":
			total = n << 10
		case "MemAvailable:":
			avail = n << 10
		}
	}
	return total, avail
}

var realFS = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "vfat": true, "f2fs": true, "jfs": true, "reiserfs": true, "ntfs": true, "ntfs3": true, "exfat": true}

// disks lists mounted real file systems (each device once).
func disks() []proto.Disk {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return nil
	}
	defer f.Close()
	seen := map[string]bool{}
	var out []proto.Disk
	s := bufio.NewScanner(f)
	for s.Scan() {
		fl := strings.Fields(s.Text())
		if len(fl) < 3 || !realFS[fl[2]] || seen[fl[0]] || strings.HasPrefix(fl[1], "/snap/") || strings.HasPrefix(fl[1], "/boot/efi") {
			continue
		}
		var st syscall.Statfs_t
		if syscall.Statfs(fl[1], &st) != nil || st.Blocks == 0 {
			continue
		}
		seen[fl[0]] = true
		bs := uint64(st.Bsize) // #nosec G115 -- block size is positive
		out = append(out, proto.Disk{Drive: fl[1], Label: fl[0], FS: fl[2], Size: st.Blocks * bs, Free: st.Bavail * bs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Drive < out[j].Drive })
	return out
}

func cpuModel() (model string, threads int) {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return "", runtime.NumCPU()
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		k, v, ok := strings.Cut(s.Text(), ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "model name", "Model":
			if model == "" {
				model = strings.TrimSpace(v)
			}
		case "processor":
			threads++
		}
	}
	if threads == 0 {
		threads = runtime.NumCPU()
	}
	return model, threads
}

func network() []proto.NetAdapter {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	gw := defaultGateways()
	dns := resolvers()
	var out []proto.NetAdapter
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		a := proto.NetAdapter{Name: i.Name, MAC: strings.ToUpper(i.HardwareAddr.String()), Gateways: gw[i.Name], DNS: dns}
		addrs, _ := i.Addrs()
		for _, ad := range addrs {
			if ip, _, err := net.ParseCIDR(ad.String()); err == nil && !ip.IsLinkLocalUnicast() {
				a.IPs = append(a.IPs, ip.String())
			}
		}
		if len(a.IPs) > 0 {
			out = append(out, a)
		}
	}
	return out
}

// defaultGateways reads the IPv4 default routes per interface.
func defaultGateways() map[string][]string {
	out := map[string][]string{}
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return out
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fl := strings.Fields(s.Text())
		if len(fl) < 3 || fl[1] != "00000000" {
			continue
		}
		v, err := strconv.ParseUint(fl[2], 16, 32)
		if err != nil || v == 0 {
			continue
		}
		ip := net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)) // #nosec G115 -- bytes of an IPv4 address
		out[fl[0]] = append(out[fl[0]], ip.String())
	}
	return out
}

func resolvers() []string {
	b, _ := os.ReadFile("/etc/resolv.conf")
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "nameserver" {
			out = append(out, f[1])
		}
	}
	return out
}

// packages lists installed packages (dpkg or rpm).
func packages(ctx context.Context) ([]proto.Software, error) {
	var cmd *exec.Cmd
	sep := "\t"
	switch {
	case have("dpkg-query"):
		cmd = exec.CommandContext(ctx, "dpkg-query", "-W", "-f", "${db:Status-Abbrev}\t${Package}\t${Version}\t${Maintainer}\t\t${source:Package}\t${source:Version}\n")
	case have("rpm"):
		cmd = exec.CommandContext(ctx, "rpm", "-qa", "--qf", "ii \t%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{INSTALLTIME:date}\n")
	default:
		return nil, nil
	}
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var list []proto.Software
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Split(l, sep)
		if len(f) < 4 || !strings.HasPrefix(f[0], "ii") {
			continue
		}
		s := proto.Software{Name: f[1], Version: f[2], Publisher: f[3]}
		if len(f) > 4 {
			s.InstallDate = f[4]
		}
		if len(f) > 6 {
			s.Source, s.SourceVersion = f[5], f[6]
		}
		list = append(list, s)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	if len(list) > 5000 {
		list = list[:5000]
	}
	return list, nil
}

func have(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func rebootRequired() bool {
	_, err := os.Stat("/var/run/reboot-required")
	return err == nil
}

// CollectInventory gathers the inventory of a Linux machine.
func CollectInventory(ctx context.Context) *proto.Inventory {
	r := osRelease()
	host, _ := os.Hostname()
	inv := &proto.Inventory{CollectedAt: time.Now().UTC(), Hostname: host, LoggedOnUser: loggedOnUser(), PendingReboot: rebootRequired(),
		OS: proto.OSInfo{Name: osName(), Version: r["VERSION_ID"], Build: kernel(), DisplayVer: r["VERSION_CODENAME"], Arch: runtime.GOARCH, BootTime: bootTime()}}
	if fqdn, err := exec.CommandContext(ctx, "hostname", "-d").Output(); err == nil { // #nosec G204 -- fixed command
		inv.Domain = strings.TrimSpace(string(fqdn))
		inv.PartOfDomain = inv.Domain != ""
	}
	model, threads := cpuModel()
	total, _ := meminfo()
	virt := readTrim("/sys/class/dmi/id/sys_vendor")
	inv.Hardware = proto.Hardware{Manufacturer: virt, Model: readTrim("/sys/class/dmi/id/product_name"), Serial: readTrim("/sys/class/dmi/id/product_serial"),
		BIOS: strings.TrimSpace(readTrim("/sys/class/dmi/id/bios_vendor") + " " + readTrim("/sys/class/dmi/id/bios_version")),
		CPU:  model, Cores: runtime.NumCPU(), Threads: threads, MemoryBytes: total}
	for _, v := range []string{"QEMU", "VMware", "Microsoft Corporation", "Xen", "innotek", "KVM", "Proxmox", "Red Hat"} {
		if strings.Contains(virt, v) || strings.Contains(inv.Hardware.Model, v) {
			inv.Hardware.Virtual = true
		}
	}
	if _, err := os.Stat("/proc/1/environ"); err == nil {
		if b, _ := os.ReadFile("/proc/1/environ"); bytes.Contains(b, []byte("container=")) { // LXC, docker
			inv.Hardware.Virtual = true
		}
	}
	inv.Disks = disks()
	inv.Network = network()
	sw, err := packages(ctx)
	if err != nil {
		inv.Errors = append(inv.Errors, "packages: "+err.Error())
	}
	inv.Software = sw
	return inv
}

// ---- metrics

var cpuPrev struct {
	sync.Mutex
	idle, total uint64
}

func cpuPercent() float64 {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	line, _, _ := strings.Cut(string(b), "\n")
	f := strings.Fields(line)
	if len(f) < 5 || f[0] != "cpu" {
		return 0
	}
	var idle, total uint64
	for i, v := range f[1:] {
		n, _ := strconv.ParseUint(v, 10, 64)
		total += n
		if i == 3 || i == 4 { // idle, iowait
			idle += n
		}
	}
	cpuPrev.Lock()
	defer cpuPrev.Unlock()
	di, dt := idle-cpuPrev.idle, total-cpuPrev.total
	first := cpuPrev.total == 0
	cpuPrev.idle, cpuPrev.total = idle, total
	if first || dt == 0 {
		return 0
	}
	return float64(dt-di) / float64(dt) * 100
}

var lastFailed time.Time

// failedUnits lists systemd services in the failed state.
func failedUnits(ctx context.Context) []string {
	out, err := exec.CommandContext(ctx, "systemctl", "list-units", "--type=service", "--state=failed", "--no-legend", "--plain", "--no-pager").Output() // #nosec G204 -- fixed command
	if err != nil {
		return nil
	}
	list := []string{}
	for _, l := range strings.Split(string(out), "\n") {
		if f := strings.Fields(l); len(f) > 0 {
			list = append(list, strings.TrimSuffix(f[0], ".service"))
		}
	}
	return list
}

// CollectMetrics samples the machine for a heartbeat.
func CollectMetrics(ctx context.Context) *proto.Metrics {
	total, avail := meminfo()
	m := &proto.Metrics{CPU: cpuPercent(), MemTotal: total, MemUsed: total - min(avail, total), Disks: disks()}
	if rx, tx, ok := netCounters(); ok {
		m.NetRx, m.NetTx = netPrev.rate(rx, tx, time.Now())
	}
	if time.Since(lastFailed) >= 5*time.Minute && have("systemctl") {
		lastFailed = time.Now()
		m.StoppedAuto = failedUnits(ctx)
		m.Security = &proto.SecurityState{PendingReboot: rebootRequired(), CheckedAt: time.Now().UTC()}
	}
	return m
}

// netCounters sums the bytes received and sent by all interfaces except
// loopback, from /proc/net/dev.
func netCounters() (rx, tx uint64, ok bool) {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0, false
	}
	return parseNetDev(string(b))
}
