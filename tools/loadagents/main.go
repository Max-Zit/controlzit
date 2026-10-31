// loadagents runs many simulated agents against a test server: each one
// enrolls with a real enrollment code, keeps its own TLS channel, sends
// heartbeats with metrics and an inventory, and answers commands like an
// agent. It is a load test tool; never point it at a production server.
//
//	go run ./tools/loadagents -db postgres://… -agent https://host:8444 -fp <fingerprint> -n 500
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/max-zit/rmmzit/internal/agent"
	"github.com/max-zit/rmmzit/internal/proto"
	"github.com/max-zit/rmmzit/internal/store"
)

func main() {
	dbURL := flag.String("db", "", "database of the test server (to create the enrollment code)")
	agentURL := flag.String("agent", "", "agent endpoint of the test server, e.g. https://host:8444")
	fp := flag.String("fp", "", "agent certificate fingerprint of the test server")
	n := flag.Int("n", 100, "agents")
	dir := flag.String("dir", filepath.Join(os.TempDir(), "czload"), "folder for the agents' identities")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	agent.ProtectDir = func(string) error { return nil }
	agent.PatchScan = func(context.Context) (*agent.PatchScanResult, error) { return &agent.PatchScanResult{}, nil }

	st, err := store.Open(ctx, *dbURL)
	if err != nil {
		fmt.Println("database:", err)
		os.Exit(1)
	}
	cust, err := st.CreateCustomer(ctx, fmt.Sprintf("Load %s", time.Now().Format("15:04:05")), "")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	site, _ := st.CreateSite(ctx, cust, "Load site", "", "")
	tok, err := st.CreateEnrollToken(ctx, site, "load test", "loadagents", 24*time.Hour, *n)
	st.Close()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var enrolled, failed atomic.Int64
	start := time.Now()
	sem := make(chan struct{}, 25)
	var wg sync.WaitGroup
	agents := make([]*agent.Agent, *n)
	for i := 0; i < *n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			d := filepath.Join(*dir, fmt.Sprintf("a%05d", i))
			_ = os.MkdirAll(d, 0o700)
			cfg, err := agent.Enroll(ctx, d, *agentURL, *fp, tok)
			if err != nil {
				failed.Add(1)
				fmt.Println("enroll:", err)
				return
			}
			enrolled.Add(1)
			agents[i] = newAgent(d, cfg, i)
		}()
	}
	wg.Wait()
	fmt.Printf("enrolled %d (failed %d) in %s\n", enrolled.Load(), failed.Load(), time.Since(start).Round(time.Second))
	for _, a := range agents {
		if a != nil {
			go func() { _ = a.Run(ctx) }()
			time.Sleep(5 * time.Millisecond) // a ramp, not one burst
		}
	}
	fmt.Println("all agents running; Ctrl+C ends them")
	<-ctx.Done()
}

// newAgent is a simulated Windows computer with a realistic inventory and
// changing load.
func newAgent(dir string, cfg *agent.Config, i int) *agent.Agent {
	boot := time.Now().Add(-rand.N(72 * time.Hour)) // #nosec G404 -- simulated data
	free := (150 + rnd(50)) << 30
	host := fmt.Sprintf("LOAD-PC-%05d", i)
	var sw []proto.Software
	for j := 0; j < 150; j++ {
		sw = append(sw, proto.Software{Name: fmt.Sprintf("Program %03d", j), Version: fmt.Sprintf("%d.%d.%d", j%7, j%13, j%31), Publisher: "Vendor"})
	}
	var rx, tx atomic.Uint64
	return &agent.Agent{Dir: dir, Cfg: cfg, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Info: func() agent.SysInfo {
			return agent.SysInfo{OS: "Microsoft Windows 11 Pro", OSVersion: "10.0.26100", OSBuild: "26100", BootTime: boot, LoggedOnUser: `LOAD\user` + fmt.Sprint(i)}
		},
		Collect: func(context.Context) *proto.Inventory {
			return &proto.Inventory{Hostname: host, OS: proto.OSInfo{Name: "Microsoft Windows 11 Pro", Version: "10.0.26100", Build: "26100", Arch: "64-bit"}, Software: sw}
		},
		Metrics: func(context.Context) *proto.Metrics {
			rx.Add(rnd(5_000_000))
			tx.Add(rnd(1_000_000))
			return &proto.Metrics{CPU: float64(5 + rnd(40)), MemTotal: 16 << 30, MemUsed: (4 + rnd(8)) << 30,
				Disks: []proto.Disk{{Drive: "C:", FS: "NTFS", Size: 475 << 30, Free: free}, {Drive: "D:", FS: "NTFS", Size: 1 << 40, Free: 600 << 30}},
				NetRx: float64(rnd(200_000)), NetTx: float64(rnd(50_000))}
		}}
}

// rnd is a number below n for the simulated values.
func rnd(n uint64) uint64 {
	return rand.Uint64N(n) // #nosec G404 -- simulated data, not a secret
}
