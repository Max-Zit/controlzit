// controlzit-agent is the ControlZit agent: it runs as a service on a
// managed machine and connects outbound to the ControlZit server.
//
//	controlzit-agent enroll --server https://rmm.example.com:8444 --fingerprint SHA256 --token czet_…
//	controlzit-agent run          # in the foreground (the service runs this)
//	controlzit-agent install      # register and start the Windows service (MSI does this itself)
//	controlzit-agent uninstall
//	controlzit-agent status | inventory | version
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/max-zit/controlzit/internal/agent"
)

var version = "dev"

func main() {
	agent.Version = version
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() error {
	fmt.Fprintln(os.Stderr, `usage: controlzit-agent <command> [options]

commands:
  enroll     join this machine to a ControlZit server
             --server URL --fingerprint SHA256 --token TOKEN [--dir DIR]
  run        run the agent in the foreground
  install    register and start the Windows service
  uninstall  stop and remove the Windows service
  status     show the enrollment
  inventory  print the inventory of this machine as JSON
  version    print the version`)
	return errors.New("no command")
}

func run(args []string) error {
	if isService() {
		return runService(agent.DefaultDir())
	}
	if len(args) == 0 {
		return usage()
	}
	cmd, args := args[0], args[1:]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	dir := fs.String("dir", agent.DefaultDir(), "data directory")
	server := fs.String("server", "", "agent endpoint of the server, e.g. https://rmm.example.com:8444")
	fp := fs.String("fingerprint", "", "SHA-256 fingerprint of the server's agent certificate")
	token := fs.String("token", "", "enrollment token of the site")
	force := fs.Bool("force", false, "enroll again even if already enrolled")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch cmd {
	case "version":
		fmt.Println("controlzit-agent", version)
		return nil
	case "enroll":
		if !*force {
			if c, err := agent.LoadConfig(*dir); err == nil {
				return fmt.Errorf("already enrolled with %s (customer %q, site %q); use --force to enroll again", c.ServerURL, c.Customer, c.Site)
			}
		} else {
			// A new enrollment gets a new key, so the old device entry stops working.
			_ = os.Remove(filepath.Join(*dir, "agent.key"))
		}
		c, err := agent.Enroll(ctx, *dir, *server, *fp, *token)
		if err != nil {
			return err
		}
		fmt.Printf("Enrolled: customer %q, site %q, device #%d.\n", c.Customer, c.Site, c.DeviceID)
		return nil
	case "status":
		c, err := agent.LoadConfig(*dir)
		if err != nil {
			return err
		}
		fmt.Printf("server:      %s\nfingerprint: %s\ncustomer:    %s\nsite:        %s\ndevice:      #%d\nagent id:    %s\nenrolled:    %s\n",
			c.ServerURL, c.Fingerprint, c.Customer, c.Site, c.DeviceID, c.AgentID, c.EnrolledAt.Local().Format(time.DateTime))
		return nil
	case "inventory":
		inv := agent.CollectInventory(ctx)
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("", "  ")
		return e.Encode(inv)
	case "run":
		log := slog.New(slog.NewTextHandler(io.MultiWriter(os.Stderr, agent.OpenLog(*dir)), nil))
		return runAgent(ctx, *dir, log)
	case "install":
		return installService()
	case "uninstall":
		return uninstallService()
	}
	return usage()
}

func runAgent(ctx context.Context, dir string, log *slog.Logger) error {
	// Wait for the enrollment (the MSI enrolls before it starts the service,
	// but a manual install may start the service first).
	var cfg *agent.Config
	for {
		c, err := agent.LoadConfig(dir)
		if err == nil {
			cfg = c
			break
		}
		if !errors.Is(err, agent.ErrNotEnrolled) {
			return err
		}
		log.Warn("not enrolled yet; waiting", "dir", dir)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Minute):
		}
	}
	log.Info("ControlZit agent starting", "version", version, "server", cfg.ServerURL, "customer", cfg.Customer, "site", cfg.Site)
	a := &agent.Agent{Dir: dir, Cfg: cfg, Log: log}
	return a.Run(ctx)
}
