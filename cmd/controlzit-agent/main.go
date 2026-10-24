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
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/max-zit/controlzit/internal/agent"
	"github.com/max-zit/controlzit/internal/rd"
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
             --code CZ1-… (or --server URL --fingerprint SHA256 --token TOKEN)
             [--force] [--if-not-enrolled] [--pending-ok] [--dir DIR]
  forget     remove the enrollment (configuration and key)
  run        run the agent in the foreground
  install    install and start the service (Linux: --code CZ1-… enrolls too)
  uninstall  stop and remove the service
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
	code := fs.String("code", "", "enrollment code from the console (CZ1-…), instead of --server, --fingerprint and --token")
	ifNot := fs.Bool("if-not-enrolled", false, "do nothing when already enrolled (installer upgrades)")
	pendingOK := fs.Bool("pending-ok", false, "if the server cannot be reached, let the service finish the enrollment later")
	session := fs.String("session", "", "remote desktop session (rdhelper, started by the service)")
	technician := fs.String("technician", "", "name shown in the notice (rdhelper)")
	noNotice := fs.Bool("no-notice", false, "do not show the notice on the screen (rdhelper; console setting)")
	noClipboard := fs.Bool("no-clipboard", false, "no clipboard exchange (rdhelper; console setting)")
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
		var d agent.EnrollData
		var err error
		if *code != "" {
			d, err = agent.ParseEnrollCode(*code)
		} else {
			d, err = agent.EnrollData{Server: *server, Fingerprint: *fp, Token: *token}, nil
		}
		if err != nil {
			return err
		}
		if c, err := agent.LoadConfig(*dir); err == nil && !*force {
			if *ifNot {
				fmt.Printf("Already enrolled with %s (customer %q, site %q); nothing to do.\n", c.ServerURL, c.Customer, c.Site)
				return nil
			}
			return fmt.Errorf("already enrolled with %s (customer %q, site %q); use --force to enroll again", c.ServerURL, c.Customer, c.Site)
		}
		var restore func()
		if *force {
			// A new enrollment gets a new key; the old one is kept until the
			// new enrollment succeeds, so a wrong code does not break the agent.
			restore, err = agent.SetAside(*dir)
			if err != nil {
				return err
			}
		}
		c, err := agent.EnrollWith(ctx, *dir, d)
		if restore != nil {
			if err != nil && !(*pendingOK && !errors.As(err, new(*agent.RefusedError))) {
				restore()
			} else {
				restore = nil
				agent.DropSetAside(*dir)
			}
		}
		var refused *agent.RefusedError
		if err != nil && *pendingOK && !errors.As(err, &refused) {
			// No network yet (installed at boot, server down): the service finishes it.
			if perr := agent.SavePending(*dir, d); perr != nil {
				return perr
			}
			fmt.Println("The server cannot be reached now; the agent service will finish the enrollment:", err)
			return nil
		}
		if err != nil {
			return err
		}
		fmt.Printf("Enrolled: customer %q, site %q, device #%d.\n", c.Customer, c.Site, c.DeviceID)
		return nil
	case "forget":
		if err := agent.Forget(*dir); err != nil {
			return err
		}
		fmt.Println("Enrollment removed.")
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
	case "rdhelper":
		// Started by the service in the console session; the token comes on stdin.
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		log := slog.New(slog.NewTextHandler(agent.OpenLog(*dir), nil)).With("helper", *session)
		return agent.RunHelper(ctx, *dir, *session, *technician, line, !*noNotice, !*noClipboard, log)
	case "clipwatch":
		// Started by a remote desktop helper as the signed-in user.
		return rd.WatchFiles(ctx, os.Stdout)
	case "install":
		return installService(*code)
	case "uninstall":
		return uninstallService()
	}
	return usage()
}

func runAgent(ctx context.Context, dir string, log *slog.Logger) error {
	// Wait for the enrollment: the MSI enrolls before it starts the service,
	// or leaves a pending enrollment when the server could not be reached.
	var cfg *agent.Config
	wait := 15 * time.Second
	for {
		c, err := agent.LoadConfig(dir)
		if err == nil {
			cfg = c
			break
		}
		if !errors.Is(err, agent.ErrNotEnrolled) {
			return err
		}
		if d, ok := agent.LoadPending(dir); ok {
			c, err := agent.EnrollWith(ctx, dir, d)
			if err == nil {
				log.Info("pending enrollment finished", "customer", c.Customer, "site", c.Site)
				cfg = c
				break
			}
			log.Warn("pending enrollment failed; trying again later", "server", d.Server, "err", err)
		} else {
			log.Warn("not enrolled yet; waiting", "dir", dir)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		wait = min(2*wait, 15*time.Minute)
	}
	log.Info("ControlZit agent starting", "version", version, "server", cfg.ServerURL, "customer", cfg.Customer, "site", cfg.Site)
	a := &agent.Agent{Dir: dir, Cfg: cfg, Log: log}
	return a.Run(ctx)
}
