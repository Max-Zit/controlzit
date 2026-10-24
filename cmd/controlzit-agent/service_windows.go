//go:build windows

package main

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"log/slog"
	"os"
	"time"

	"github.com/max-zit/controlzit/internal/agent"
)

const (
	serviceName = "ControlZitAgent"
	serviceDesc = "ControlZit remote monitoring and management agent (MaxZit)."
)

func isService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

type handler struct{ dir string }

func (h handler) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	log := slog.New(slog.NewTextHandler(agent.OpenLog(h.dir), nil))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runAgent(ctx, h.dir, log) }()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	go func() {
		// The icon for the user signed in now (later sign-ins: the Run key).
		time.Sleep(5 * time.Second)
		if err := agent.StartTray(); err != nil {
			log.Warn("cannot start the tray icon", "err", err)
		}
	}()
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				st <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(15 * time.Second):
				}
				return false, 0
			}
		case err := <-done:
			cancel()
			if err != nil {
				log.Error("agent stopped", "err", err)
				return false, 1
			}
			return false, 0
		}
	}
}

func runService(dir string) error {
	if err := agent.EnsureDir(dir); err != nil {
		return err
	}
	return svc.Run(serviceName, handler{dir: dir})
}

func installService(string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager (run as administrator): %w", err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		_ = s.Close()
		return fmt.Errorf("service %s already exists", serviceName)
	}
	s, err := m.CreateService(serviceName, exe, mgr.Config{DisplayName: "ControlZit Agent", Description: serviceDesc,
		StartType: mgr.StartAutomatic, DelayedAutoStart: true})
	if err != nil {
		return err
	}
	defer s.Close()
	// Restart after a crash: 10 s, 30 s, then every 60 s.
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second}, {Type: mgr.ServiceRestart, Delay: 60 * time.Second}}, 86400)
	if err := s.Start(); err != nil {
		return fmt.Errorf("service installed but not started: %w", err)
	}
	fmt.Println("Service", serviceName, "installed and started.")
	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager (run as administrator): %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	defer s.Close()
	if st, err := s.Control(svc.Stop); err == nil {
		for i := 0; i < 30 && st.State != svc.Stopped; i++ {
			time.Sleep(500 * time.Millisecond)
			st, _ = s.Query()
		}
	}
	if err := s.Delete(); err != nil {
		return err
	}
	fmt.Println("Service", serviceName, "removed.")
	return nil
}
