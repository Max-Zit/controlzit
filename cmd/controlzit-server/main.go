// controlzit-server is the ControlZit server: the management console on
// one listener and the agent endpoint on another.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"github.com/max-zit/controlzit/internal/auth"
	"github.com/max-zit/controlzit/internal/helper"
	"github.com/max-zit/controlzit/internal/logfile"
	"github.com/max-zit/controlzit/internal/netacl"
	"github.com/max-zit/controlzit/internal/store"
	"github.com/max-zit/controlzit/internal/tlsutil"
	"github.com/max-zit/controlzit/internal/web"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func defaultDataDir() string {
	if runtime.GOOS == "windows" {
		if p := os.Getenv("ProgramData"); p != "" {
			return filepath.Join(p, "ControlZit")
		}
	}
	return "/var/lib/controlzit"
}

func run() error {
	dataDir := flag.String("data-dir", env("CONTROLZIT_DATA", defaultDataDir()), "data directory (certificates, secret key)")
	dbURL := flag.String("db", os.Getenv("CONTROLZIT_DB"), "PostgreSQL URL, e.g. postgres://controlzit:…@localhost/controlzit")
	devDB := flag.Bool("dev-embedded-db", false, "start a private PostgreSQL in the data directory (development and evaluation only)")
	mgmtListen := flag.String("mgmt-listen", "", "console address; overrides the saved setting (e.g. 127.0.0.1:8443)")
	agentListen := flag.String("agent-listen", "", "agent endpoint address; overrides the saved setting (e.g. :8444)")
	devHTTP := flag.String("dev-http", "", "also serve the console over plain HTTP on this loopback address (development only)")
	devNo2FA := flag.Bool("dev-no-2fa", false, "sign in with the password only (development and lab tests only; shown as a warning in the console and audited)")
	resetACL := flag.Bool("reset-allowlist", false, "allow the console again from the private networks (10/8, 172.16/12, 192.168/16, fc00::/7) and exit")
	unblock := flag.String("unblock-ip", "", "lift the sign-in block of an address (or \"all\") and exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	runHelper := flag.Bool("helper", false, "root helper: handle a request of the console (updates, time zone, network) and exit; started by controlzit-helper.service")
	flag.Parse()

	if *showVersion {
		fmt.Println("controlzit-server", version)
		return nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *runHelper {
		// Its own log in a directory only root can write (Settings → Diagnostics shows it).
		out := io.Writer(os.Stdout)
		if lw, err := logfile.Open("/var/log/controlzit-helper/helper.log", 0o644); err == nil {
			_ = os.Chmod("/var/log/controlzit-helper", 0o755) // the console reads it, only root writes
			defer lw.Close()
			out = io.MultiWriter(os.Stdout, lw)
		}
		log := slog.New(slog.NewTextHandler(out, nil))
		h := &helper.Helper{DataDir: *dataDir, CacheDir: "/var/cache/controlzit", EnvFile: "/etc/controlzit/server.env", Binary: "/usr/bin/controlzit-server",
			Run: helper.RunCommand, Log: func(format string, args ...any) { log.Info(fmt.Sprintf(format, args...)) }}
		return h.Handle(ctx)
	}
	// The server log: the journal and a file in the data directory (Settings → Diagnostics).
	srvLogFile := ""
	var logOut io.Writer = os.Stdout
	if err := os.MkdirAll(*dataDir, 0o700); err == nil {
		if lw, err := logfile.Open(filepath.Join(*dataDir, "logs", "server.log"), 0o600); err == nil {
			defer lw.Close()
			logOut = io.MultiWriter(os.Stdout, lw)
			srvLogFile = filepath.Join(*dataDir, "logs", "server.log")
		}
	}
	log := slog.New(slog.NewTextHandler(logOut, nil))

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		return err
	}
	if *devDB {
		pg, url, err := startEmbeddedDB(*dataDir)
		if err != nil {
			return fmt.Errorf("embedded database: %w", err)
		}
		defer pg.Stop()
		*dbURL = url
		log.Warn("using the embedded development database", "dir", filepath.Join(*dataDir, "pgdata"))
	}
	if *dbURL == "" {
		return errors.New("database URL required (--db or CONTROLZIT_DB)")
	}
	st, err := store.Open(ctx, *dbURL)
	if err != nil {
		return err
	}
	defer st.Close()
	key, created, err := store.LoadOrCreateSecretKey(*dataDir)
	if err != nil {
		return fmt.Errorf("secret key: %w", err)
	}
	if err := st.UseSecretKey(key); err != nil {
		return err
	}
	if created {
		log.Warn("created a new secret key; back it up together with the database", "file", filepath.Join(*dataDir, store.SecretKeyFile))
	}

	switch {
	case *resetACL:
		if err := web.ResetMgmtAllowList(ctx, st); err != nil {
			return err
		}
		_ = st.Audit(ctx, "-", "local", "settings.network.reset", "settings", "console allow-list reset to the private networks from the command line")
		fmt.Println("The console allows the private networks again. Restart the service if it is running.")
		return nil
	case *unblock != "":
		n, err := st.Unblock(ctx, *unblock)
		if err != nil {
			return err
		}
		_ = st.Audit(ctx, "-", "local", "login.unblock", "ip:"+*unblock, "sign-in block lifted from the command line")
		fmt.Printf("Lifted %d block(s).\n", n)
		return nil
	}

	srv, err := web.New(ctx, st, log)
	if err != nil {
		return err
	}
	srv.Version = version
	srv.DownloadsDir = filepath.Join(*dataDir, "downloads")
	srv.DataDir = *dataDir
	srv.LogFile = srvLogFile
	if *devNo2FA {
		// For development and lab tests only: the console shows a red warning
		// on every page and the audit log records each start in this mode.
		srv.DevNo2FA = true
		log.Warn("TEST MODE: two-factor sign-in is switched off (--dev-no-2fa); never use this on a production server")
		_ = st.Audit(ctx, "-", "local", "settings.2fa.off", "server", "server started with --dev-no-2fa: sign-in with the password only")
	}
	net0, err := srv.Network(ctx)
	if err != nil {
		return err
	}
	if *mgmtListen != "" {
		net0.MgmtListen = *mgmtListen
	}
	if *agentListen != "" {
		net0.AgentListen = *agentListen
	}
	if err := net0.Validate(); err != nil {
		return err
	}
	srv.RunningMgmt, srv.RunningAgent = net0.MgmtListen, net0.AgentListen
	srv.ListenOverride = *mgmtListen != "" || *agentListen != ""

	tlsDir := filepath.Join(*dataDir, "tls")
	agentCert, err := tlsutil.LoadOrCreate(tlsDir, "agent", "ControlZit agent endpoint", 20)
	if err != nil {
		return fmt.Errorf("agent certificate: %w", err)
	}
	consoleCert, err := tlsutil.LoadOrCreate(tlsDir, "console", "ControlZit console", 5)
	if err != nil {
		return fmt.Errorf("console certificate: %w", err)
	}
	srv.AgentFingerprint = tlsutil.Fingerprint(agentCert)
	if srv.CommandKey, err = tlsutil.LoadOrCreateEd25519(filepath.Join(tlsDir, "command.key")); err != nil {
		return fmt.Errorf("command key: %w", err)
	}

	if n, err := st.UserCount(ctx); err != nil {
		return err
	} else if n == 0 {
		tok := auth.RandomToken(18)
		p := filepath.Join(*dataDir, "setup-token.txt")
		if err := os.WriteFile(p, []byte(tok+"\n"), 0o600); err != nil {
			return err
		}
		srv.SetSetupToken(tok)
		srv.SetupTokenFile = p
		log.Warn("no users yet: open the console and finish the setup; the setup token is in the file", "file", p)
	}

	refused := func(kind string) func(string) {
		return func(remote string) { log.Debug("connection refused by allow-list", "listener", kind, "remote", remote) }
	}
	errc := make(chan error, 3)
	var servers []*http.Server
	serve := func(addr string, cfg *tls.Config, list *netacl.List, h http.Handler, kind string) error {
		raw, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("%s listener %s: %w", kind, addr, err)
		}
		l := tls.NewListener(&netacl.Listener{Listener: raw, List: list, OnRefuse: refused(kind)}, cfg)
		hs := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 120 * time.Second,
			IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10, ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelDebug)}
		servers = append(servers, hs)
		go func() { errc <- hs.Serve(l) }()
		log.Info("listening", "listener", kind, "addr", raw.Addr().String())
		return nil
	}
	srv.TLS = web.NewConsoleTLS(filepath.Join(tlsDir, "web"), consoleCert, log)
	srv.Port80Addr = env("CONTROLZIT_HTTP80", ":80")
	if err := serve(net0.MgmtListen, srv.TLS.Config(), srv.MgmtACL, srv.Handler(), "console"); err != nil {
		return err
	}
	if err := serve(net0.AgentListen, tlsutil.AgentServerConfig(agentCert), srv.AgentACL, srv.AgentHandler(), "agent"); err != nil {
		return err
	}
	if *devHTTP != "" {
		a, ok := netacl.AddrOf(*devHTTP)
		if !ok || !a.IsLoopback() {
			return errors.New("--dev-http must be a loopback address such as 127.0.0.1:8080")
		}
		hs := &http.Server{Addr: *devHTTP, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
		servers = append(servers, hs)
		go func() { errc <- hs.ListenAndServe() }()
		log.Warn("development HTTP console (no TLS)", "addr", *devHTTP)
	}
	log.Info("ControlZit server started", "version", version, "agent_fingerprint", srv.AgentFingerprint)
	// For the root helper: which version runs and where (it checks this after an update).
	if err := helper.WriteServerInfo(*dataDir, helper.ServerInfo{Version: version, MgmtListen: net0.MgmtListen}); err != nil {
		log.Warn("cannot write the helper information", "err", err)
	}

	go srv.RunMonitor(ctx)
	go srv.RunCertificates(ctx)
	go srv.RunUpdates(ctx)
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = st.PurgeSessions(ctx)
			}
		}
	}()

	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, hs := range servers {
		_ = hs.Shutdown(shut)
	}
	log.Info("stopped")
	return nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// startEmbeddedDB runs PostgreSQL from the data directory on a fixed
// loopback port (development only).
func startEmbeddedDB(dir string) (*embeddedpostgres.EmbeddedPostgres, string, error) {
	const port = 54329
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().Port(port).
		DataPath(filepath.Join(dir, "pgdata")).RuntimePath(filepath.Join(dir, "pgrt")).
		BinariesPath(filepath.Join(dir, "pgbin")).Database("controlzit").Logger(io.Discard))
	if err := pg.Start(); err != nil {
		return nil, "", err
	}
	return pg, fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d/controlzit?sslmode=disable", port), nil
}
