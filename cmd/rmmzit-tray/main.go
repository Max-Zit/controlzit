// rmmzit-tray shows the RMMZit icon in the notification area of a
// user session: the computer is managed, and whether the agent is connected.
// The MSI starts it at every sign-in; the agent service starts it for the
// signed-in user after installation.
package main

import (
	"flag"
	"os"
	"path/filepath"

	"github.com/max-zit/rmmzit/internal/tray"
)

func main() {
	def := filepath.Join(os.Getenv("ProgramData"), "RMMZit", "agent-status.json")
	status := flag.String("status", def, "status file written by the agent service")
	open := flag.Bool("open", false, "open the agent window (also when the icon is already running)")
	flag.Parse()
	if err := tray.Run(*status, *open); err != nil {
		os.Exit(1)
	}
}
