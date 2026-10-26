package agent

import (
	"strings"

	"github.com/max-zit/controlzit/internal/proto"
)

// parseChoco reads the --limit-output lines of choco: "id|version" (search)
// or "id|current|available|pinned" (outdated).
func parseChoco(out string, outdated bool) []proto.WingetPackage {
	var list []proto.WingetPackage
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(line), "|")
		if len(f) < 2 || !proto.ValidChocoID(f[0]) {
			continue
		}
		p := proto.WingetPackage{Name: f[0], ID: f[0], Version: f[1]}
		if outdated {
			if len(f) < 3 {
				continue
			}
			p.Available = f[2]
		}
		list = append(list, p)
	}
	return list
}
