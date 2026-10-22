package agent

import (
	"strings"

	"github.com/max-zit/controlzit/internal/proto"
)

// parseWingetTable reads the first table of winget output. Columns start
// where the header names them; a name longer than its column pushes the
// rest of that row to the right, so the row's columns are shifted by as
// much as its ID starts late. Columns may be empty (no newer version).
func parseWingetTable(out string) []proto.WingetPackage {
	lines := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")
	for i, l := range lines {
		if j := strings.LastIndexByte(l, '\r'); j >= 0 { // progress spinners
			lines[i] = l[j+1:]
		}
	}
	head := -1
	for i := 0; i+1 < len(lines); i++ {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), "Name") && strings.HasPrefix(strings.TrimSpace(lines[i+1]), "---") {
			head = i
			break
		}
	}
	if head < 0 {
		return nil
	}
	hdr := []rune(strings.TrimLeft(lines[head], " "))
	type col struct {
		name  string
		start int
	}
	var cols []col
	for i := 0; i < len(hdr); i++ {
		if hdr[i] != ' ' && (i == 0 || hdr[i-1] == ' ') {
			j := i
			for j < len(hdr) && hdr[j] != ' ' {
				j++
			}
			cols = append(cols, col{string(hdr[i:j]), i})
		}
	}
	if len(cols) < 2 || cols[0].name != "Name" || cols[1].name != "Id" {
		return nil
	}
	var pkgs []proto.WingetPackage
	for _, l := range lines[head+2:] {
		row := []rune(l)
		if strings.TrimSpace(l) == "" || len(row) <= cols[1].start {
			break
		}
		// Where does the ID really start?
		idAt := cols[1].start
		if row[idAt-1] != ' ' {
			for idAt < len(row) && row[idAt] != ' ' {
				idAt++
			}
			for idAt < len(row) && row[idAt] == ' ' {
				idAt++
			}
		}
		shift := idAt - cols[1].start
		field := func(k int) string {
			from := cols[k].start + shift
			to := len(row)
			if k+1 < len(cols) {
				to = min(cols[k+1].start+shift, len(row))
			}
			if from >= len(row) || from >= to {
				return ""
			}
			return strings.TrimSpace(string(row[from:to]))
		}
		p := proto.WingetPackage{Name: strings.TrimSpace(string(row[:idAt]))}
		for k := 1; k < len(cols); k++ {
			switch cols[k].name {
			case "Id":
				p.ID = field(k)
			case "Version":
				p.Version = field(k)
			case "Available":
				p.Available = field(k)
			}
		}
		if !proto.ValidWingetID(p.ID) {
			break // a summary line such as "7 upgrades available."
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}
