//go:build windows

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/max-zit/rmmzit/internal/proto"
)

func init() { register(proto.KindEventQuery, queryEvents) }

// eventScript reads a log with Get-WinEvent; the placeholders are filled
// with validated values only (the log name from a fixed list, numbers).
const eventScript = `$ErrorActionPreference = 'SilentlyContinue'
$w = New-Object IO.StreamWriter([Console]::OpenStandardOutput(), (New-Object Text.UTF8Encoding $false))
$f = @{ LogName = '@LOG@'; StartTime = (Get-Date).AddHours(-@HOURS@) }
@LEVEL@
@ID@
$out = @(Get-WinEvent -FilterHashtable $f -MaxEvents @MAX@ | ForEach-Object {
  $m = [string]$_.Message
  if ($m.Length -gt 2000) { $m = $m.Substring(0, 2000) }
  [pscustomobject]@{ time = $_.TimeCreated.ToUniversalTime().ToString('o'); level = [int]$_.Level; id = [int]$_.Id; provider = [string]$_.ProviderName; message = $m }
})
$w.Write((ConvertTo-Json -InputObject $out -Depth 3 -Compress)); $w.Flush()
`

func queryEvents(ctx context.Context, raw json.RawMessage) (any, error) {
	var q proto.EventQuery
	if err := args(raw, &q); err != nil {
		return nil, err
	}
	known := false
	for _, l := range proto.EventLogs {
		if q.Log == l {
			known = true
		}
	}
	if !known || q.Hours < 1 || q.Hours > 720 || q.Max < 1 || q.Max > 1000 || q.Level < 0 || q.Level > 3 || q.ID < 0 || q.ID > 65535 || len(q.Text) > 200 {
		return nil, errors.New("bad event query")
	}
	// A text filter is applied here, so read more events for it.
	fetch := q.Max + 1
	if q.Text != "" {
		fetch = 5000
	}
	level := ""
	switch q.Level {
	case 1:
		level = "$f.Level = 1"
	case 2:
		level = "$f.Level = @(1, 2)"
	case 3:
		level = "$f.Level = @(1, 2, 3)"
	}
	id := ""
	if q.ID > 0 {
		id = "$f.Id = " + strconv.Itoa(q.ID)
	}
	script := strings.NewReplacer("@LOG@", q.Log, "@HOURS@", strconv.Itoa(q.Hours), "@LEVEL@", level, "@ID@", id, "@MAX@", strconv.Itoa(fetch)).Replace(eventScript)
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var events []proto.Event
	if err := runPatchScript(cctx, script, &events); err != nil {
		return nil, err
	}
	res := &proto.EventResult{}
	text := strings.ToLower(q.Text)
	for _, e := range events {
		if text != "" && !strings.Contains(strings.ToLower(e.Message), text) && !strings.Contains(strings.ToLower(e.Provider), text) {
			continue
		}
		if len(res.Events) == q.Max {
			res.Truncated = true
			break
		}
		res.Events = append(res.Events, e)
	}
	return res, nil
}
