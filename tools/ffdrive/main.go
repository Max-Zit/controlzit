// ffdrive drives a running Firefox over WebDriver BiDi for lab tests (real
// key presses and clicks, so the clipboard behaves as for a user). Start
// Firefox with its own profile and --remote-debugging-port 9333, then:
//
//	ffdrive -port 9333 nav URL | eval JS | keys "Control+v" | type TEXT | click X Y
//
// Each run opens a BiDi session, acts on the first tab and ends the session.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
)

var (
	ws  *websocket.Conn
	ctx context.Context
	id  int
)

func call(method string, params any) (json.RawMessage, error) {
	id++
	b, _ := json.Marshal(map[string]any{"id": id, "method": method, "params": params})
	if err := ws.Write(ctx, websocket.MessageText, b); err != nil {
		return nil, err
	}
	for {
		_, data, err := ws.Read(ctx)
		if err != nil {
			return nil, err
		}
		var m struct {
			ID     int             `json:"id"`
			Type   string          `json:"type"`
			Result json.RawMessage `json:"result"`
			Error  string          `json:"error"`
			Msg    string          `json:"message"`
		}
		_ = json.Unmarshal(data, &m)
		if m.ID != id {
			continue // events
		}
		if m.Type == "error" {
			return nil, fmt.Errorf("%s: %s", m.Error, m.Msg)
		}
		return m.Result, nil
	}
}

var keyNames = map[string]string{"Control": "", "Shift": "", "Alt": "", "Enter": "", "Escape": "", "Tab": ""}

func key(k string) string {
	if v, ok := keyNames[k]; ok {
		return v
	}
	return k
}

func main() {
	port := flag.Int("port", 9333, "remote debugging port")
	flag.Parse()
	args := flag.Args()
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var err error
	ws, _, err = websocket.Dial(ctx, "ws://127.0.0.1:"+strconv.Itoa(*port)+"/session", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		os.Exit(1)
	}
	defer ws.CloseNow()
	ws.SetReadLimit(64 << 20)
	if _, err := call("session.new", map[string]any{"capabilities": map[string]any{"alwaysMatch": map[string]any{"acceptInsecureCerts": true}}}); err != nil {
		fmt.Fprintln(os.Stderr, "session:", err)
		os.Exit(1)
	}
	defer func() { _, _ = call("session.end", map[string]any{}) }()
	tree, err := call("browsingContext.getTree", map[string]any{})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var t struct {
		Contexts []struct {
			Context string `json:"context"`
		} `json:"contexts"`
	}
	_ = json.Unmarshal(tree, &t)
	c := t.Contexts[0].Context
	res, err := run(c, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(res)
}

func run(c string, args []string) (string, error) {
	switch args[0] {
	case "nav":
		_, err := call("browsingContext.navigate", map[string]any{"context": c, "url": args[1], "wait": "complete"})
		return "ok", err
	case "eval", "evalu": // evalu: as if the user acted
		r, err := call("script.evaluate", map[string]any{"expression": args[1], "target": map[string]any{"context": c}, "awaitPromise": true, "userActivation": args[0] == "evalu"})
		return string(r), err
	case "keys": // "Control+v": hold the modifiers, press the last key
		parts := strings.Split(args[1], "+")
		var acts []map[string]any
		for _, p := range parts {
			acts = append(acts, map[string]any{"type": "keyDown", "value": key(p)})
		}
		for i := len(parts) - 1; i >= 0; i-- {
			acts = append(acts, map[string]any{"type": "keyUp", "value": key(parts[i])})
		}
		_, err := call("input.performActions", map[string]any{"context": c, "actions": []any{map[string]any{"type": "key", "id": "kb", "actions": acts}}})
		return "ok", err
	case "type":
		var acts []map[string]any
		for _, r := range args[1] {
			acts = append(acts, map[string]any{"type": "keyDown", "value": string(r)}, map[string]any{"type": "keyUp", "value": string(r)})
		}
		_, err := call("input.performActions", map[string]any{"context": c, "actions": []any{map[string]any{"type": "key", "id": "kb", "actions": acts}}})
		return "ok", err
	case "click":
		x, _ := strconv.Atoi(args[1])
		y, _ := strconv.Atoi(args[2])
		_, err := call("input.performActions", map[string]any{"context": c, "actions": []any{map[string]any{"type": "pointer", "id": "mouse", "actions": []any{
			map[string]any{"type": "pointerMove", "x": x, "y": y}, map[string]any{"type": "pointerDown", "button": 0}, map[string]any{"type": "pointerUp", "button": 0}}}}})
		return "ok", err
	}
	return "", fmt.Errorf("unknown command %s", args[0])
}
