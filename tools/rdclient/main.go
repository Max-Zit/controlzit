// rdclient is a test client for the remote desktop: it connects to the
// console like the browser viewer, assembles the screen into a PNG and can
// send clicks, keys and text (lab tests of agents without a browser).
//
//	go run ./tools/rdclient -console https://rmm:8443 -device 4 -cookie VALUE -out screen.png -wait 8s [-click 100,200] [-keys MetaLeft] [-text hello]
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"image"
	"image/draw"
	"image/jpeg"
	"image/png"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/max-zit/controlzit/internal/proto"
)

func main() {
	console := flag.String("console", "", "console URL")
	device := flag.Int("device", 0, "device ID")
	cookie := flag.String("cookie", "", "value of the __Host-czsession cookie")
	out := flag.String("out", "screen.png", "PNG to write")
	wait := flag.Duration("wait", 8*time.Second, "how long to receive before writing")
	click := flag.String("click", "", "x,y to click after the first frame")
	keys := flag.String("keys", "", "comma-separated KeyboardEvent codes to press after the first frame (a+b = chord)")
	text := flag.String("text", "", "text to type after the first frame")
	cad := flag.Bool("cad", false, "send Ctrl+Alt+Del after the first frame")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *wait+40*time.Second)
	defer cancel()
	u := strings.Replace(*console, "https://", "wss://", 1) + "/devices/" + strconv.Itoa(*device) + "/rd/ws"
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // #nosec G402 -- lab test tool
	ws, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPClient: hc, HTTPHeader: http.Header{
		"Origin": {*console}, "Cookie": {"__Host-czsession=" + *cookie}}})
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		os.Exit(1)
	}
	defer ws.CloseNow()
	ws.SetReadLimit(64 << 20)
	send := func(v any) {
		b, _ := json.Marshal(v)
		_ = ws.Write(ctx, websocket.MessageText, b)
	}
	var canvas *image.RGBA
	var info proto.RDScreenInfo
	deadline := time.Now().Add(*wait)
	acted := false
	frames, bytesIn := 0, 0
	start := time.Now()
	for time.Now().Before(deadline) {
		rctx, rcancel := context.WithDeadline(ctx, deadline)
		typ, data, err := ws.Read(rctx)
		rcancel()
		if err != nil {
			break
		}
		if typ == websocket.MessageText {
			fmt.Println("text:", string(data))
			continue
		}
		bytesIn += len(data)
		switch data[0] {
		case proto.RDScreen:
			_ = json.Unmarshal(data[1:], &info)
			canvas = image.NewRGBA(image.Rect(0, 0, info.Width, info.Height))
			fmt.Printf("screen %dx%d desktop %s\n", info.Width, info.Height, info.Desktop)
		case proto.RDTiles:
			tiles, err := proto.DecodeTiles(data)
			if err != nil || canvas == nil {
				continue
			}
			for _, t := range tiles {
				img, err := jpeg.Decode(bytes.NewReader(t.Data))
				if err == nil {
					draw.Draw(canvas, image.Rect(int(t.X), int(t.Y), int(t.X)+int(t.W), int(t.Y)+int(t.H)), img, image.Point{}, draw.Src)
				}
			}
			frames++
			send(proto.RDInput{T: "ack"})
			if !acted {
				acted = true
				if *click != "" {
					p := strings.Split(*click, ",")
					x, _ := strconv.Atoi(p[0])
					y, _ := strconv.Atoi(p[1])
					send(proto.RDInput{T: "m", X: x, Y: y})
					send(proto.RDInput{T: "m", X: x, Y: y, Buttons: 1})
					send(proto.RDInput{T: "m", X: x, Y: y})
				}
				if *cad {
					send(proto.RDInput{T: "cad"})
				}
				for _, k := range strings.Split(*keys, ",") {
					if k == "" {
						continue
					}
					chord := strings.Split(k, "+")
					for _, c := range chord {
						send(proto.RDInput{T: "k", Code: c, Down: true})
					}
					for i := len(chord) - 1; i >= 0; i-- {
						send(proto.RDInput{T: "k", Code: chord[i]})
					}
				}
				if *text != "" {
					send(proto.RDInput{T: "text", Text: *text})
				}
			}
		}
	}
	el := time.Since(start).Seconds()
	fmt.Printf("%d tile batches, %.1f KB/s, %.1f batches/s\n", frames, float64(bytesIn)/1024/el, float64(frames)/el)
	if canvas == nil {
		fmt.Fprintln(os.Stderr, "no screen received")
		os.Exit(1)
	}
	f, err := os.Create(*out) // #nosec G304 -- test tool output
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	_ = png.Encode(f, canvas)
	_ = ws.Close(websocket.StatusNormalClosure, "")
}
