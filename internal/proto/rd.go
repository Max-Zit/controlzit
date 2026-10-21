package proto

import (
	"encoding/binary"
	"errors"
)

// Remote desktop.
//
// The console asks the agent (signed command rd.start) to start a helper
// in the console session. The helper opens a second WebSocket to the agent
// endpoint (PathStream, the agent's TLS identity plus the one-time session
// token) and streams the screen; the server relays between it and the
// technician's browser. Screen data goes as binary messages, input and
// control as JSON text messages.

// PathStream is the agent endpoint of a remote desktop stream.
const PathStream = "/agent/v1/stream"

// KindRDStart starts a remote desktop helper.
const KindRDStart = "rd.start"

// RDStart is the argument of rd.start.
type RDStart struct {
	Session    string `json:"session"`
	Token      string `json:"token"`
	Technician string `json:"technician"`
}

// Binary messages from the helper start with one of these bytes.
const (
	RDScreen byte = 1 // JSON RDScreenInfo follows
	RDTiles  byte = 2 // tile batch, see EncodeTiles
	RDCursor byte = 3 // int16 x, int16 y (screen pixels), uint8 visible
)

// RDScreenInfo describes the captured screen (all monitors).
type RDScreenInfo struct {
	Width   int    `json:"w"`
	Height  int    `json:"h"`
	Desktop string `json:"desktop"` // Default, Winlogon (sign-in/UAC screen)
	User    string `json:"user"`
}

// RDInput is a text message from the browser.
type RDInput struct {
	T string `json:"t"` // m mouse, k key, ack, q quality, cad, text
	// mouse: position in screen pixels, buttons bit mask (1 left, 2 right,
	// 4 middle), wheel delta (120 per notch)
	X       int `json:"x,omitempty"`
	Y       int `json:"y,omitempty"`
	Buttons int `json:"b,omitempty"`
	Wheel   int `json:"w,omitempty"`
	// key: KeyboardEvent.code, pressed or released
	Code string `json:"code,omitempty"`
	Down bool   `json:"down,omitempty"`
	// quality 10–95 (JPEG)
	Quality int `json:"quality,omitempty"`
	// text to type (paste)
	Text string `json:"text,omitempty"`
}

// Tile is one changed rectangle, JPEG or PNG encoded.
type Tile struct {
	X, Y, W, H uint16
	Data       []byte
}

// EncodeTiles makes an RDTiles message:
//
//	1 byte RDTiles, uint16 count, then per tile uint16 x, y, w, h, uint32 len, data
func EncodeTiles(tiles []Tile) []byte {
	n := 3
	for _, t := range tiles {
		n += 12 + len(t.Data)
	}
	b := make([]byte, 3, n)
	b[0] = RDTiles
	binary.BigEndian.PutUint16(b[1:], uint16(len(tiles))) // #nosec G115 -- a batch has far fewer than 65536 tiles
	for _, t := range tiles {
		var h [12]byte
		binary.BigEndian.PutUint16(h[0:], t.X)
		binary.BigEndian.PutUint16(h[2:], t.Y)
		binary.BigEndian.PutUint16(h[4:], t.W)
		binary.BigEndian.PutUint16(h[6:], t.H)
		binary.BigEndian.PutUint32(h[8:], uint32(len(t.Data))) // #nosec G115 -- tiles are small
		b = append(b, h[:]...)
		b = append(b, t.Data...)
	}
	return b
}

// DecodeTiles parses an RDTiles message (tests and tools).
func DecodeTiles(b []byte) ([]Tile, error) {
	if len(b) < 3 || b[0] != RDTiles {
		return nil, errors.New("not a tile message")
	}
	n := int(binary.BigEndian.Uint16(b[1:]))
	b = b[3:]
	out := make([]Tile, 0, n)
	for i := 0; i < n; i++ {
		if len(b) < 12 {
			return nil, errors.New("short tile header")
		}
		t := Tile{X: binary.BigEndian.Uint16(b[0:]), Y: binary.BigEndian.Uint16(b[2:]), W: binary.BigEndian.Uint16(b[4:]), H: binary.BigEndian.Uint16(b[6:])}
		l := int(binary.BigEndian.Uint32(b[8:]))
		b = b[12:]
		if len(b) < l {
			return nil, errors.New("short tile data")
		}
		t.Data, b = b[:l], b[l:]
		out = append(out, t)
	}
	return out, nil
}
