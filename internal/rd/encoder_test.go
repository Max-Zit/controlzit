package rd

import (
	"bytes"
	"image/jpeg"
	"testing"

	"github.com/max-zit/rmmzit/internal/proto"
)

func frame(w, h int, c byte) *Frame {
	f := &Frame{W: w, H: h, Pix: bytes.Repeat([]byte{c, c, c, 0xff}, w*h)}
	return f
}

func TestEncoderDiff(t *testing.T) {
	e := &Encoder{Quality: 60}
	f := frame(200, 130, 10) // 4x3 tiles, partial at the edges
	tiles, err := e.Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	// First frame: one run per tile row covering the full width.
	if len(tiles) != 3 || tiles[0].W != 200 || tiles[2].H != 2 {
		t.Fatalf("first frame tiles: %+v", len(tiles))
	}
	if tiles, _ := e.Encode(f); len(tiles) != 0 {
		t.Fatalf("unchanged frame sent %d tiles", len(tiles))
	}
	// Change one pixel in tile (2,1) and one in tile (3,1): one run.
	set := func(x, y int, c byte) {
		o := (y*f.W + x) * 4
		f.Pix[o], f.Pix[o+1], f.Pix[o+2] = c, c, c
	}
	set(130, 70, 200)
	set(199, 127, 200)
	tiles, _ = e.Encode(f)
	if len(tiles) != 1 || tiles[0].X != 128 || tiles[0].Y != 64 || tiles[0].W != 72 || tiles[0].H != 64 {
		t.Fatalf("changed tiles: %+v", tiles)
	}
	img, err := jpeg.Decode(bytes.NewReader(tiles[0].Data))
	if err != nil || img.Bounds().Dx() != 72 {
		t.Fatalf("tile is not a JPEG of the right size: %v", err)
	}
	// A size change sends everything again.
	if tiles, _ := e.Encode(frame(100, 64, 1)); len(tiles) != 1 || tiles[0].W != 100 {
		t.Fatalf("after resize: %+v", tiles)
	}
}

func TestTileMessage(t *testing.T) {
	in := []proto.Tile{{X: 1, Y: 2, W: 3, H: 4, Data: []byte("abc")}, {X: 64, Y: 0, W: 64, H: 64, Data: []byte{9}}}
	out, err := proto.DecodeTiles(proto.EncodeTiles(in))
	if err != nil || len(out) != 2 || out[0].X != 1 || string(out[0].Data) != "abc" || out[1].X != 64 {
		t.Fatalf("roundtrip: %+v %v", out, err)
	}
	if _, err := proto.DecodeTiles([]byte{2, 0, 1, 0}); err == nil {
		t.Fatal("short message accepted")
	}
}
