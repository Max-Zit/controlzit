// Package rd is the remote desktop of the ControlZit agent: screen
// capture, change detection, encoding and input injection.
package rd

import (
	"bytes"
	"image"
	"image/jpeg"
	"runtime"
	"sync"

	"github.com/max-zit/controlzit/internal/proto"
)

// TileSize is the edge of the change-detection grid.
const TileSize = 64

// Frame is a captured screen: 32-bit BGRA pixels, top-down rows.
type Frame struct {
	W, H int
	Pix  []byte // len = W*H*4
}

// Encoder turns frames into tile updates: it compares each frame with the
// previous one on a grid of TileSize squares and encodes runs of changed
// tiles of a row as one JPEG.
type Encoder struct {
	Quality int
	prev    *Frame
}

// Reset forgets the previous frame, so the next Encode sends everything.
func (e *Encoder) Reset() { e.prev = nil }

// tileChanged compares one tile of two frames.
func tileChanged(a, b *Frame, x0, y0, w, h int) bool {
	stride := a.W * 4
	for y := y0; y < y0+h; y++ {
		o := y*stride + x0*4
		if !bytes.Equal(a.Pix[o:o+w*4], b.Pix[o:o+w*4]) {
			return true
		}
	}
	return false
}

// Encode returns the tiles that changed since the previous frame (all of
// them for the first frame or after a size change). The changed strips are
// encoded in parallel.
func (e *Encoder) Encode(f *Frame) ([]proto.Tile, error) {
	full := e.prev == nil || e.prev.W != f.W || e.prev.H != f.H
	type rect struct{ x, y, w, h int }
	var rects []rect
	for ty := 0; ty < f.H; ty += TileSize {
		th := min(TileSize, f.H-ty)
		run := -1 // start x of a run of changed tiles
		for tx := 0; tx < f.W; tx += TileSize {
			tw := min(TileSize, f.W-tx)
			if full || tileChanged(e.prev, f, tx, ty, tw, th) {
				if run < 0 {
					run = tx
				}
				continue
			}
			if run >= 0 {
				rects = append(rects, rect{run, ty, tx - run, th})
				run = -1
			}
		}
		if run >= 0 {
			rects = append(rects, rect{run, ty, f.W - run, th})
		}
	}
	out := make([]proto.Tile, len(rects))
	errs := make([]error, len(rects))
	var wg sync.WaitGroup
	next := make(chan int)
	for w := 0; w < min(runtime.NumCPU(), len(rects)); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				r := rects[i]
				out[i], errs[i] = e.encodeRect(f, r.x, r.y, r.w, r.h)
			}
		}()
	}
	for i := range rects {
		next <- i
	}
	close(next)
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	// Keep a copy: the capturer reuses its buffer.
	if e.prev == nil || len(e.prev.Pix) != len(f.Pix) {
		e.prev = &Frame{W: f.W, H: f.H, Pix: make([]byte, len(f.Pix))}
	}
	e.prev.W, e.prev.H = f.W, f.H
	copy(e.prev.Pix, f.Pix)
	return out, nil
}

func (e *Encoder) encodeRect(f *Frame, x0, y0, w, h int) (proto.Tile, error) {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	stride := f.W * 4
	for y := 0; y < h; y++ {
		src := f.Pix[(y0+y)*stride+x0*4 : (y0+y)*stride+(x0+w)*4]
		dst := img.Pix[y*img.Stride : y*img.Stride+w*4]
		for i := 0; i < len(src); i += 4 {
			dst[i], dst[i+1], dst[i+2], dst[i+3] = src[i+2], src[i+1], src[i], 0xff
		}
	}
	q := e.Quality
	if q < 10 || q > 95 {
		q = 70
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: q}); err != nil {
		return proto.Tile{}, err
	}
	return proto.Tile{X: uint16(x0), Y: uint16(y0), W: uint16(w), H: uint16(h), Data: buf.Bytes()}, nil // #nosec G115 -- screens are smaller than 65536 px
}
