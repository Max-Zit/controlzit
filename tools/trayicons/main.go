// trayicons draws the tray icon states from the RMMZit icon: the icon
// with a green (connected) or grey (not connected) dot, as .ico files with
// 16, 20, 24, 32 and 48 pixel images.
//
//	go run ./tools/trayicons brand/rmmzit-icon-256.png internal/tray/icons
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"

	xdraw "golang.org/x/image/draw"
)

var sizes = []int{16, 20, 24, 32, 48}

// disc draws a filled circle with a white ring (antialiased by 4×4 samples).
func disc(img *image.RGBA, cx, cy, r float64, fill color.RGBA) {
	b := img.Bounds()
	ring := r + max(1, r*0.28)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			inFill, inRing := 0, 0
			for sy := 0; sy < 4; sy++ {
				for sx := 0; sx < 4; sx++ {
					dx := float64(x) + (float64(sx)+0.5)/4 - cx
					dy := float64(y) + (float64(sy)+0.5)/4 - cy
					d := dx*dx + dy*dy
					if d <= r*r {
						inFill++
					} else if d <= ring*ring {
						inRing++
					}
				}
			}
			if inFill+inRing == 0 {
				continue
			}
			// Mix fill and white by coverage, over what is there.
			c := img.RGBAAt(x, y)
			blend := func(dst *color.RGBA, src color.RGBA, a float64) {
				dst.R = uint8(float64(src.R)*a + float64(dst.R)*(1-a))
				dst.G = uint8(float64(src.G)*a + float64(dst.G)*(1-a))
				dst.B = uint8(float64(src.B)*a + float64(dst.B)*(1-a))
				dst.A = uint8(min(255, float64(dst.A)+(255-float64(dst.A))*a))
			}
			blend(&c, color.RGBA{255, 255, 255, 255}, float64(inRing)/16)
			blend(&c, fill, float64(inFill)/16)
			img.SetRGBA(x, y, c)
		}
	}
}

func icoFile(src image.Image, dot color.RGBA) ([]byte, error) {
	var images [][]byte
	for _, s := range sizes {
		img := image.NewRGBA(image.Rect(0, 0, s, s))
		xdraw.CatmullRom.Scale(img, img.Bounds(), src, src.Bounds(), xdraw.Over, nil)
		if dot.A != 0 {
			r := float64(s) * 0.2
			disc(img, float64(s)-r-1, float64(s)-r-1, r, dot)
		}
		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err != nil {
			return nil, err
		}
		images = append(images, buf.Bytes())
	}
	// ICONDIR, ICONDIRENTRY×n, then the PNG images.
	var out bytes.Buffer
	_ = binary.Write(&out, binary.LittleEndian, [3]uint16{0, 1, uint16(len(images))}) // #nosec G115 -- five images
	offset := 6 + 16*len(images)
	for i, data := range images {
		s := sizes[i]
		w := byte(s) // #nosec G115 -- sizes up to 48
		if s >= 256 {
			w = 0
		}
		out.Write([]byte{w, w, 0, 0})
		_ = binary.Write(&out, binary.LittleEndian, [2]uint16{1, 32})
		_ = binary.Write(&out, binary.LittleEndian, [2]uint32{uint32(len(data)), uint32(offset)}) // #nosec G115 -- small images
		offset += len(data)
	}
	for _, data := range images {
		out.Write(data)
	}
	return out.Bytes(), nil
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: trayicons ICON.png OUTDIR")
		os.Exit(2)
	}
	f, err := os.Open(os.Args[1]) // #nosec G304 G703 -- build tool input
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	src, err := png.Decode(f)
	_ = f.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for name, dot := range map[string]color.RGBA{
		"app.ico":       {},
		"connected.ico": {0x16, 0xa3, 0x4a, 0xff}, // green
		"offline.ico":   {0x94, 0xa3, 0xb8, 0xff}, // grey
	} {
		b, err := icoFile(src, dot)
		if err == nil {
			err = os.WriteFile(filepath.Join(os.Args[2], name), b, 0o644) // #nosec G306 G703 -- build output
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
