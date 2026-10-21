// msiart draws the installer images (WiX dialog and banner bitmaps) from
// the ControlZit icon: go run ./tools/msiart brand/controlzit-icon-256.png packaging/windows
package main

import (
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"

	"golang.org/x/image/bmp"
	xdraw "golang.org/x/image/draw"
)

var (
	indigo = color.RGBA{0x4f, 0x46, 0xe5, 0xff}
	navy   = color.RGBA{0x0f, 0x17, 0x2a, 0xff}
	white  = color.RGBA{0xff, 0xff, 0xff, 0xff}
)

func fill(img *image.RGBA, r image.Rectangle, c color.Color) {
	xdraw.Draw(img, r, image.NewUniform(c), image.Point{}, xdraw.Src)
}

func icon(dst *image.RGBA, src image.Image, r image.Rectangle) {
	xdraw.CatmullRom.Scale(dst, r, src, src.Bounds(), xdraw.Over, nil)
}

func save(path string, img image.Image) {
	f, err := os.Create(path) // #nosec G304 -- build tool, path from its own command line
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if err := bmp.Encode(f, img); err != nil {
		panic(err)
	}
}

func main() {
	f, err := os.Open(os.Args[1]) // #nosec G304 -- build tool input
	if err != nil {
		panic(err)
	}
	src, err := png.Decode(f)
	f.Close()
	if err != nil {
		panic(err)
	}
	out := os.Args[2]

	// Dialog (welcome/finish): 493x312, the left 164 px are the brand panel.
	d := image.NewRGBA(image.Rect(0, 0, 493, 312))
	fill(d, d.Bounds(), white)
	fill(d, image.Rect(0, 0, 164, 312), navy)
	fill(d, image.Rect(0, 300, 164, 312), indigo)
	icon(d, src, image.Rect(34, 40, 130, 136))
	save(filepath.Join(out, "dialog.bmp"), d)

	// Banner (top of inner dialogs): 493x58, icon on the right.
	b := image.NewRGBA(image.Rect(0, 0, 493, 58))
	fill(b, b.Bounds(), white)
	fill(b, image.Rect(0, 56, 493, 58), indigo)
	icon(b, src, image.Rect(440, 9, 478, 47))
	save(filepath.Join(out, "banner.bmp"), b)
	fmt.Println("wrote dialog.bmp and banner.bmp")
}
