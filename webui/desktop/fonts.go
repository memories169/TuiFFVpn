// fxvpn-desktop — native Linux GUI for the Firefox VPN console.
// Copyright (C) 2026
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// SPDX-License-Identifier: GPL-3.0-only

package desktop

// Embedded UI fonts. The Go fonts (gioui.org/font/gofont) cover only
// Latin-1 plus a handful of precomposed letters — Vietnamese diacritics
// like ả ạ ế ữ ơ ư are MISSING from their cmap, so every label with those
// glyphs rendered blank/tofu. DejaVu Sans has full Vietnamese coverage
// (same for Latin Extended Additional), ships in every Linux distro and
// is freely redistributable: Bitstream Vera license (permission to use,
// copy, merge, publish, distribute and sell — keep the notice), DejaVu
// changes are public domain. Notice reproduced in NOTICE-FONTS.md.

import (
	"embed"
	"sync"

	"gioui.org/font"
	"gioui.org/font/opentype"
	"gioui.org/text"
)

//go:embed assets/DejaVuSans.ttf assets/DejaVuSans-Bold.ttf
var fontFS embed.FS

var (
	fontOnce  sync.Once
	fontFaces []font.FontFace
)

// uiFonts parses the embedded DejaVu faces once and returns them as a Gio
// font collection (regular first — it becomes the default face).
func uiFonts() []font.FontFace {
	fontOnce.Do(func() {
		for _, name := range []string{
			"assets/DejaVuSans.ttf",
			"assets/DejaVuSans-Bold.ttf",
		} {
			raw, err := fontFS.ReadFile(name)
			if err != nil {
				continue
			}
			faces, err := opentype.ParseCollection(raw)
			if err != nil {
				continue
			}
			// ParseCollection on a bare TTF yields one face; mark it bold
			// when it is the bold file so material.Bold weight matches.
			for i := range faces {
				if name == "assets/DejaVuSans-Bold.ttf" {
					faces[i].Font.Weight = font.Bold
				}
				faces[i].Font.Typeface = "DejaVu Sans"
			}
			fontFaces = append(fontFaces, faces...)
		}
	})
	return fontFaces
}

// newShaper returns a text shaper seeded with the embedded fonts. System
// fonts stay enabled so any glyph DejaVu lacks can still resolve (emoji,
// CJK) on machines that have them.
func newShaper() *text.Shaper {
	return text.NewShaper(text.WithCollection(uiFonts()))
}
