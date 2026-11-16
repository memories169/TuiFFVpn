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

// Catppuccin Macchiato palette — https://catppuccin.com/palette
// Medium-dark: lavender accents on a #24273a surface.

import (
	"image/color"

	"gioui.org/unit"
	"gioui.org/widget/material"
)

// Macchiato named colors.
var (
	Rosewater = rgb(0xf4dbd6)
	Flamingo  = rgb(0xf0c6c6)
	Pink      = rgb(0xf5bde6)
	Mauve     = rgb(0xc6a0f6)
	Red       = rgb(0xed8796)
	Maroon    = rgb(0xee99a0)
	Peach     = rgb(0xf5a97f)
	Yellow    = rgb(0xeed49f)
	Green     = rgb(0xa6da95)
	Teal      = rgb(0x8bd5ca)
	Sky       = rgb(0x91d7e3)
	Sapphire  = rgb(0x7dc4e8)
	Blue      = rgb(0x8aadf4)
	Lavender  = rgb(0xb7bdf8)
	Text      = rgb(0xcaddd6f3)
	Subtext1  = rgb(0xb8c0e0)
	Subtext0  = rgb(0xa5adcb)
	Overlay2  = rgb(0x939ab7)
	Overlay1  = rgb(0x8087a2)
	Overlay0  = rgb(0x6e738d)
	Surface2  = rgb(0x5b6078)
	Surface1  = rgb(0x494d64)
	Surface0  = rgb(0x363a4f)
	Base      = rgb(0x24273a)
	Mantle    = rgb(0x1e2030)
	Crust     = rgb(0x181926)
)

func rgb(c uint32) color.NRGBA {
	return color.NRGBA{
		R: uint8(c >> 16),
		G: uint8(c >> 8),
		B: uint8(c),
		A: 255,
	}
}

// withAlpha returns the color at a given opacity (0-255).
func withAlpha(c color.NRGBA, a uint8) color.NRGBA {
	c.A = a
	return c
}

// macchiatoTheme layers the palette over material's defaults: same font
// collection and widget sizing, colors swapped so every widget — buttons,
// inputs, lists, scrollbars, switches — speaks Macchiato.
func macchiatoTheme(th *material.Theme) *material.Theme {
	th.Palette = material.Palette{
		Fg:         Text,
		Bg:         Base,
		ContrastBg: Lavender, // filled buttons / active accents
		ContrastFg: Crust,    // text on those accents
	}
	th.TextSize = unit.Sp(14.5)
	return th
}
