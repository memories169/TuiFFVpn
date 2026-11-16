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

// Command fxvpn-desktop is the native desktop app for Linux, Windows and
// macOS: a Gio window over the in-process fxvpn engine (token keeper,
// rotator, MASQUE dialer, SOCKS5 proxy) — no container, no admin login, no
// browser required.
//
// Build on the matching platform (Gio needs the native window/GL toolchain):
//
//	Linux:   make                       (libxkbcommon/wayland/x11/gl dev headers)
//	Windows: go build -tags nometal -o fxvpn-desktop.exe ./webui/desktop/cmd/fxvpn-desktop
//	         (uses the pure-Go Direct3D/GDI path; no cgo toolchain needed)
//	macOS:   go build -o fxvpn-desktop ./webui/desktop/cmd/fxvpn-desktop
//	         (needs Xcode command line tools for the Metal cgo backend)
//
// See docs/install-windows.md and docs/install-macos.md.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"gioui.org/app"
	"gioui.org/unit"

	"fxsocks/webui/desktop"
)

var version = "dev"

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	stateFile := flag.String("state", desktop.DefaultStatePath(), "state file (same layout as fxvpn-webui)")
	proxyAddr := flag.String("socks", desktop.DefaultProxyAddr(), "SOCKS5 listen address")
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVer {
		fmt.Println("fxvpn-desktop", version)
		return
	}

	log.Printf("fxvpn-desktop %s state=%s socks=%s", version, *stateFile, *proxyAddr)

	engine, err := desktop.NewEngine(*stateFile, *proxyAddr)
	if err != nil {
		log.Fatalf("engine: %v", err)
	}

	ui := desktop.NewUI(engine)
	go func() {
		w := new(app.Window)
		w.Option(app.Title("fxvpn — Firefox VPN (Catppuccin Macchiato)"))
		w.Option(app.Size(unit.Dp(980), unit.Dp(680)))
		ui.SetWindow(w)
		if err := ui.Run(); err != nil {
			log.Fatalf("ui: %v", err)
		}
		os.Exit(0)
	}()

	app.Main()
}
