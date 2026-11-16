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

// Command fxvpn-desktop is the native Linux desktop app: a Gio window over
// the in-process fxvpn engine (token keeper, rotator, MASQUE dialer, SOCKS5
// proxy) — no container, no admin login, no browser required.
//
// Build (on a Linux machine with the dev headers installed):
//
//	make -f desktop/Makefile            # or: go build -o fxvpn-desktop ./desktop
//
// Runtime deps on the user machine: libxkbcommon, wayland or X11, GL/EGL —
// see docs/desktop-linux.md for per-distro install commands.
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
