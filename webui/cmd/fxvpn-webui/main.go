// fxvpn-webui — unofficial Firefox VPN client console.
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

package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"fxsocks/webui/internal/state"
	"fxsocks/webui/internal/webapp"
)

var version = "dev"

func init() { webapp.BuildVersion = version }

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	listen := flag.String("http", envOr("WEBUI_ADDR", ":9090"), "web UI listen address")
	proxyAddr := flag.String("socks", envOr("SOCKS_ADDR", "127.0.0.1:1080"), "SOCKS5 proxy listen address")
	stateFile := flag.String("state", envOr("STATE_FILE", "/data/state.json"), "persistent state file")
	guardian := flag.String("guardian", envOr("GUARDIAN_ENDPOINT", "https://vpn.mozilla.org"), "Guardian API endpoint")
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("fxvpn-webui %s http=%s socks=%s", version, *listen, *proxyAddr)

	st, err := state.Load(*stateFile)
	if err != nil {
		log.Fatalf("load state: %v", err)
	}
	if err := st.EnsureAdmin(); err != nil {
		log.Fatalf("init admin: %v", err)
	}
	app := webapp.New(st, *guardian, *proxyAddr)

	srv := &http.Server{
		Addr:              *listen,
		Handler:           app.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("web UI listening on %s", *listen)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("http: %v", err)
	}
}
