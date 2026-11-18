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

package webapp

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
)

//go:embed static
var staticFS embed.FS

// Routes returns the root handler for the web console: the admin auth, the
// REST API, and the embedded static UI.
func (a *App) Routes() http.Handler {
	mux := http.NewServeMux()

	// Public: admin auth + web console bootstrap status + OAuth callback.
	mux.HandleFunc("/api/admin/login", a.handleAdminLogin)
	mux.HandleFunc("/api/admin/logout", a.handleAdminLogout)
	mux.HandleFunc("/api/admin/status", a.handleAdminStatus)
	// PC-browser ingest (userscript pushes tokens from the host Firefox).
	// Key-authenticated; disabled unless FXVPN_INGEST_KEY is set.
	mux.HandleFunc("/api/ingest", a.handleIngest)

	// Edge control API for external orchestrators (telegram/discord bots
	// driving sing-box — github.com/ppptran/super-bot-go pattern): list
	// servers, switch the selected edge, read status. Key-authenticated
	// with the same FXVPN_INGEST_KEY; single SOCKS5 port serves traffic.
	a.registerEdgeRoutes(mux)

	// Authed: everything else.
	mux.HandleFunc("/api/admin/change-password", a.requireAuth(a.handleChangePassword))
	mux.HandleFunc("/api/accounts", a.requireAuth(a.handleAccounts))
	mux.HandleFunc("/api/accounts/delete", a.requireAuth(a.handleAccountDelete))
	mux.HandleFunc("/api/accounts/refresh-all", a.requireAuth(a.handleAccountsRefreshAll))
	mux.HandleFunc("/api/accounts/select", a.requireAuth(a.handleAccountSelect))
	mux.HandleFunc("/api/login", a.requireAuth(a.handleLogin))

	mux.HandleFunc("/api/login-token", a.requireAuth(a.handleLoginToken))
	mux.HandleFunc("/api/verify", a.requireAuth(a.handleVerify))
	mux.HandleFunc("/api/servers", a.requireAuth(a.handleServers))
	mux.HandleFunc("/api/select", a.requireAuth(a.handleSelect))
	mux.HandleFunc("/api/status", a.requireAuth(a.handleStatus))
	mux.HandleFunc("/api/test", a.requireAuth(a.handleTest))
	// Logs tab: the engine ring buffer (same lines docker logs prints) +
	// a clear button. Auth like every other admin route.
	mux.HandleFunc("/api/logs", a.requireAuth(a.handleLogs))
	mux.HandleFunc("/api/logs/clear", a.requireAuth(a.handleLogsClear))
	// WireGuard mode: connect/stop/status (auth like everything else).
	mux.HandleFunc("/api/wg/connect", a.requireAuth(a.handleWGConnect))
	mux.HandleFunc("/api/wg/stop", a.requireAuth(a.handleWGStop))
	mux.HandleFunc("/api/wg/status", a.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(a.WGStatus())
	}))

	// Serve the embedded UI. no-store is deliberate: embed.FS files carry
	// no modtime, so http.FileServer emits no Last-Modified/ETag — without
	// an explicit directive browsers heuristically cache app.js/index.html
	// and keep running the PREVIOUS build's UI after an image update (the
	// new tab appears but its JS is stale — the Logs tab stuck at its
	// loading placeholder was exactly this).
	mux.Handle("/", noCache(http.FileServer(http.FS(staticSub()))))
	return mux
}

// staticSub returns the embedded static tree (or a safe empty FS on the
// impossible embed failure).
func staticSub() fs.FS {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return emptyFS{}
	}
	return sub
}

type emptyFS struct{}

func (emptyFS) Open(string) (fs.File, error) { return nil, fs.ErrNotExist }

// noCache strips any caching: the console UI must always match the binary.
func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		next.ServeHTTP(w, r)
	})
}
