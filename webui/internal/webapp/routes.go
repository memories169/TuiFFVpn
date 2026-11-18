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

	// Serve the embedded UI.
	sub, err := fs.Sub(staticFS, "static")
	if err == nil {
		mux.Handle("/", http.FileServer(http.FS(sub)))
	}
	return mux
}
