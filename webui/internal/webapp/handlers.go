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
	"encoding/json"
	"errors"

	"fxsocks/webui/internal/fxa"
	"fxsocks/webui/internal/guardian"
	"log"
	"net/http"
	"time"
)

// SelectRequest is the payload for /api/select.
type SelectRequest struct {
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	CityCode    string `json:"city_code"`
	CityName    string `json:"city_name"`
	ServerHost  string `json:"server_host"`
	ServerPort  int    `json:"server_port"`
}

// handleSelect persists the chosen server and (re)starts the proxy.
func (a *App) handleSelect(w http.ResponseWriter, r *http.Request) {
	var req SelectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad request"})
		return
	}
	if req.ServerHost == "" || req.ServerPort == 0 {
		writeJSON(w, 400, map[string]any{"error": "server host/port required"})
		return
	}
	token, terr := a.validAccessToken(r.Context())
	if token == "" {
		if terr == nil {
			terr = errors.New("not logged in")
		}
		writeJSON(w, 200, map[string]any{
			"error":  terr.Error(),
			"action": "re_add_account",
		})
		return
	}

	// Persist the selection BEFORE fetching the proxy pass: the user's choice
	// should survive even when the token/pass needs a refresh on the next try
	// (otherwise a failed fetch makes the UI forget the selection).
	a.mu.Lock()
	a.Store.Select(req.CountryCode, req.CountryName, req.CityCode, req.CityName, req.ServerHost, req.ServerPort)
	err := a.Store.Save()
	a.mu.Unlock()
	if err != nil {
		writeJSON(w, 200, map[string]any{"error": "persist failed: " + err.Error()})
		return
	}

	// Fetch a proxy pass for this account, refreshing the token once if the
	// current one is rejected (HTTP 401/403).
	pass, err := a.fetchProxyPassWithRefresh(r, token)
	if err != nil {
		a.mu.Lock()
		a.lastErr = err.Error()
		a.mu.Unlock()
		writeJSON(w, 200, map[string]any{"error": err.Error()})
		return
	}
	a.mu.Lock()
	a.lastErr = ""
	a.mu.Unlock()

	// Track the account quota from the proxy pass.
	a.mu.Lock()
	active := a.Store.ActiveAccount()
	var email string
	if active != nil {
		email = active.Email
		active.QuotaMax = pass.QuotaMax
		active.QuotaLeft = pass.QuotaLeft
		active.CheckedAt = time.Now()
	}
	a.mu.Unlock()
	if email != "" {
		a.saveState()
	}

	// Restart the proxy against the selected server.
	a.startProxy(req.ServerHost, req.ServerPort, pass.Bearer())

	log.Printf("webui: selected %s (%s/%s) server=%s:%d", req.CountryName, req.CountryCode, req.CityName, req.ServerHost, req.ServerPort)
	writeJSON(w, 200, map[string]any{"ok": true, "server": req.ServerHost, "port": req.ServerPort})
}

// handleStatus reports login, selected server, and proxy state.
func (a *App) handleStatus(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	st := a.Store
	a.mu.Unlock()
	loggedIn := st.ActiveAccount() != nil
	var email string
	if active := st.ActiveAccount(); active != nil {
		email = active.Email
	}
	writeJSON(w, 200, map[string]any{
		"logged_in": loggedIn,
		"email":     email,
		"selected":  st.Selected,
		"proxy":     a.proxyState(),
	})
}

// fetchProxyPassWithRefresh gets a Guardian proxy pass, refreshing the stored
// access token once and retrying when Guardian rejects it with 401/403.
func (a *App) fetchProxyPassWithRefresh(r *http.Request, token string) (*guardian.ProxyPass, error) {
	gc := &guardian.Client{Endpoint: a.Guardian, Token: token}
	pass, err := gc.FetchProxyPass(r.Context())
	if err == nil {
		return pass, nil
	}
	if !errors.Is(err, guardian.ErrTokenInvalid) {
		return nil, err
	}
	// Refresh and retry once.
	a.mu.Lock()
	active := a.Store.ActiveAccount()
	var refresh string
	if active != nil {
		refresh = active.RefreshToken
	}
	a.mu.Unlock()
	if refresh == "" {
		return nil, err
	}
	tok, rerr := fxa.RefreshToken(r.Context(), refresh)
	if rerr != nil {
		return nil, err
	}
	a.mu.Lock()
	if active := a.Store.ActiveAccount(); active != nil {
		active.AccessToken = tok.AccessToken
		if tok.RefreshToken != "" {
			active.RefreshToken = tok.RefreshToken
		}
		active.ObtainedAt = time.Now()
		active.ExpiresIn = tok.ExpiresIn
		a.Store.Save()
	}
	a.mu.Unlock()
	gc2 := &guardian.Client{Endpoint: a.Guardian, Token: tok.AccessToken}
	pass2, err2 := gc2.FetchProxyPass(r.Context())
	if err2 == nil {
		return pass2, nil
	}
	// Free-tier accounts are not entitled until activated. Provision the
	// entitlement via Guardian /activate, then retry the proxy pass once.
	if errors.Is(err2, guardian.ErrTokenInvalid) {
		if _, aerr := gc2.Activate(r.Context()); aerr == nil {
			if pass3, err3 := gc2.FetchProxyPass(r.Context()); err3 == nil {
				return pass3, nil
			}
		}
	}
	return nil, err2
}
