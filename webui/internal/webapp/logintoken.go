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
	"log"
	"net/http"
	"strings"
)

// handleLoginToken stores manually-supplied OAuth tokens. This is the fallback
// when automated FxA login is blocked (e.g. Fastly issues a CAPTCHA challenge
// that a non-browser client cannot solve): obtain the tokens from a browser
// session or the reference CLI and paste them here.
func (a *App) handleLoginToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Email        string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, LoginResponse{Error: "bad request"})
		return
	}
	if req.AccessToken == "" {
		writeJSON(w, 400, LoginResponse{Error: "access_token is required"})
		return
	}
	if req.ExpiresIn == 0 {
		req.ExpiresIn = 3600
	}
	a.mu.Lock()
	a.Store.UpsertAccount(strings.TrimSpace(req.Email), req.AccessToken, req.RefreshToken, req.ExpiresIn)
	err := a.Store.Save()
	a.mu.Unlock()
	if err != nil {
		writeJSON(w, 200, LoginResponse{Error: "failed to persist tokens: " + err.Error()})
		return
	}
	a.trackAccount(req.Email, "", "")
	log.Printf("webui: stored manual OAuth tokens for %s", req.Email)
	a.probeQuota(req.AccessToken, req.Email)
	writeJSON(w, 200, map[string]any{"ok": true})
}
