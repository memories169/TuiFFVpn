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

// Package webapp exposes the REST API and static UI for the Firefox VPN web
// console: login (email/password + email 2FA), server/location selection, and
// proxy status.
package webapp

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"fxsocks/webui/internal/fxa"
	"fxsocks/webui/internal/guardian"
	"fxsocks/webui/internal/proxy"
	"fxsocks/webui/internal/serverlist"
	"fxsocks/webui/internal/state"
)

// App wires the store, control-plane auth, and the proxy server.
type App struct {
	mu        sync.Mutex
	Store     *state.Store
	Guardian  string
	ProxyAddr string
	sessions  *sessionStore

	proxySrv *proxy.Server
	pass     *guardian.ProxyPass
	lastErr  string
}

// New builds an App.
func New(st *state.Store, guardianEndpoint, proxyAddr string) *App {
	app := &App{Store: st, Guardian: guardianEndpoint, ProxyAddr: proxyAddr, sessions: newSessionStore()}
	app.startRotator()
	return app
}

func (a *App) accessToken() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ac := a.Store.ActiveAccount(); ac != nil {
		return ac.AccessToken
	}
	return ""
}

// validAccessToken returns a usable access token for the active account,
// refreshing it from its refresh token when expired. Returns an error when no
// account is active.
func (a *App) validAccessToken(ctx context.Context) (string, error) {
	a.mu.Lock()
	ac := a.Store.ActiveAccount()
	if ac == nil {
		a.mu.Unlock()
		return "", errors.New("not logged in")
	}
	if ac.AccessTokenValid(time.Now()) {
		tok := ac.AccessToken
		a.mu.Unlock()
		return tok, nil
	}
	refresh := ac.RefreshToken
	old := ac.AccessToken
	a.mu.Unlock()
	if refresh == "" {
		// No refresh token; return whatever we have (may be rejected by Guardian).
		return old, nil
	}
	tok, err := fxa.RefreshToken(ctx, refresh)
	if err != nil {
		return old, nil // keep old; Guardian decides
	}
	a.mu.Lock()
	if ac := a.Store.ActiveAccount(); ac != nil {
		ac.AccessToken = tok.AccessToken
		if tok.RefreshToken != "" {
			ac.RefreshToken = tok.RefreshToken
		}
		ac.ObtainedAt = time.Now()
		ac.ExpiresIn = tok.ExpiresIn
		_ = a.Store.Save()
	}
	a.mu.Unlock()
	return tok.AccessToken, nil
}

// LoginResponse is the API reply for /api/login.
type LoginResponse struct {
	Needs2FA bool   `json:"needs_2fa"`
	Session  string `json:"session,omitempty"`
	Email    string `json:"email,omitempty"`
	Error    string `json:"error,omitempty"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// handleLogin does the email/password login.
func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, LoginResponse{Error: "bad request"})
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" || req.Password == "" {
		writeJSON(w, 400, LoginResponse{Error: "email and password required"})
		return
	}
	lr, err := fxa.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		if errors.Is(err, fxa.ErrUnverified) {
			writeJSON(w, 200, LoginResponse{Needs2FA: true, Session: lr.SessionToken, Email: req.Email})
			return
		}
		writeJSON(w, 200, LoginResponse{Error: err.Error()})
		return
	}
	a.completeSession(r.Context(), w, lr.SessionToken, req.Email)
}

// handleVerify submits the email 2FA code.
func (a *App) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Session string `json:"session"`
		Code    string `json:"code"`
		Email   string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, LoginResponse{Error: "bad request"})
		return
	}
	if err := fxa.Verify(r.Context(), req.Session, strings.TrimSpace(req.Code)); err != nil {
		writeJSON(w, 200, LoginResponse{Error: err.Error()})
		return
	}
	a.completeSession(r.Context(), w, req.Session, req.Email)
}

// completeSession exchanges the session for OAuth tokens and persists them.
func (a *App) completeSession(ctx context.Context, w http.ResponseWriter, sessionToken, email string) {
	tok, err := fxa.OAuthToken(ctx, sessionToken)
	if err != nil {
		writeJSON(w, 200, LoginResponse{Error: err.Error()})
		return
	}
	a.mu.Lock()
	a.Store.UpsertAccount(email, tok.AccessToken, tok.RefreshToken, tok.ExpiresIn)
	err = a.Store.Save()
	a.mu.Unlock()
	if err != nil {
		writeJSON(w, 200, LoginResponse{Error: "failed to persist tokens: " + err.Error()})
		return
	}
	a.trackAccount(email, "", "")
	a.probeQuota(tok.AccessToken, email)
	log.Printf("webui: logged in as %s", email)
	writeJSON(w, 200, LoginResponse{Email: email})
}

// handleServers returns the country/city/server tree.
func (a *App) handleServers(w http.ResponseWriter, r *http.Request) {
	countries, err := serverlist.Fetch(r.Context())
	if err != nil {
		writeJSON(w, 200, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"countries": countries})
}
