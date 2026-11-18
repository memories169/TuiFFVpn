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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

const sessionCookie = "fxvpn_session"

// sessionStore holds active admin sessions in memory (single-process app).
type sessionStore struct {
	mu       sync.Mutex
	tokens   map[string]time.Time
	validFor time.Duration
}

func newSessionStore() *sessionStore {
	return &sessionStore{tokens: map[string]time.Time{}, validFor: 24 * time.Hour}
}

func (ss *sessionStore) create() (string, time.Time) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	exp := time.Now().Add(ss.validFor)
	ss.mu.Lock()
	ss.tokens[tok] = exp
	ss.mu.Unlock()
	return tok, exp
}

func (ss *sessionStore) valid(tok string) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	exp, ok := ss.tokens[tok]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(ss.tokens, tok)
		return false
	}
	return true
}

func (ss *sessionStore) revoke(tok string) {
	ss.mu.Lock()
	delete(ss.tokens, tok)
	ss.mu.Unlock()
}

// requireAuth is middleware that rejects unauthenticated API calls.
func (a *App) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || !a.sessions.valid(c.Value) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "not authenticated", "admin_login": true})
			return
		}
		next(w, r)
	}
}

type adminLoginReq struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

func (a *App) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	var req adminLoginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad request"})
		return
	}
	a.mu.Lock()
	ok := a.Store.VerifyAdmin(req.User, req.Password)
	a.mu.Unlock()
	if !ok {
		writeJSON(w, 401, map[string]any{"error": "invalid username or password"})
		return
	}
	tok, _ := a.sessions.create()
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.sessions.revoke(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(1, 0)})
	writeJSON(w, 200, map[string]any{"ok": true})
}

// BuildVersion lets main inject the binary's version string; it surfaces in
// /api/admin/status so a stale docker image is immediately identifiable from
// the console (no shell access needed).
var BuildVersion = "dev"

func (a *App) handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(sessionCookie)
	loggedIn := err == nil && a.sessions.valid(c.Value)
	a.mu.Lock()
	theme := a.Store.Admin.Theme
	user := a.Store.Admin.User
	a.mu.Unlock()
	writeJSON(w, 200, map[string]any{"authenticated": loggedIn, "user": user, "theme": theme, "version": BuildVersion})
}

type changePassReq struct {
	Current string `json:"current"`
	Next    string `json:"next"`
}

func (a *App) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req changePassReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad request"})
		return
	}
	a.mu.Lock()
	ok := a.Store.VerifyAdmin(a.Store.Admin.User, req.Current)
	a.mu.Unlock()
	if !ok {
		writeJSON(w, 401, map[string]any{"error": "current password is incorrect"})
		return
	}
	if len(req.Next) < 4 {
		writeJSON(w, 400, map[string]any{"error": "new password must be at least 4 characters"})
		return
	}
	a.mu.Lock()
	err := a.Store.SetAdminPassword(req.Next)
	a.mu.Unlock()
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
