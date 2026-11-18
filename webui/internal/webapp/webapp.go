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
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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
	// UDPBNDAddr overrides the BND.ADDR in SOCKS5 UDP ASSOCIATE replies
	// (FXVPN_UDP_BND_ADDR) — the docker host's LAN IP so LAN clients can
	// route datagrams to the relay. nil = RFC default (0.0.0.0).
	UDPBNDAddr net.IP
	Store     *state.Store
	Guardian  string
	ProxyAddr string
	sessions  *sessionStore

	proxySrv *proxy.Server
	pass     *guardian.ProxyPass
	// ingested holds a proxy pass pushed by the PC userscript (edge-blocked
	// networks) — Connect falls back to it when the Go fetch 406s.
	ingested *ingestedPass
	lastErr  string
	// currentPass is the live proxy pass JWT of the running proxy. The
	// dialer's bearerProvider reads it after refreshing through Guardian.
	currentPass string
	// refreshMu gates ONE account's refresh-token exchange at a time (FxA
	// refresh tokens are rotating: two concurrent refreshes with the same
	// token race and the loser would overwrite the stored refresh token with
	// a revoked one). It is keyed PER ACCOUNT — refreshes of DIFFERENT
	// accounts run fully in parallel, so the keeper heals 50 accounts in the
	// time a global lock would heal 2 and no account's refresh ever waits
	// behind another account's (the old global-lock behavior that let queued
	// tokens decay while waiting).
	refreshMu sync.Mutex
	// refreshing is the per-account single-flight key: the refresh token
	// currently being exchanged (locked under refreshMu).
	refreshing string
	// edgeDialer is the live MASQUE dialer; its Generation() reports how
	// many distinct edge sessions have been built (stability diagnostics).
	edgeDialer *proxy.MasqueDialer
	// suspectEdge is the server host currently rejecting tunnels
	// server-side (2 consecutive fast fresh-session failures).
	suspectEdge string
	// refreshAll tracks the manual "refresh all tokens" pass (UI button).
	refreshAll refreshAllState
	// suppressNextRotate is set when boot restored the tunnel with the
	// persisted proxy pass (the edge is 406ing fresh fetches): the FIRST
	// rotation pass is skipped so a healthy-by-all-accounts tunnel is not
	// churned (and no pointless edge-storm of Guardian calls is fired).
	suppressNextRotate atomic.Bool
}

// SetLastPassLocked snapshots the fetched pass into the store for the boot
// fallback (persisted pass survives restarts). Caller holds a.mu.
func (a *App) SetLastPassLocked(pass *guardian.ProxyPass, email string) {
	if pass == nil || pass.RawToken == "" {
		return
	}
	a.Store.SetLastPass(pass.RawToken, email, pass.QuotaMax, pass.QuotaLeft)
}

// SetIngestKey stores the desktop ingest key and persists the state file
// (locked like every other Store mutation).
func (a *App) SetIngestKey(key string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.Store.IngestKey == key {
		return nil
	}
	a.Store.IngestKey = key
	return a.Store.Save()
}

// New builds an App.
func New(st *state.Store, guardianEndpoint, proxyAddr string) *App {
	InstallLogCapture()
	app := &App{Store: st, Guardian: guardianEndpoint, ProxyAddr: proxyAddr, sessions: newSessionStore()}
	// UDPBNDAddr: the address clients should send UDP datagrams to (the
	// docker host's LAN IP when behind port mapping). Empty → RFC default.
	if v := os.Getenv("FXVPN_UDP_BND_ADDR"); v != "" {
		if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil {
			app.UDPBNDAddr = ip
		} else {
			log.Printf("webui: FXVPN_UDP_BND_ADDR %q is not a valid IP — ignoring", v)
		}
	}
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
//
// FxA refresh tokens are ONE-TIME-USE (rotating): every successful refresh
// revokes the presented token and issues a new one. Concurrent refreshes
// using the same token therefore race — the loser's write would overwrite
// the stored (still-valid) refresh token with a dead one. All refreshes go
// through a single-flight gate keyed on the refresh token to prevent that.
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
	tok, err := a.refreshAccountToken(ctx, activeEmail(a), refresh)
	if err != nil {
		// Refresh failed (typically transient: Fastly challenge). If the
		// stored access token is STILL VALID, using it avoids handing
		// Guardian an expired token that only earns a misleading 401. When
		// it is expired there is genuinely nothing better to send — let
		// Guardian decide.
		a.mu.Lock()
		ac := a.Store.ActiveAccount()
		stillValid := ac != nil && ac.AccessTokenValid(time.Now())
		if stillValid {
			old = ac.AccessToken
		}
		a.mu.Unlock()
		return old, nil
	}
	return tok, nil
}

// refreshAccountToken single-flights an FxA refresh FOR ONE ACCOUNT.
// FxA refresh tokens are ONE-TIME-USE (rotating): the presented token is
// revoked on success and a new one is returned. The gate is keyed on the
// account's current refresh token, so concurrent refreshes of the SAME
// account collapse into one exchange (a loser re-reads the rotated pair),
// while refreshes of DIFFERENT accounts never queue behind each other —
// with an account list of any size every token is healed promptly and none
// decays while waiting for another account's refresh.
func (a *App) refreshAccountToken(ctx context.Context, email, refreshToken string) (string, error) {
	key := email + "|" + refreshToken

	// Serialize against any in-flight exchange of THIS account.
	a.refreshMu.Lock()
	a.mu.Lock()
	if ac := a.Store.FindAccount(email); ac != nil && ac.RefreshToken != refreshToken {
		// A concurrent exchange already rotated our account for us.
		tok := ac.AccessToken
		a.mu.Unlock()
		a.refreshMu.Unlock()
		return tok, nil
	}
	a.mu.Unlock()
	if a.refreshing == "" {
		// Gate free and our account still holds the presented refresh token
		// — this goroutine performs the exchange.
		a.refreshing = key
		a.refreshMu.Unlock()
	} else {
		// An exchange for a DIFFERENT account is in flight. Ours must not
		// block it (per-account gating), so poll until the gate frees and
		// then claim it — the wait is one exchange long, not a queue.
		a.refreshMu.Unlock()
		for {
			a.refreshMu.Lock()
			if a.refreshing == "" {
				a.refreshing = key
				a.refreshMu.Unlock()
				break
			}
			a.refreshMu.Unlock()
			time.Sleep(20 * time.Millisecond) // an FxA exchange takes seconds
			if err := ctx.Err(); err != nil {
				return "", err
			}
		}
	}

	defer func() {
		// Release the gate no matter which way the exchange went (also on a
		// panic inside the exchange — a stuck flag would deadlock all
		// refreshes forever).
		a.refreshMu.Lock()
		a.refreshing = ""
		a.refreshMu.Unlock()
	}()

	tok, err := fxa.RefreshToken(ctx, refreshToken)
	if err != nil && isTransientRefreshErr(err) {
		// Transient (Fastly CAPTCHA / network): one spaced retry usually
		// clears it — the challenge cookie TTL or the bot score changes.
		// Bound the retry to 10 s so a keeper pass with many accounts does
		// not stall on a hard-down network.
		rctx, rcancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer rcancel()
		tok, err = fxa.RefreshToken(rctx, refreshToken)
	}
	if err != nil {
		a.mu.Lock()
		if ac := a.Store.FindAccount(email); ac != nil && ac.RefreshToken == refreshToken {
			if errors.Is(err, fxa.ErrFastlyChallenge) || isTransientRefreshErr(err) {
				// TRANSIENT (Fastly CAPTCHA, network hiccup, 5xx): the FxA
				// grant is alive and the VPN keeps working. Record it as a
				// warning on ProbeError — NOT as a dead RefreshError — and
				// clear the dead marker in case an earlier run set it.
				ac.RefreshError = ""
				ac.ProbeError = "refresh: " + transientErrLabel(err)
			} else {
				// A real rejection (HTTP 400/401/403 = dead grant: password
				// changed, signed out everywhere). Record WHY on the account;
				// other accounts are untouched and keep rotating.
				ac.RefreshError = err.Error()
			}
			_ = a.Store.Save()
		}
		a.mu.Unlock()
		return "", err
	}
	a.mu.Lock()
	if ac := a.Store.FindAccount(email); ac != nil && ac.RefreshToken == refreshToken {
		ac.AccessToken = tok.AccessToken
		if tok.RefreshToken != "" {
			ac.RefreshToken = tok.RefreshToken
		}
		ac.ObtainedAt = time.Now()
		ac.ExpiresIn = tok.ExpiresIn
		ac.RefreshedAt = time.Now()
		ac.RefreshError = ""
		_ = a.Store.Save()
	}
	fresh := tok.AccessToken
	a.mu.Unlock()
	return fresh, nil
}

// isTransientRefreshErr reports whether a refresh failure is temporary and
// says nothing about the account's health: Fastly CAPTCHA/challenge, network
// errors, timeouts, and server-side 5xx/429. Only a clean HTTP 400/401/403
// from the FxA OAuth endpoint means the grant is really dead.
func isTransientRefreshErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, fxa.ErrFastlyChallenge) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled) {
		return true
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "fastly"):
		return true
	case strings.Contains(msg, "challenge"):
		return true
	case strings.Contains(msg, "captcha"):
		return true
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline"):
		return true
	case strings.Contains(msg, "connection reset"), strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "broken pipe"), strings.Contains(msg, "eof"),
		strings.Contains(msg, "dial tcp"), strings.Contains(msg, "no such host"),
		strings.Contains(msg, "tls handshake"), strings.Contains(msg, "proxyconnect"):
		return true
	case strings.Contains(msg, "http 429"), strings.Contains(msg, "http 500"),
		strings.Contains(msg, "http 502"), strings.Contains(msg, "http 503"),
		strings.Contains(msg, "http 504"):
		return true
	}
	return false
}

// transientErrLabel is the compact UI label for a transient refresh failure.
func transientErrLabel(err error) string {
	if errors.Is(err, fxa.ErrFastlyChallenge) {
		return "Fastly đang chặn IP server bằng CAPTCHA (tạm thời — account vẫn hoạt động bình thường, sẽ tự retry)"
	}
	return err.Error()
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
