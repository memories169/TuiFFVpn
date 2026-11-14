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
	"context"
	"errors"
	"log"
	"time"

	"fxsocks/webui/internal/guardian"
)

// rotateTicker drives the automatic account rotation: when the active
// account's access token is close to expiring (or its quota is nearly burnt),
// switch to the healthiest other account and restart the proxy on it. Firefox
// VPN access tokens live at most 6h, so the default interval keeps a fresh
// token always in front.
type rotateSettings struct {
	Interval      time.Duration // how often to evaluate rotation
	RefreshBefore time.Duration // refresh when the token expires within this window
	MinQuotaBytes float64       // switch when remaining quota is under this (bytes); 0 = disabled
}

var defaultRotateSettings = rotateSettings{
	Interval:      30 * time.Minute,
	RefreshBefore: 30 * time.Minute,
}

// startRotator launches the background rotation loop.
func (a *App) startRotator() {
	go func() {
		t := time.NewTicker(defaultRotateSettings.Interval)
		defer t.Stop()
		// Evaluate once shortly after boot so a stale token gets refreshed
		// before the first proxy use.
		time.Sleep(5 * time.Second)
		a.rotateOnce()
		for range t.C {
			a.rotateOnce()
		}
	}()
}

// rotateOnce evaluates and performs one rotation if needed.
func (a *App) rotateOnce() {
	a.mu.Lock()
	ac := a.Store.ActiveAccount()
	if ac == nil {
		a.mu.Unlock()
		return
	}
	needsRefresh := !ac.AccessTokenValid(time.Now().Add(defaultRotateSettings.RefreshBefore))
	// Rough quota check: Guardian reports strings; parse what we can.
	lowQuota := false
	if ac.QuotaLeft != "" {
		if left, ok := parseQuotaBytes(ac.QuotaLeft); ok && left < 512*1024*1024 { // < 512 MB
			lowQuota = true
		}
	}
	email := ac.Email
	a.mu.Unlock()

	if !needsRefresh && !lowQuota {
		return
	}
	log.Printf("rotator: account %s needs attention (refresh=%v lowQuota=%v)", email, needsRefresh, lowQuota)

	// Try refreshing in place first — cheap and keeps the same account.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	if a.refreshAccount(ctx, email) {
		cancel()
		log.Printf("rotator: refreshed %s in place", email)
		return
	}
	cancel()

	// Refresh failed (token revoked?). Rotate to the healthiest alternative.
	alt := a.pickAlternate(email)
	if alt == nil {
		log.Printf("rotator: no alternative account to rotate to")
		return
	}
	log.Printf("rotator: switching active account %s -> %s", email, alt.Email)
	a.mu.Lock()
	a.Store.SetActive(alt.Email)
	sel := a.Store.Selected
	a.mu.Unlock()
	a.saveState()

	if sel.ServerHost != "" && sel.ServerPort != 0 {
		if err := a.restartProxyOnActive(context.Background(), sel.ServerHost, sel.ServerPort); err != nil {
			log.Printf("rotator: proxy restart on %s failed: %v", alt.Email, err)
		} else {
			log.Printf("rotator: proxy now running on %s", alt.Email)
		}
	}
}

// refreshAccount refreshes the named account's access token; true on success.
// Goes through singleFlightRefresh (webapp.go) so concurrent rotations never
// race the rotating one-time-use FxA refresh token.
func (a *App) refreshAccount(ctx context.Context, email string) bool {
	a.mu.Lock()
	ac := a.Store.FindAccount(email)
	refresh := ""
	if ac != nil {
		refresh = ac.RefreshToken
	}
	a.mu.Unlock()
	if refresh == "" {
		return false
	}
	tok, err := a.refreshAccountToken(ctx, email, refresh)
	if err != nil {
		log.Printf("rotator: refresh %s failed: %v", email, err)
		return false
	}
	return tok != ""
}

// pickAlternate picks the other account with the most remaining quota.
func (a *App) pickAlternate(exclude string) *AccountView {
	a.mu.Lock()
	defer a.mu.Unlock()
	var best *AccountView
	for i := range a.Store.Accounts {
		ac := &a.Store.Accounts[i]
		if ac.Email == exclude || ac.AccessToken == "" || ac.RefreshToken == "" {
			continue
		}
		if best == nil || parseQuotaBytesSafe(ac.QuotaLeft) > parseQuotaBytesSafe(best.QuotaLeft) {
			best = &AccountView{Email: ac.Email, QuotaLeft: ac.QuotaLeft}
		}
	}
	return best
}

// AccountView is a rotation-oriented account snapshot.
type AccountView struct {
	Email     string
	QuotaLeft string
}

// restartProxyOnActive fetches a fresh proxy pass for the active account and
// restarts the SOCKS5 proxy against the given server.
// refreshProxyPass fetches a fresh Guardian proxy pass for the active
// account using the full healing chain (valid access token → refresh on
// invalid → activate on invalid). It does NOT touch the running proxy or
// its listener — safe to call from inside a dial's bearerProvider.
func (a *App) refreshProxyPass(ctx context.Context) (*guardian.ProxyPass, error) {
	token, err := a.validAccessToken(ctx)
	if err != nil || token == "" {
		return nil, err
	}
	gc := &guardian.Client{Endpoint: a.Guardian, Token: token}
	pass, err := gc.FetchProxyPass(ctx)
	if errors.Is(err, guardian.ErrTokenInvalid) {
		// Provision with the current token first (activate is what registers
		// a fresh account for the free tier), then refresh+retry.
		if _, aerr := gc.Activate(ctx); aerr == nil {
			pass, err = gc.FetchProxyPass(ctx)
		}
		if errors.Is(err, guardian.ErrTokenInvalid) && a.refreshAccount(ctx, activeEmail(a)) {
			nt, _ := a.validAccessToken(ctx)
			gc = &guardian.Client{Endpoint: a.Guardian, Token: nt}
			pass, err = gc.FetchProxyPass(ctx)
			if errors.Is(err, guardian.ErrTokenInvalid) {
				if _, aerr := gc.Activate(ctx); aerr == nil {
					pass, err = gc.FetchProxyPass(ctx)
				}
			}
		}
	}
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	if ac := a.Store.ActiveAccount(); ac != nil {
		ac.QuotaMax = pass.QuotaMax
		ac.QuotaLeft = pass.QuotaLeft
		ac.CheckedAt = time.Now()
		_ = a.Store.Save()
	}
	a.mu.Unlock()
	return pass, nil
}

// restartProxyOnActive re-fetches a proxy pass and restarts the SOCKS proxy
// against the given server. Callers outside the dial path only — it replaces
// a.proxySrv (closing the listener).
func (a *App) restartProxyOnActive(ctx context.Context, host string, port int) error {
	pass, err := a.refreshProxyPass(ctx)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.currentPass = pass.RawToken
	a.mu.Unlock()
	a.startProxy(host, port, pass.Bearer())
	return nil
}

func activeEmail(a *App) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ac := a.Store.ActiveAccount(); ac != nil {
		return ac.Email
	}
	return ""
}
