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
	"os"
	"strconv"
	"sync"
	"time"

	"fxsocks/webui/internal/guardian"
	"fxsocks/webui/internal/state"
)

// rotateSettings drives the automatic account rotation: when the active
// account's access token is close to expiring (or its quota is nearly burnt),
// switch to the healthiest other account and keep the proxy on it. Firefox
// VPN access tokens live at most 6h, so the default interval keeps a fresh
// token always in front.
type rotateSettings struct {
	Interval      time.Duration // how often to evaluate rotation
	RefreshBefore time.Duration // refresh when the token expires within this window
	MinQuotaBytes float64       // switch when remaining quota is under this (bytes); 0 = disabled
}

// envDuration reads an env var as a Go duration; returns def when unset or
// unparsable. Lets the operator tune the rotator for any account count
// without recompiling.
func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
		log.Printf("rotator: ignoring unparsable %s=%q (want e.g. 30m, 1h)", key, v)
	}
	return def
}

// envInt reads an env var as a positive integer; def when unset/unparsable.
func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
		log.Printf("rotator: ignoring unparsable %s=%q (want a positive integer)", key, v)
	}
	return def
}

// defaultRotateSettings picks up FXVPN_ROTATE_INTERVAL / FXVPN_REFRESH_BEFORE
// from the environment (docker-compose overrides) with the proven defaults.
var defaultRotateSettings = func() rotateSettings {
	return rotateSettings{
		Interval:      envDuration("FXVPN_ROTATE_INTERVAL", 30*time.Minute),
		RefreshBefore: envDuration("FXVPN_REFRESH_BEFORE", 30*time.Minute),
		MinQuotaBytes: 0, // quota-driven switching is handled in rotateOnce
	}
}()

// tokenKeeperInterval — how often EVERY account's refresh token is
// exercised. FxA refresh tokens decay when their grant/session goes
// unused (the user's complaint: after hours/days only the last-used
// account stayed valid). Refreshing each account daily keeps every
// grant active simultaneously. Override with FXVPN_KEEPER_INTERVAL.
var tokenKeeperInterval = envDuration("FXVPN_KEEPER_INTERVAL", 24*time.Hour)

// keeperWorkers is the keeper's concurrency: how many accounts refresh at
// the same time. The old sequential keeper walked the list one account at a
// time (up to 45 s each), so a large account list took longer than the
// decay window and late accounts died. With workers the whole list heals in
// one pass regardless of size. Override with FXVPN_KEEPER_WORKERS.
var keeperWorkers = envInt("FXVPN_KEEPER_WORKERS", 4)

// startRotator launches the background rotation loop.
func (a *App) startRotator() {
	go func() {
		t := time.NewTicker(defaultRotateSettings.Interval)
		defer t.Stop()
		keeper := time.NewTicker(tokenKeeperInterval)
		defer keeper.Stop()
		// Restore the last-selected server before the first rotation pass so
		// the proxy is reachable as soon as possible after a container
		// restart (the selected server persists in state.json).
		a.restoreSelectedOnBoot()
		a.rotateOnce()
		// First keeper pass shortly after boot: heal any accounts that
		// went stale while the container was down.
		time.Sleep(20 * time.Second)
		a.keeperOnce()
		for {
			select {
			case <-t.C:
				a.rotateOnce()
			case <-keeper.C:
				a.keeperOnce()
			}
		}
	}()
}

// keeperOnce refreshes EVERY inactive account's access token with a bounded
// worker pool (FXVPN_KEEPER_WORKERS concurrent refreshes). The active
// account is skipped — the rotator owns it and it is already fresh. Keeps
// all grants alive so non-active accounts never go "token invalid" from
// inactivity, no matter how many accounts are managed.
func (a *App) keeperOnce() {
	a.mu.Lock()
	accts := append([]state.Account(nil), a.Store.Accounts...)
	active := a.Store.Active
	a.mu.Unlock()

	var wg sync.WaitGroup
	sem := make(chan struct{}, keeperWorkers)
	var mu sync.Mutex // guards refreshed/failed counters
	refreshed, failed := 0, 0

	for _, ac := range accts {
		if ac.Email == active || ac.RefreshToken == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(email, refresh string) {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			_, err := a.refreshAccountToken(ctx, email, refresh)
			cancel()
			mu.Lock()
			if err != nil {
				failed++
				log.Printf("keeper: %s refresh failed: %v (account may need re-add)", email, err)
			} else {
				refreshed++
			}
			mu.Unlock()
		}(ac.Email, ac.RefreshToken)
	}
	wg.Wait()
	if refreshed+failed > 0 {
		log.Printf("keeper: exercised %d/%d inactive accounts (%d workers, failed %d)",
			refreshed, refreshed+failed, keeperWorkers, failed)
	}
}

// restoreSelectedOnBoot restarts the proxy on the persisted server selection
// (if any) after a container restart. Runs in the background: failures are
// logged and the user can re-select from the UI. The full healing chain
// (token refresh, entitlement activation, pass fetch) runs as part of it.
func (a *App) restoreSelectedOnBoot() {
	a.mu.Lock()
	sel := a.Store.Selected
	hasAccount := a.Store.ActiveAccount() != nil
	a.mu.Unlock()

	if !hasAccount {
		log.Printf("boot: no account yet — skip proxy restore (add an account via the userscript)")
		return
	}
	if sel.ServerHost == "" || sel.ServerPort == 0 {
		log.Printf("boot: no server selected yet — skip proxy restore")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := a.restartProxyOnActive(ctx, sel.ServerHost, sel.ServerPort); err != nil {
		log.Printf("boot: auto-connect to %s:%d failed: %v (re-select the server in the UI once tokens are healthy)", sel.ServerHost, sel.ServerPort, err)
		return
	}
	log.Printf("boot: proxy restored on %s:%d (last selected server)", sel.ServerHost, sel.ServerPort)
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

	// Refresh failed (token revoked?) — rotate through the healthy
	// alternatives, best quota first, until one yields a working proxy pass.
	alts := a.pickAlternates(email)
	if len(alts) == 0 {
		log.Printf("rotator: no healthy alternative account to rotate to (%d accounts on file, all dead or tokenless)", a.accountsOnFile())
		return
	}
	for i, alt := range alts {
		log.Printf("rotator: switching active account %s -> %s (fallback %d/%d)", email, alt.Email, i+1, len(alts))
		if a.activateAccount(alt.Email) {
			return
		}
		log.Printf("rotator: fallback %s did not produce a working pass — trying next", alt.Email)
	}
	log.Printf("rotator: every alternative account failed this pass; keeping %s active", email)
}

// accountsOnFile returns how many accounts are stored (for log lines).
func (a *App) accountsOnFile() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.Store.Accounts)
}

// activateAccount makes email the active account and swaps the running
// proxy onto it (pass-swap on the live session pool when possible, full
// restart otherwise). True when the proxy ended up serving with this
// account's pass.
func (a *App) activateAccount(email string) bool {
	a.mu.Lock()
	a.Store.SetActive(email)
	sel := a.Store.Selected
	a.mu.Unlock()
	a.saveState()

	// Pass-swap account rotation: keep the tunnel pool alive. The proxy
	// pass is account-scoped but edge-host-agnostic — the new account's
	// pass works on the SAME edge host, so swap it into the live dialer
	// instead of tearing every session down (which would kill every
	// sing-box flow). If the new pass is rejected on this edge later, the
	// in-band 401 refresh chain handles it.
	if sel.ServerHost != "" && sel.ServerPort != 0 && a.edgeDialer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		pass, err := a.refreshProxyPass(ctx)
		cancel()
		if err == nil {
			a.mu.Lock()
			a.currentPass = pass.RawToken
			a.mu.Unlock()
			a.edgeDialer.UpdatePass(pass.RawToken)
			a.edgeDialer.SetRenewProvider(func() (string, error) {
				pctx, pcancel := context.WithTimeout(context.Background(), 60*time.Second)
				defer pcancel()
				p, perr := a.refreshProxyPass(pctx)
				if perr != nil {
					return "", perr
				}
				a.mu.Lock()
				a.currentPass = p.RawToken
				a.mu.Unlock()
				a.edgeDialer.UpdatePass(p.RawToken)
				return p.RawToken, nil
			}, pass.ExpiresAt())
			log.Printf("rotator: pass swapped to %s on the live session pool (sessions retained)", email)
			return true
		}
		log.Printf("rotator: pass swap for %s failed: %v — falling back to proxy restart", email, err)
		if rerr := a.restartProxyOnActive(context.Background(), sel.ServerHost, sel.ServerPort); rerr == nil {
			log.Printf("rotator: proxy now running on %s", email)
			return true
		} else {
			log.Printf("rotator: proxy restart on %s failed: %v", email, rerr)
		}
		return false
	}

	if sel.ServerHost != "" && sel.ServerPort != 0 {
		if err := a.restartProxyOnActive(context.Background(), sel.ServerHost, sel.ServerPort); err != nil {
			log.Printf("rotator: proxy restart on %s failed: %v", email, err)
			return false
		}
		log.Printf("rotator: proxy now running on %s", email)
	}
	return true
}

// refreshAccount refreshes the named account's access token; true on success.
// Goes through refreshAccountToken (webapp.go) so concurrent rotations never
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

// pickAlternates lists the OTHER healthy accounts, most remaining quota
// first. Every usable account is returned — the rotator walks the whole list
// instead of giving up after a single candidate, so any number of accounts
// can back the proxy. A stale RefreshError is retried on later passes: the
// account list is only written to state (and shown dead in the UI) when a
// refresh actually fails.
func (a *App) pickAlternates(exclude string) []state.Account {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Store.HealthyAccounts(exclude)
}

// restartProxyOnActive fetches a fresh proxy pass for the active account and
// restarts the SOCKS proxy against the given server.
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
	a.startProxy(host, port, pass.Bearer(), pass.ExpiresAt())
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
