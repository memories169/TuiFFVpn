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

// Desktop-facing facade. The native GUI (desktop/) drives the SAME engine as
// the web console; these exported methods expose the exact operations the
// HTTP handlers perform so the GUI and the web UI never drift apart. No new
// logic lives here — every call forwards to the handler internals.

import (
	"context"
	"log"
	"net/http"
	"time"
)

// requestWithContext builds the bare *http.Request the internal pass-fetch
// helpers expect (they only use it for its Context and remote identity).
func requestWithContext(ctx context.Context) *http.Request {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	if err != nil { // only fails on a malformed method/URL — impossible here
		r = (&http.Request{Method: http.MethodGet, URL: nil}).WithContext(ctx)
	}
	return r
}

// NormalizeAccounts merges quota-only stubs and prunes tokenless entries
// (same call handleAccounts makes before listing).
func (a *App) NormalizeAccounts() {
	a.mu.Lock()
	a.Store.ActiveAccount()
	a.Store.Save()
	a.mu.Unlock()
}

// SaveState persists the store (no-op convenience for the facade above).
func (a *App) SaveState() {
	a.mu.Lock()
	_ = a.Store.Save()
	a.mu.Unlock()
}

// AccountsList copies the current account slice.
func (a *App) AccountsList() []accountCopy {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]accountCopy, 0, len(a.Store.Accounts))
	for i := range a.Store.Accounts {
		ac := &a.Store.Accounts[i]
		out = append(out, accountCopy{
			Email:        ac.Email,
			AccessToken:  ac.AccessToken,
			QuotaMax:     ac.QuotaMax,
			QuotaLeft:    ac.QuotaLeft,
			ProbeError:   ac.ProbeError,
			RefreshError: ac.RefreshError,
			RefreshedAt:  ac.RefreshedAt,
		})
	}
	return out
}

// accountCopy is a detached snapshot of a state.Account (no locks held on it).
type accountCopy struct {
	Email        string
	AccessToken  string
	QuotaMax     string
	QuotaLeft    string
	ProbeError   string
	RefreshError string
	RefreshedAt  time.Time
}

// ActiveEmail returns the active account's email ("" when none).
func (a *App) ActiveEmail() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Store.Active
}

// StatusSnapshot is what /api/status returns, as a struct.
type StatusSnapshot struct {
	LoggedIn  bool
	Email     string
	Running   bool
	Listen    string
	Server    string
	Account   string
	Country   string
	City      string
	LastError string
}

// StatusSnapshot builds the top-bar summary.
func (a *App) StatusSnapshot() StatusSnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := a.Store
	loggedIn := st.ActiveAccount() != nil
	email := ""
	if active := st.ActiveAccount(); active != nil {
		email = active.Email
	}
	s := StatusSnapshot{
		LoggedIn:  loggedIn,
		Email:     email,
		Listen:    a.ProxyAddr,
		LastError: a.lastErr,
		Account:   st.Active,
		Country:   st.Selected.CountryName,
		City:      st.Selected.CityName,
	}
	if a.proxySrv != nil {
		s.Running = true
		s.Server = st.Selected.ServerHost
	}
	return s
}

// RunProxyTest exposes testProxy for the GUI's "Test kết nối" button.
func (a *App) RunProxyTest() TestResult { return a.testProxy() }

// UpsertAccount stores a token pair (login / paste-tokens path).
func (a *App) UpsertAccount(email, access, refresh string, expiresIn int) {
	a.mu.Lock()
	a.Store.UpsertAccount(email, access, refresh, expiresIn)
	_ = a.Store.Save()
	a.mu.Unlock()
}

// ProbeQuota best-effort refreshes the account's quota display.
func (a *App) ProbeQuota(accessToken, email string) { a.probeQuota(accessToken, email) }

// DeleteAccount removes an account and stops the proxy if it ran on it
// (the handleAccountDelete path minus JSON).
func (a *App) DeleteAccount(email string) error {
	a.mu.Lock()
	removed := false
	kept := a.Store.Accounts[:0]
	for i := range a.Store.Accounts {
		if a.Store.Accounts[i].Email == email {
			removed = true
			continue
		}
		kept = append(kept, a.Store.Accounts[i])
	}
	if removed {
		a.Store.Accounts = kept
		if a.Store.Active == email {
			a.Store.Active = ""
		}
	}
	err := a.Store.Save()
	a.mu.Unlock()
	if !removed {
		return nil
	}
	a.stopProxyIfActiveAccount(email)
	return err
}

// SelectAccount switches the active account without changing the location
// (the /api/accounts/select path minus JSON).
func (a *App) SelectAccount(email string) error {
	a.mu.Lock()
	ac := a.Store.FindAccount(email)
	if ac == nil {
		a.mu.Unlock()
		return errNoAccount
	}
	// Ensure it has a usable token: refresh if needed, in place.
	refresh := ac.RefreshToken
	a.mu.Unlock()

	if refresh != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		err := a.refreshAccountErr(ctx, email)
		cancel()
		if err != nil && !isTransientRefreshErr(err) {
			return err
		}
	}

	a.mu.Lock()
	a.Store.Active = email
	err := a.Store.Save()
	a.mu.Unlock()
	if err != nil {
		return err
	}

	// Re-fetch the proxy pass under the (possibly new) active account so the
	// tunnel keeps running seamlessly; a failure here only reverts the
	// active marker, the tunnel itself keeps the old pass until it expires.
	a.mu.Lock()
	sel := a.Store.Selected
	a.mu.Unlock()
	if sel.ServerHost != "" && sel.ServerPort != 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		if tok, _ := a.validAccessToken(ctx); tok != "" {
			if pass, perr := a.fetchProxyPassWithRefresh(requestWithContext(ctx), tok); perr == nil {
				a.mu.Lock()
				a.currentPass = pass.RawToken
				a.mu.Unlock()
				a.startProxy(sel.ServerHost, sel.ServerPort, pass.Bearer(), pass.ExpiresAt())
				return nil
			}
		}
	}
	return err
}

// errNoAccount marks an unknown email in SelectAccount/DeleteAccount.
type errString string

func (e errString) Error() string { return string(e) }

const errNoAccount = errString("account không tồn tại")

// StartRefreshAll kicks the manual refresh-all pass; false when one runs.
func (a *App) StartRefreshAll() bool {
	if !a.refreshAll.tryStart() {
		return false
	}
	go a.refreshAllAccounts()
	return true
}

// RefreshAllRunning reports whether a manual pass is in flight.
func (a *App) RefreshAllRunning() bool {
	a.refreshAll.mu.Lock()
	defer a.refreshAll.mu.Unlock()
	return a.refreshAll.running
}

// LivePass exposes the current proxy pass for diagnostics.
func (a *App) LivePass() *proxyPassCopy {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pass == nil {
		return nil
	}
	return &proxyPassCopy{RawToken: a.pass.RawToken, ExpiresAt: a.pass.ExpiresAt()}
}

// proxyPassCopy is a detached snapshot of guardian.ProxyPass.
type proxyPassCopy struct {
	RawToken  string
	ExpiresAt time.Time
}

// SelectAndStart is the /api/select path minus JSON: persist selection, fetch
// a pass (refreshing the token once if rejected), restart the proxy.
func (a *App) SelectAndStart(ctx context.Context, countryCode, countryName, cityCode, cityName, host string, port int) error {
	token, terr := a.validAccessToken(ctx)
	if token == "" {
		if terr == nil {
			terr = errNotLoggedIn
		}
		return terr
	}

	a.mu.Lock()
	a.Store.Select(countryCode, countryName, cityCode, cityName, host, port)
	err := a.Store.Save()
	a.mu.Unlock()
	if err != nil {
		return err
	}

	pass, err := a.fetchProxyPassWithRefresh(requestWithContext(ctx), token)
	if err != nil {
		a.mu.Lock()
		a.lastErr = err.Error()
		a.mu.Unlock()
		return err
	}
	a.mu.Lock()
	a.lastErr = ""
	a.mu.Unlock()

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

	a.mu.Lock()
	a.currentPass = pass.RawToken
	a.mu.Unlock()
	a.startProxy(host, port, pass.Bearer(), pass.ExpiresAt())
	return nil
}

// DisconnectProxy stops the running proxy and clears the last error.
func (a *App) DisconnectProxy() {
	a.mu.Lock()
	if a.proxySrv != nil {
		_ = a.proxySrv.Close()
		a.proxySrv = nil
	}
	a.lastErr = ""
	a.mu.Unlock()
	log.Printf("desktop: proxy stopped by user")
}

// errNotLoggedIn marks a tokenless active account.
const errNotLoggedIn = errString("chưa có account nào — thêm account trước khi kết nối")
