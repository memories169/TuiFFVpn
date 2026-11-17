// fxvpn-desktop — native Linux GUI for the Firefox VPN console.
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

// Package desktop hosts the Gio GUI that drives the SAME engine as the web
// console: webapp.App (token keeper, rotator, MASQUE dialer, SOCKS5 server)
// runs in-process and the widgets call its internals directly — no admin
// login screen, no HTTP loopback, no container. The state file layout is
// identical to fxvpn-webui's, so a state.json created by the container can be
// opened on the desktop and vice versa.
package desktop

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"fxsocks/webui/bridge"
	"fxsocks/webui/internal/fxa"
	"fxsocks/webui/internal/serverlist"
	"fxsocks/webui/internal/webapp"
)

// Bridge re-export so embedders compiling against this package do not need
// the bridge import directly.
type BridgeApp = bridge.App

// Engine is the desktop facade over webapp.App. The GUI reads snapshots of
// engine state through it; every mutation goes through the same code paths as
// the web console handlers (validAccessToken → fetchProxyPassWithRefresh →
// startProxy), so stability fixes (single-flight refresh, healing chain,
// transient-Fastly handling) apply to the desktop app automatically.
type Engine struct {
	app  *webapp.App
	path string

	mu      sync.Mutex
	servers []serverlist.Country // cache of the last successful fetch
}

// DefaultStatePath returns the per-user state file, following the platform
// convention:
//
//	Windows: %AppData%\fxvpn\state.json (C:\Users\<u>\AppData\Roaming)
//	macOS:   ~/Library/Application Support/fxvpn/state.json
//	Linux:   $XDG_STATE_HOME/fxvpn/state.json (default ~/.local/state/fxvpn)
//
// FXVPN_STATE_FILE overrides it on every platform (handy for pointing the
// desktop app at a container's state.json for a one-off import).
func DefaultStatePath() string {
	if p := os.Getenv("FXVPN_STATE_FILE"); p != "" {
		return p
	}
	switch runtime.GOOS {
	case "windows":
		if dir := os.Getenv("AppData"); dir != "" {
			return filepath.Join(dir, "fxvpn", "state.json")
		}
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "AppData", "Roaming", "fxvpn", "state.json")
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support", "fxvpn", "state.json")
	default:
		dir := os.Getenv("XDG_STATE_HOME")
		if dir == "" {
			home, _ := os.UserHomeDir()
			dir = filepath.Join(home, ".local", "state")
		}
		return filepath.Join(dir, "fxvpn", "state.json")
	}
}

// DefaultProxyAddr is the SOCKS5 listen address for the desktop app.
func DefaultProxyAddr() string {
	if p := os.Getenv("SOCKS_ADDR"); p != "" {
		return p
	}
	return "127.0.0.1:1080"
}

// NewEngine loads (or creates) the state file and starts the engine's
// background loops — token keeper and rotator included, exactly like the web
// console boot.
func NewEngine(statePath, proxyAddr string) (*Engine, error) {
	InstallLogCapture()
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}
	app, err := bridge.Load(statePath, guardianEndpoint(), proxyAddr)
	if err != nil {
		return nil, err
	}
	e := &Engine{app: app, path: statePath}
	log.Printf("fxvpn-desktop: engine ready (state=%s socks=%s)", statePath, proxyAddr)
	return e, nil
}

// RecentLogs returns the captured engine log lines (oldest first) for the
// Logs tab.
func (e *Engine) RecentLogs() string {
	return strings.Join(ring.Snapshot(), "\n")
}

// ClearLogs empties the log ring.
func (e *Engine) ClearLogs() { ring.Clear() }

// guardianEndpoint honors GUARDIAN_ENDPOINT for staging/testing.
func guardianEndpoint() string {
	if v := os.Getenv("GUARDIAN_ENDPOINT"); v != "" {
		return v
	}
	return "https://vpn.mozilla.org"
}

// ---- snapshots for the GUI ----

// AccountRow is one row of the accounts list.
type AccountRow struct {
	Email      string
	QuotaMax   string
	QuotaLeft  string
	Active     bool
	HasToken   bool
	ProbeError string
	// RefreshError is a REAL dead grant (HTTP 400/401/403) — needs re-add.
	RefreshError string
	// RefreshedAt is when the keeper last refreshed the account.
	RefreshedAt time.Time
}

// StatusSnapshot is the top bar's state.
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

// Accounts returns the account list in display order (active first, then
// insertion order — same normalization the web console applies).
func (e *Engine) Accounts() []AccountRow {
	e.app.NormalizeAccounts()
	e.app.SaveState()
	accts := e.app.AccountsList()
	active := e.app.ActiveEmail()
	rows := make([]AccountRow, 0, len(accts))
	for i := range accts {
		ac := &accts[i]
		rows = append(rows, AccountRow{
			Email:        ac.Email,
			QuotaMax:     ac.QuotaMax,
			QuotaLeft:    ac.QuotaLeft,
			Active:       ac.Email == active,
			HasToken:     ac.AccessToken != "",
			ProbeError:   ac.ProbeError,
			RefreshError: ac.RefreshError,
			RefreshedAt:  ac.RefreshedAt,
		})
	}
	return rows
}

// Status reports the proxy/state summary for the top bar.
func (e *Engine) Status() StatusSnapshot {
	s := e.app.StatusSnapshot()
	return StatusSnapshot{
		LoggedIn:  s.LoggedIn,
		Email:     s.Email,
		Running:   s.Running,
		Listen:    s.Listen,
		Server:    s.Server,
		Account:   s.Account,
		Country:   s.Country,
		City:      s.City,
		LastError: s.LastError,
	}
}

// TestProxy dials Cloudflare through the tunnel (same as the web UI test).
func (e *Engine) TestProxy() webapp.TestResult {
	return e.app.RunProxyTest()
}

// ---- mutations ----

// AddAccount performs the FxA login (and optional email-2FA verify) and
// stores the tokens — the identical path the web console uses. When the
// account requires the email code it returns (true, sessionToken, nil); the
// caller re-invokes with that session and the code.
func (e *Engine) AddAccount(ctx context.Context, email, password, session, code string) (needsCode bool, sessionToken string, err error) {
	switch {
	case session != "" && code != "":
		if err := fxa.Verify(ctx, session, strings.TrimSpace(code)); err != nil {
			return true, session, err
		}
		return false, "", e.completeSession(ctx, session, email)
	case session != "":
		// A session still waiting for its code.
		return true, session, nil
	default:
		lr, err := fxa.Login(ctx, email, password)
		if err != nil {
			if errors.Is(err, fxa.ErrUnverified) {
				return true, lr.SessionToken, nil
			}
			return false, "", err
		}
		return false, "", e.completeSession(ctx, lr.SessionToken, email)
	}
}

// completeSession exchanges the FxA session for OAuth tokens and persists
// them (mirrors webapp.completeSession).
func (e *Engine) completeSession(ctx context.Context, sessionToken, email string) error {
	tok, err := fxa.OAuthToken(ctx, sessionToken)
	if err != nil {
		return err
	}
	e.app.UpsertAccount(email, tok.AccessToken, tok.RefreshToken, tok.ExpiresIn)
	e.app.ProbeQuota(tok.AccessToken, email)
	log.Printf("fxvpn-desktop: logged in as %s", email)
	return nil
}

// AddAccountWithTokens stores an OAuth token pair directly (the "paste
// tokens" flow, used when Fastly serves the account an unsolvable CAPTCHA).
func (e *Engine) AddAccountWithTokens(email, access, refresh string, expiresIn int) error {
	if refresh == "" && access == "" {
		return errors.New("cần ít nhất một token")
	}
	e.app.UpsertAccount(email, access, refresh, expiresIn)
	e.app.ProbeQuota(access, email)
	return nil
}

// DeleteAccount removes an account (stops the proxy if it runs on it).
func (e *Engine) DeleteAccount(email string) error {
	return e.app.DeleteAccount(email)
}

// SelectAccount makes the account active WITHOUT touching the server
// selection (the web console's /api/accounts/select behavior).
func (e *Engine) SelectAccount(email string) error {
	return e.app.SelectAccount(email)
}

// RefreshAll kicks a manual token-keeper pass over every account. Returns
// false if a pass is already running.
func (e *Engine) RefreshAll() bool {
	return e.app.StartRefreshAll()
}

// RefreshAllRunning reports whether the manual pass is still running.
func (e *Engine) RefreshAllRunning() bool {
	return e.app.RefreshAllRunning()
}

// Location is a flattened, sorted location for the picker.
type Location struct {
	Country string
	City    string
	Host    string
	Port    int
}

// Locations fetches (or reuses the cached) country/city/server tree and
// flattens it into picker rows, sorted by country then city.
func (e *Engine) Locations(ctx context.Context, force bool) ([]Location, error) {
	e.mu.Lock()
	cached := e.servers
	e.mu.Unlock()
	if !force && len(cached) > 0 {
		return flatten(cached), nil
	}
	countries, err := serverlist.Fetch(ctx)
	if err != nil {
		if len(cached) > 0 {
			return flatten(cached), nil // stale cache beats an error
		}
		return nil, err
	}
	e.mu.Lock()
	e.servers = countries
	e.mu.Unlock()
	return flatten(countries), nil
}

func flatten(countries []serverlist.Country) []Location {
	var out []Location
	for _, c := range countries {
		for _, city := range c.Cities {
			for _, s := range city.Servers {
				if s.Quarantined {
					continue
				}
				out = append(out, Location{Country: c.Name, City: city.Name, Host: s.Hostname, Port: s.Port})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Country != out[j].Country {
			return out[i].Country < out[j].Country
		}
		return out[i].City < out[j].City
	})
	return out
}

// Connect selects the location and starts the MASQUE tunnel + SOCKS5 listener
// (identical to the web console's /api/select, including the token refresh
// retry and proxy-pass healing chain).
func (e *Engine) Connect(ctx context.Context, loc Location) error {
	return e.app.SelectAndStart(ctx, loc.Country, loc.Country, loc.City, loc.City, loc.Host, loc.Port)
}

// GuardianPassPeek is a read-only peek at the live proxy pass diagnostics.
func (e *Engine) GuardianPassPeek() (rawToken string, expires time.Time) {
	p := e.app.LivePass()
	if p == nil {
		return "", time.Time{}
	}
	return p.RawToken, p.ExpiresAt
}

// Disconnect stops the running proxy (tunnel closed, port released). The
// rotator will NOT auto-reconnect: an explicit user disconnect is honored
// until the next manual Connect.
func (e *Engine) Disconnect() {
	e.app.DisconnectProxy()
}

// StatePath exposes where the state file lives (about box).
func (e *Engine) StatePath() string { return e.path }
