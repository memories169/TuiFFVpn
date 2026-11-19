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

// Package state persists the user's OAuth tokens and selected VPN server so
// the proxy can restart without re-logging-in.
package state

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Tokens holds OAuth credentials.
type Tokens struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresIn    int       `json:"expires_in"`
	Email        string    `json:"email,omitempty"`
	ObtainedAt   time.Time `json:"obtained_at"`
}

// Account is one managed Firefox account with its own OAuth tokens, so the
// proxy can be switched between accounts without re-login. Quota lives here
// too, right next to the credentials it belongs to.
//
// There is NO cap on how many accounts a Store may hold — add as many as you
// like; every per-account subsystem (rotation, keeper, quota probe) is
// account-count aware and scales with the list.
type Account struct {
	Email        string    `json:"email"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresIn    int       `json:"expires_in"`
	ObtainedAt   time.Time `json:"obtained_at"`
	QuotaMax     string    `json:"quota_max,omitempty"`
	QuotaLeft    string    `json:"quota_left,omitempty"`
	CheckedAt    time.Time `json:"checked_at,omitempty"`
	AddedAt      time.Time `json:"added_at"`
	// ProbeError is the last quota-probe failure reason (empty = OK). It lets
	// the UI show WHY quota is missing instead of a bare "?".
	ProbeError string `json:"probe_error,omitempty"`
	// RefreshedAt is when the token keeper last successfully refreshed this
	// account (zero = never). Lets the keeper stagger accounts instead of
	// hammering all of them in one burst.
	RefreshedAt time.Time `json:"refreshed_at,omitempty"`
	// RefreshError is the last token-refresh failure reason (empty = OK). A
	// non-empty value means the FxA grant is dead (password change, sign-out
	// everywhere) and the account needs re-adding — but it never blocks the
	// other accounts from rotating or refreshing.
	RefreshError string `json:"refresh_error,omitempty"`
}

// AccessTokenValid reports whether the account's access token is usable.
func (ac *Account) AccessTokenValid(now time.Time) bool {
	if ac.AccessToken == "" {
		return false
	}
	if ac.ObtainedAt.IsZero() || ac.ExpiresIn <= 0 {
		return false
	}
	return now.Before(ac.ObtainedAt.Add(time.Duration(ac.ExpiresIn) * time.Second))
}

// Selected holds the chosen server/location.
type Selected struct {
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	CityCode    string `json:"city_code,omitempty"`
	CityName    string `json:"city_name"`
	ServerHost  string `json:"server_host"`
	ServerPort  int    `json:"server_port"`
}

// Store is a persistent state file. Accounts has no length cap — the state
// file is rewritten atomically on every change, so hundreds of accounts cost
// nothing but JSON size.
type Store struct {
	Path     string    `json:"-"`
	Admin    Admin     `json:"admin"`
	Accounts []Account `json:"accounts,omitempty"`
	Active   string    `json:"active_account,omitempty"` // email of the account the proxy uses
	Tokens   Tokens    `json:"tokens"`                   // legacy single-account field, kept for migration
	Selected Selected  `json:"selected"`
	// IngestKey pins the localhost ingest key so it SURVIVES restarts. A
	// regenerated key would break every paired userscript after each app
	// update (the docker image never has this problem: FXVPN_INGEST_KEY
	// comes from .env), so the desktop app persists its key on first boot
	// and reuses it forever. See desktop.ingestKey.
	IngestKey string `json:"ingest_key,omitempty"`
	// LastPass is the most recent proxy pass JWT together with the account
	// it belongs to and its parsed expiry. The boot restore (and Connect)
	// falls back to it when the Fastly edge 406s every Go-side pass fetch
	// right after a restart — a pass that worked minutes ago usually still
	// works. Without it, a restart on an edge-hostile network could not
	// open the tunnel at all until the user re-pushed from the userscript.
	LastPass PersistedPass `json:"last_pass,omitempty"`
	// WGLastServer records the WireGuard server last used (like Selected for
	// MASQUE) so the boot restore can reconnect the WG tunnel.
	WGLastServer *WGServerInfo `json:"wg_last_server,omitempty"`
	// WGDevice is the WireGuard device identity registered with Guardian
	// (base64 keypair + assigned tunnel IPs + the account email it belongs
	// to). Registered once per account via POST /api/v1/vpn/device; with it,
	// the WireGuard tunnel (full UDP) becomes available alongside MASQUE.
	WGDevice *WGDeviceState `json:"wg_device,omitempty"`
	// GuardianJWT is the short-lived JWT Guardian itself mints (via the
	// browser PKCE login, /api/v2/vpn/login/verify) — the ONLY credential
	// Guardian's JWT-verified endpoints accept (/vpn/device, /vpn/servers;
	// the FxA access token gets errno 120 "invalid algorithm" there).
	GuardianJWT   string    `json:"guardian_jwt,omitempty"`
	GuardianEmail string    `json:"guardian_email,omitempty"`
	GuardianJWTAt time.Time `json:"guardian_jwt_at,omitempty"`
}

// WGServerInfo is a flattened WireGuard server endpoint.
type WGServerInfo struct {
	Hostname    string `json:"hostname"`
	IPv4AddrIn  string `json:"ipv4_addr_in"`
	IPv4Gateway string `json:"ipv4_gateway,omitempty"` // in-tunnel DNS resolver
	PublicKey   string `json:"public_key"`
	Port        int    `json:"port"`
	Weight      int    `json:"weight,omitempty"` // load-balancing weight (Guardian)
}

// WGDeviceState persists the registered WireGuard device.
type WGDeviceState struct {
	Name      string `json:"name"`
	UniqueID  string `json:"unique_id"`
	PrivKey   string `json:"private_key"`
	PubKey    string `json:"public_key"`
	IPv4      string `json:"ipv4_address"`
	IPv6      string `json:"ipv6_address"`
	Email     string `json:"email"` // the account the device belongs to
	CreatedAt string `json:"created_at"`
}

// PersistedPass is the state-file snapshot of the live proxy pass.
type PersistedPass struct {
	RawToken  string    `json:"raw_token"`
	Email     string    `json:"email,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	SavedAt   time.Time `json:"saved_at"`
	QuotaMax  string    `json:"quota_max,omitempty"`
	QuotaLeft string    `json:"quota_left,omitempty"`
}

// Usable reports whether the persisted pass can still be tried: present,
// parsed, and not yet expired (the caller decides how close to expiry is
// close enough).
func (p PersistedPass) Usable() bool {
	if p.RawToken == "" || p.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().Before(p.ExpiresAt)
}

// SetLastPass parses a raw proxy-pass JWT and stores it on the store. It
// returns false when the token is not a parseable JWT (nothing is written).
func (s *Store) SetLastPass(rawToken, email, quotaMax, quotaLeft string) bool {
	claims, err := guardianParseJWT(rawToken)
	if err != nil {
		return false
	}
	if s.LastPass.RawToken != rawToken {
		s.LastPass = PersistedPass{
			RawToken:  rawToken,
			Email:     email,
			ExpiresAt: time.Unix(claims.Exp, 0),
			SavedAt:   time.Now(),
			QuotaMax:  quotaMax,
			QuotaLeft: quotaLeft,
		}
	}
	return true
}

// FindAccount returns the account with the given email, or nil.
func (s *Store) FindAccount(email string) *Account {
	for i := range s.Accounts {
		if s.Accounts[i].Email == email {
			return &s.Accounts[i]
		}
	}
	return nil
}

// ActiveAccount returns the account the proxy currently uses, falling back to
// the first stored account. Migrates the legacy single-token field on the way
// and prunes tokenless stubs left by older quota probes.
func (s *Store) ActiveAccount() *Account {
	// Migration: old single-account state.
	if len(s.Accounts) == 0 && s.Tokens.AccessToken != "" {
		s.Accounts = append(s.Accounts, Account{
			Email:        s.Tokens.Email,
			AccessToken:  s.Tokens.AccessToken,
			RefreshToken: s.Tokens.RefreshToken,
			ExpiresIn:    s.Tokens.ExpiresIn,
			ObtainedAt:   s.Tokens.ObtainedAt,
			AddedAt:      s.Tokens.ObtainedAt,
		})
		if s.Active == "" {
			s.Active = s.Tokens.Email
		}
	}
	// Migration: merge legacy AccountQuota-style entries (quota but no token)
	// into their token-bearing twin, then drop them.
	for i := 0; i < len(s.Accounts); i++ {
		if s.Accounts[i].AccessToken != "" {
			continue
		}
		twin := s.FindAccountWithToken(s.Accounts[i].Email)
		if twin == nil {
			continue
		}
		if twin.QuotaLeft == "" || twin.QuotaMax == "" {
			twin.QuotaMax = s.Accounts[i].QuotaMax
			twin.QuotaLeft = s.Accounts[i].QuotaLeft
			twin.CheckedAt = s.Accounts[i].CheckedAt
		}
		s.Accounts = append(s.Accounts[:i], s.Accounts[i+1:]...)
		i--
	}
	// Drop tokenless entries entirely when no token twin exists — they can
	// never run the proxy and only confuse the "active" selection.
	keep := s.Accounts[:0]
	for _, ac := range s.Accounts {
		if ac.AccessToken != "" {
			keep = append(keep, ac)
		}
	}
	if len(keep) != len(s.Accounts) {
		s.Accounts = keep
	}
	if s.Active != "" {
		if ac := s.FindAccount(s.Active); ac != nil {
			return ac
		}
	}
	if len(s.Accounts) > 0 {
		s.Active = s.Accounts[0].Email
		return &s.Accounts[0]
	}
	return nil
}

// FindAccountWithToken returns the token-bearing account with the given email.
func (s *Store) FindAccountWithToken(email string) *Account {
	for i := range s.Accounts {
		if s.Accounts[i].Email == email && s.Accounts[i].AccessToken != "" {
			return &s.Accounts[i]
		}
	}
	return nil
}

// UpsertAccount inserts or replaces the account's credentials by email and
// marks it active.
func (s *Store) UpsertAccount(email, access, refresh string, expiresIn int) *Account {
	email = strings.TrimSpace(email)
	now := time.Now()
	if ac := s.FindAccount(email); ac != nil {
		ac.AccessToken = access
		if refresh != "" {
			ac.RefreshToken = refresh
		}
		ac.ExpiresIn = expiresIn
		ac.ObtainedAt = now
		s.Active = ac.Email
		return ac
	}
	ac := Account{
		Email:        email,
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresIn:    expiresIn,
		ObtainedAt:   now,
		AddedAt:      now,
	}
	s.Accounts = append(s.Accounts, ac)
	s.Active = email
	return &s.Accounts[len(s.Accounts)-1]
}

// RemoveAccount deletes the account; if it was active, active moves to the
// first remaining one.
func (s *Store) RemoveAccount(email string) bool {
	keep := s.Accounts[:0]
	removed := false
	for _, ac := range s.Accounts {
		if ac.Email == email {
			removed = true
			continue
		}
		keep = append(keep, ac)
	}
	s.Accounts = keep
	if removed && s.Active == email {
		s.Active = ""
		if len(s.Accounts) > 0 {
			s.Active = s.Accounts[0].Email
		}
	}
	return removed
}

// SetActive marks the account the proxy should use.
func (s *Store) SetActive(email string) bool {
	if s.FindAccount(email) == nil {
		return false
	}
	s.Active = email
	return true
}

// Load reads the state file, returning an empty store if missing.
func Load(path string) (*Store, error) {
	s := &Store{Path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, err
	}
	return s, nil
}

// Save writes the state file atomically with owner-only permissions.
func (s *Store) Save() error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

// AccessTokenValid reports whether the stored access token is still usable.
func (s *Store) AccessTokenValid(now time.Time) bool {
	if s.Tokens.AccessToken == "" {
		return false
	}
	if s.Tokens.ObtainedAt.IsZero() || s.Tokens.ExpiresIn <= 0 {
		return false
	}
	return now.Before(s.Tokens.ObtainedAt.Add(time.Duration(s.Tokens.ExpiresIn) * time.Second))
}

// Select stores the chosen server.
func (s *Store) Select(countryCode, countryName, cityCode, cityName, host string, port int) {
	s.Selected = Selected{
		CountryCode: countryCode,
		CountryName: countryName,
		CityCode:    cityCode,
		CityName:    cityName,
		ServerHost:  host,
		ServerPort:  port,
	}
}

// HealthyAccounts returns every OTHER usable account (token + refresh token
// present, no dead grant), best quota first. There is no cap on the returned
// count — the rotator works through as many fallbacks as the user has added.
func (s *Store) HealthyAccounts(exclude string) []Account {
	candidates := make([]Account, 0, len(s.Accounts))
	for i := range s.Accounts {
		ac := &s.Accounts[i]
		if ac.Email == exclude || ac.AccessToken == "" || ac.RefreshToken == "" || ac.RefreshError != "" {
			continue
		}
		candidates = append(candidates, *ac)
	}
	// Most remaining quota first; ties break on the earliest added so the
	// order stays stable across evaluations.
	for i := 1; i < len(candidates); i++ {
		for j := i; j > 0; j-- {
			ji, jj := candidates[j], candidates[j-1]
			if parseQuota(ji.QuotaLeft) > parseQuota(jj.QuotaLeft) ||
				(parseQuota(ji.QuotaLeft) == parseQuota(jj.QuotaLeft) && ji.AddedAt.Before(jj.AddedAt)) {
				candidates[j], candidates[j-1] = candidates[j-1], candidates[j]
			} else {
				break
			}
		}
	}
	return candidates
}

// parseQuota is a state-local byte parser (no import cycle with webapp).
func parseQuota(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if n, err := strconv.ParseFloat(s, 64); err == nil {
		return n
	}
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
		i++
	}
	if i == 0 || i == len(s) {
		return 0
	}
	n, err := strconv.ParseFloat(s[:i], 64)
	if err != nil {
		return 0
	}
	var mult float64
	switch strings.ToUpper(strings.TrimSuffix(strings.TrimSpace(s[i:]), "S")) {
	case "B":
		mult = 1
	case "KB", "KIB":
		mult = 1024
	case "MB", "MIB":
		mult = 1024 * 1024
	case "GB", "GIB":
		mult = 1024 * 1024 * 1024
	case "TB", "TIB":
		mult = 1024 * 1024 * 1024 * 1024
	default:
		return 0
	}
	return n * mult
}

// jwtClaims is the subset of proxy-pass JWT claims the state file needs.
// A state-local copy (guardian's parseJWT is unexported and state must not
// import guardian).
type jwtClaims struct {
	Exp int64
}

// guardianParseJWT extracts the exp claim from a proxy-pass JWT.
func guardianParseJWT(token string) (jwtClaims, error) {
	var c jwtClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c, errors.New("invalid JWT")
	}
	dec, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, err
	}
	var claims map[string]any
	if err := json.Unmarshal(dec, &claims); err != nil {
		return c, err
	}
	switch v := claims["exp"].(type) {
	case float64:
		c.Exp = int64(v)
	case string:
		var n int64
		fmt.Sscan(v, &n)
		c.Exp = n
	}
	if c.Exp == 0 {
		return c, errors.New("proxy pass JWT has no exp claim")
	}
	return c, nil
}
