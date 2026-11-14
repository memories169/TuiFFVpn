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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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

// Store is a persistent state file.
type Store struct {
	Path     string    `json:"-"`
	Admin    Admin     `json:"admin"`
	Accounts []Account `json:"accounts,omitempty"`
	Active   string    `json:"active_account,omitempty"` // email of the account the proxy uses
	Tokens   Tokens    `json:"tokens"`                   // legacy single-account field, kept for migration
	Selected Selected  `json:"selected"`
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
