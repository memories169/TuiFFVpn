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

package state

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// DefaultAdminUser and DefaultAdminPass are the bootstrap credentials used the
// first time the console runs.
const (
	DefaultAdminUser = "admin"
	DefaultAdminPass = "admin"
)

// Admin holds the web-console administrator account.
type Admin struct {
	User      string    `json:"user"`
	PassSalt  string    `json:"pass_salt"`
	PassHash  string    `json:"pass_hash"`
	Theme     string    `json:"theme"` // "light" or "dark"
	ChangedAt time.Time `json:"changed_at,omitempty"`
}

// AccountQuota tracks one managed Firefox account and its quota state.
type AccountQuota struct {
	Email     string    `json:"email"`
	QuotaMax  string    `json:"quota_max"`
	QuotaLeft string    `json:"quota_left"`
	LoggedIn  bool      `json:"logged_in"`
	CheckedAt time.Time `json:"checked_at,omitempty"`
}

// EnsureAdmin initializes the admin account with defaults if not set.
func (s *Store) EnsureAdmin() error {
	if s.Admin.User != "" && s.Admin.PassHash != "" {
		return nil
	}
	salt := randomHex(16)
	s.Admin = Admin{
		User:     DefaultAdminUser,
		PassSalt: salt,
		PassHash: hashPass(DefaultAdminPass, salt),
		Theme:    "light",
	}
	return s.Save()
}

// VerifyAdmin reports whether user/pass matches the stored admin credentials.
func (s *Store) VerifyAdmin(user, pass string) bool {
	if s.Admin.User == "" {
		return false
	}
	return s.Admin.User == user && s.Admin.PassHash == hashPass(pass, s.Admin.PassSalt)
}

// SetAdminPassword replaces the admin password.
func (s *Store) SetAdminPassword(pass string) error {
	salt := randomHex(16)
	s.Admin.PassSalt = salt
	s.Admin.PassHash = hashPass(pass, salt)
	s.Admin.ChangedAt = time.Now()
	return s.Save()
}

// SetTheme stores the admin's theme preference.
func (s *Store) SetTheme(theme string) error {
	if theme != "light" && theme != "dark" {
		theme = "light"
	}
	s.Admin.Theme = theme
	return s.Save()
}

func hashPass(pass, salt string) string {
	h := sha256.Sum256([]byte(salt + ":" + pass))
	return hex.EncodeToString(h[:])
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
