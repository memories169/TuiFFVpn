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

package fxa

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Login submits email + password and returns the session. If the account is
// unverified (needs email 2FA), ErrUnverified is returned with a populated
// LoginResponse so the caller can prompt for the code.
func Login(ctx context.Context, email, password string) (*LoginResponse, error) {
	authPW, err := deriveAuthPW(email, password)
	if err != nil {
		return nil, fmt.Errorf("derive authPW: %w", err)
	}
	body := map[string]any{
		"email":              email,
		"authPW":             hex.EncodeToString(authPW),
		"verificationMethod": "email-2fa",
	}
	data, status, err := postJSON(ctx, AuthServer+"/account/login", body)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		var e struct {
			Errno int    `json:"errno"`
			Msg   string `json:"message"`
		}
		_ = json.Unmarshal(data, &e)
		// errno 107 = deployment rejects verificationMethod; retry plain.
		if status == 400 && e.Errno == 107 {
			delete(body, "verificationMethod")
			data, status, err = postJSON(ctx, AuthServer+"/account/login", body)
			if err != nil {
				return nil, err
			}
			if status != 200 {
				return nil, fmt.Errorf("login failed (HTTP %d): %s", status, truncate(data))
			}
		} else {
			return nil, fmt.Errorf("login failed (HTTP %d errno %d): %s", status, e.Errno, truncate(data))
		}
	}
	var lr LoginResponse
	if err := json.Unmarshal(data, &lr); err != nil {
		return nil, fmt.Errorf("parse login: %w", err)
	}
	if !lr.Verified {
		return &lr, ErrUnverified
	}
	return &lr, nil
}

// Verify submits the email 2FA code for an unverified session.
func Verify(ctx context.Context, sessionToken, code string) error {
	id, key, err := hawkCredentials(sessionToken, "sessionToken")
	if err != nil {
		return err
	}
	data, status, err := postJSONHawk(ctx, AuthServer+"/session/verify_code", map[string]any{"code": code}, id, key)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("verify failed (HTTP %d): %s", status, truncate(data))
	}
	return nil
}

// OAuthToken exchanges a session token for OAuth access + refresh tokens.
func OAuthToken(ctx context.Context, sessionToken string) (*TokenResponse, error) {
	id, key, err := hawkCredentials(sessionToken, "sessionToken")
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"client_id":   ClientID,
		"grant_type":  "fxa-credentials",
		"scope":       OAuthScope,
		"access_type": "offline",
	}
	data, status, err := postJSONHawk(ctx, AuthServer+"/oauth/token", body, id, key)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("oauth token failed (HTTP %d): %s", status, truncate(data))
	}
	var t TokenResponse
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	return &t, nil
}

// RefreshToken refreshes an OAuth access token from a refresh token.
func RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	body := map[string]any{
		"client_id":     ClientID,
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"scope":         OAuthScope,
	}
	data, status, err := postJSON(ctx, AuthServer+"/oauth/token", body)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("refresh failed (HTTP %d): %s", status, truncate(data))
	}
	var t TokenResponse
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("parse refresh: %w", err)
	}
	if t.RefreshToken == "" {
		t.RefreshToken = refreshToken
	}
	return &t, nil
}

func truncate(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
