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

package desktop

// Browser sign-in (the FoxyVPN flow, no userscript): the app launches a
// Chrome/Chromium window pointed at the FxA fx_desktop_v3 login page with a
// WebChannel hook installed via CDP. The user types their credentials IN THE
// BROWSER (2FA included, real Firefox UI); on success FxA sends the
// sessionToken over the WebChannel, the hook forwards it to the app, and the
// app exchanges it for OAuth tokens replaying the browser's cookies + UA —
// which also clears the Fastly edge, so no CAPTCHA dance is needed.
//
// On a standalone PC there is no userscript: this in-app browser IS the
// capture mechanism, exactly like FoxyVPN's Android WebView bridge.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"fxsocks/webui/internal/browsercapture"
	"fxsocks/webui/internal/fxa"
)

// browserLogin opens the in-app browser window and waits for the user to
// finish the sign-in. It blocks until a session token is captured (then
// exchanged) or the context is canceled / the user closes the window.
// Progress lines are streamed to onLog; the result is an account ready to
// use (OAuth tokens persisted by the caller via AddAccountResult).
func (e *Engine) BrowserLogin(ctx context.Context, onLog func(string)) (*LoginOutcome, error) {
	logf := func(format string, args ...any) {
		if onLog != nil {
			onLog(sprintf(format, args...))
		}
	}
	logf("Đang mở trình duyệt đăng nhập Firefox…")

	res, browser, err := browsercapture.Capture(ctx, browsercapture.Options{
		// Visible window — the user signs in themselves.
		Headless:    false,
		KeepBrowser: true,
		Timeout:     10 * time.Minute,
		Logf:        logf,
		Validate: func(ctx context.Context, tok string, cookies []browsercapture.Cookie, ua string) (string, string, bool, error) {
			st, err := fxa.SessionStatusWith(ctx, tok, fxa.TokenOptions{
				Cookies:   browsercapture.HTTPCookies(cookies),
				UserAgent: ua,
			}, fxa.AuthServer+"/recovery_email/status")
			if err != nil {
				return "", "", false, err
			}
			return st.Email, st.UID, st.Verified, nil
		},
	})
	if browser != nil {
		defer browser.Close()
	}
	if err != nil {
		if err == browsercapture.ErrTimeout {
			return nil, errBrowserTimeout
		}
		return nil, err
	}

	// OAuth code path (oauth_webchannel_v1): the page hands us an
	// authorization code; exchange it for the tokens directly. This is the
	// flow that works in Chromium — no session token juggling.
	if res.OAuthCode != "" {
		logf("Đã nhận mã ủy quyền OAuth (" + res.Source + ") — đang đổi sang token…")
		tok, err := fxa.ExchangeAuthorizationCode(ctx, res.OAuthCode)
		if err != nil {
			logf("Đổi mã thất bại: " + err.Error())
			return nil, err
		}
		email := res.Email
		logf("Đăng nhập thành công" + emailSuffix(email))
		return &LoginOutcome{
			Email:        email,
			AccessToken:  tok.AccessToken,
			RefreshToken: tok.RefreshToken,
			ExpiresIn:    tok.ExpiresIn,
		}, nil
	}

	logf("Đã bắt được session token (" + res.Source + ") — đang đổi sang OAuth…")
	opts := fxa.TokenOptions{
		Cookies:   browsercapture.HTTPCookies(res.Cookies),
		UserAgent: res.UserAgent,
	}
	tok, err := fxa.ExchangeSessionTokenWith(ctx, res.SessionToken, opts)
	if err != nil {
		// The exchange itself retries the Fastly challenge internally; if
		// it STILL fails, the edge is having a bad run. One patient retry
		// round after a pause, then surface the error.
		logf("Đổi token lần đầu thất bại (%v) — thử lại sau 10s…", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(10 * time.Second):
		}
		tok, err = fxa.ExchangeSessionTokenWith(ctx, res.SessionToken, opts)
		if err != nil {
			logf("Đổi token thất bại: " + err.Error())
			return nil, err
		}
	}
	email := res.Email
	logf("Đăng nhập thành công" + emailSuffix(email))
	return &LoginOutcome{
		Email:        email,
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		ExpiresIn:    tok.ExpiresIn,
	}, nil
}

// LoginOutcome is what a browser sign-in produced.
type LoginOutcome struct {
	Email        string
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
}

// CompleteBrowserLogin persists the tokens from a finished BrowserLogin and
// probes quota — call this (not AddAccount) after BrowserLogin succeeds.
func (e *Engine) CompleteBrowserLogin(out *LoginOutcome) error {
	if out == nil || (out.AccessToken == "" && out.RefreshToken == "") {
		return errNoTokens
	}
	e.app.UpsertAccount(out.Email, out.AccessToken, out.RefreshToken, out.ExpiresIn)
	e.app.ProbeQuota(out.AccessToken, out.Email)
	return nil
}

func emailSuffix(email string) string {
	if strings.TrimSpace(email) == "" {
		return ""
	}
	return " (" + email + ")"
}

// Error values for the UI to map to friendly Vietnamese messages.
var (
	errBrowserTimeout = desktopErr("hết thời gian chờ đăng nhập (10 phút) — thử lại")
	errNoTokens       = desktopErr("không có token nào để lưu")
)

// desktopErr is a plain string error for the desktop package.
type desktopErr string

func (e desktopErr) Error() string { return string(e) }

// sprintf forwards to fmt.Sprintf.
func sprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }
