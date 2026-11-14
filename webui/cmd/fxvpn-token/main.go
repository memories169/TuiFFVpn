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

// Command fxvpn-token captures a Firefox Accounts sessionToken from a real
// browser session and trades it for Firefox VPN OAuth tokens, the same way the
// FoxyVPN Android client does inside its WebView.
//
//	go build -o fxvpn-token ./webui/cmd/fxvpn-token
//	./fxvpn-token                      # opens a browser, wait for sign-in
//	./fxvpn-token -headless            # no window (needs credentials elsewhere)
//	./fxvpn-token -attach http://127.0.0.1:9222
//	./fxvpn-token -session <64hex>     # skip the browser, just exchange
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"fxsocks/webui/internal/browsercapture"
	"fxsocks/webui/internal/fxa"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	var (
		sessionToken = flag.String("session", "", "existing sessionToken (64 hex chars); skips the browser")
		browserPath  = flag.String("browser", envOr("FXVPN_BROWSER", ""), "Chrome/Chromium executable")
		debugPort    = flag.Int("port", 0, "DevTools port (0 = pick a free one)")
		headless     = flag.Bool("headless", false, "run the browser without a window")
		attach       = flag.String("attach", "", "attach to an existing DevTools endpoint, e.g. http://127.0.0.1:9222")
		userDataDir  = flag.String("profile", "", "browser profile directory (keep cookies between runs)")
		loginURL     = flag.String("url", browsercapture.DefaultLoginURL, "Firefox Accounts URL to open")
		userAgent    = flag.String("ua", "", "Firefox user agent override")
		timeout      = flag.Duration("timeout", 10*time.Minute, "how long to wait for sign-in")
		keepBrowser  = flag.Bool("keep-browser", false, "leave the browser open after capture")
		jsonOut      = flag.Bool("json", false, "print one JSON object (default: pretty)")
		exchange     = flag.Bool("exchange", true, "exchange the sessionToken for OAuth tokens")
		destroy      = flag.Bool("destroy-session", false, "revoke the sessionToken after the exchange")
		stateFile    = flag.String("state", "", "write the OAuth tokens into this fxvpn-webui state file")
	)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	token := strings.ToLower(strings.TrimSpace(*sessionToken))
	var captured *browsercapture.Result
	if token == "" {
		captured = captureToken(ctx, *browserPath, *attach, *userDataDir, *loginURL, *userAgent, *debugPort, *headless, *keepBrowser, *timeout)
		if captured != nil {
			token = captured.SessionToken
		}
	}
	if token == "" {
		os.Exit(1)
	}
	if !browsercapture.IsSessionToken(token) {
		fmt.Fprintln(os.Stderr, "error: not a 64-character hex sessionToken")
		os.Exit(1)
	}

	out := map[string]any{"session_token": token}

	exchangeOpts := fxa.TokenOptions{}
	if captured != nil {
		exchangeOpts.Cookies = browsercapture.HTTPCookies(captured.Cookies)
		exchangeOpts.UserAgent = captured.UserAgent
	}

	if *exchange {
		tok, err := fxa.ExchangeSessionTokenWith(ctx, token, exchangeOpts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "exchange failed: %v\n", err)
			fmt.Fprintf(os.Stderr, "captured sessionToken: %s\n", token)
			fmt.Fprintf(os.Stderr, "retry the exchange with: fxvpn-token -session %s -url %s\n", token, browsercapture.DefaultLoginURL)
			os.Exit(1)
		}
		out["access_token"] = tok.AccessToken
		out["refresh_token"] = tok.RefreshToken
		out["expires_in"] = tok.ExpiresIn
		out["scope"] = tok.Scope
		if *destroy {
			if err := fxa.DestroySessionWith(context.Background(), token, exchangeOpts); err != nil {
				fmt.Fprintf(os.Stderr, "warning: session destroy failed: %v\n", err)
			} else {
				out["session_destroyed"] = true
			}
		}
	}

	if *stateFile != "" {
		if err := writeState(*stateFile, out); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not write state: %v\n", err)
		}
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return
	}
	fmt.Printf("sessionToken : %s\n", token)
	if v, ok := out["access_token"].(string); ok {
		fmt.Printf("accessToken  : %s\n", v)
	}
	if v, ok := out["refresh_token"].(string); ok && v != "" {
		fmt.Printf("refreshToken : %s\n", v)
	}
	if v, ok := out["expires_in"].(int); ok {
		fmt.Printf("expiresIn    : %ds\n", v)
	}
}

func captureToken(ctx context.Context, browserPath, attach, profile, loginURL, ua string, port int, headless, keep bool, timeout time.Duration) *browsercapture.Result {
	logf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "[capture] "+format+"\n", args...)
	}
	res, browser, err := browsercapture.Capture(ctx, browsercapture.Options{
		BrowserPath: browserPath,
		AttachURL:   attach,
		UserDataDir: profile,
		LoginURL:    loginURL,
		UserAgent:   ua,
		DebugPort:   port,
		Headless:    headless,
		KeepBrowser: keep,
		Timeout:     timeout,
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
		Logf: logf,
	})
	if browser != nil {
		defer browser.Close()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return nil
	}
	if res.Email != "" {
		fmt.Fprintf(os.Stderr, "[capture] signed in as %s\n", res.Email)
	}
	return res
}

func writeState(path string, out map[string]any) error {
	// Minimal, schema-compatible patch: keep any other keys in the file.
	raw := map[string]any{}
	if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
		_ = json.Unmarshal(data, &raw)
	}
	tokens := map[string]any{}
	if cur, ok := raw["tokens"].(map[string]any); ok {
		tokens = cur
	}
	for _, k := range []string{"access_token", "refresh_token", "expires_in", "email"} {
		if v, ok := out[k]; ok {
			tokens[k] = v
		}
	}
	tokens["obtained_at"] = time.Now().UTC().Format(time.RFC3339)
	raw["tokens"] = tokens
	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
