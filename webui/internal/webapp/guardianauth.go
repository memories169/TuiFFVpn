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

// Guardian browser login (PKCE) — the exact flow the official Mozilla VPN
// client uses (src/tasks/authenticate/*.cpp). The FxA access token we hold
// is NOT accepted by Guardian's JWT-verified endpoints (POST /vpn/device
// rejects it with errno 120 "invalid algorithm" — it only accepts the
// short-lived JWT Guardian itself mints). That JWT comes from:
//
//  1. GET  /api/v2/vpn/login/<platform>?code_challenge&code_challenge_method=S256[&port]
//     → 302 Location: the FxA authorization page (client_id e6eb0d1e856335fc,
//     redirect_uri https://vpn.mozilla.org/oauth/success). Guardian stores
//     the PKCE challenge under the flow state.
//  2. The user signs in; FxA redirects to Guardian's /oauth/success which
//     forwards the browser to http://localhost:<port>/…?code=… (the `port`
//     the flow starter passed). Our web console registers a capture route,
//     or the user pastes the URL manually.
//  3. POST /api/v2/vpn/login/verify {code, code_verifier} → {user, token}:
//     the Guardian JWT used for /api/v1/vpn/* (device registration, WG
//     servers).

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"fxsocks/webui/internal/edgehttp"
	"fxsocks/webui/internal/fxa"
)

// ErrWGLoginNeeded is returned when WG mode requires the Guardian JWT but
// none is stored (or it was revoked) — the UI must show the browser login.
var ErrWGLoginNeeded = errors.New("wg: needs Guardian browser login")

// wgLoginFlowTTL bounds how long a started PKCE flow stays valid
// (Guardian's server-side flow state expires well inside this).
const wgLoginFlowTTL = 15 * time.Minute

// wgLoginFlow is one in-flight PKCE login.
type wgLoginFlow struct {
	verifier string
	client   *http.Client // cookie jar + browser-fingerprint transport
	started  time.Time
}

// wgPKCEVerifier mirrors the official client's 128-char verifier alphabet
// (authenticationlistener.cpp generatePkceCodes).
func wgPKCEVerifier() (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	b := make([]byte, 128)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, 128)
	for i, v := range b {
		out[i] = alphabet[int(v)%len(alphabet)]
	}
	return string(out), nil
}

// wgPKCEChallenge is S256(verifier) per RFC 7636 (base64url, no padding).
func wgPKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// StartWGLogin begins the PKCE flow: calls Guardian's login/<platform>,
// captures the FxA authorization URL from the 302, and returns it for the
// user's browser. hostPort is the console's host:port (from the request
// Host header) passed as `port` so Guardian redirects the browser back to
// the console with the code in the query string.
func (a *App) StartWGLogin(hostPort string) (string, error) {
	verifier, err := wgPKCEVerifier()
	if err != nil {
		return "", fmt.Errorf("pkce verifier: %w", err)
	}
	challenge := wgPKCEChallenge(verifier)

	jar, _ := cookiejar.New(nil)
	// Never follow redirects: the 302 Location IS the FxA authorization URL
	// (following it would hit accounts.firefox.com from the server).
	client := &http.Client{
		Jar:       jar,
		Timeout:   60 * time.Second,
		Transport: edgehttp.Transport(),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	u := fmt.Sprintf("%s/api/v2/vpn/login/linux?code_challenge=%s&code_challenge_method=S256&user_agent=%s",
		strings.TrimRight(a.Guardian, "/"), url.QueryEscape(challenge), url.QueryEscape(fxa.UA))
	if hostPort != "" {
		u += "&port=" + url.QueryEscape(hostPort)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", fxa.UA)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("guardian login: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	// Guardian answers in one of two shapes:
	//   302 Location: <full FxA authorization URL>   (plain HTTP clients)
	//   200 {"fxa_oauth":{"url":...,"params":{...}}} (structured clients —
	//   the uTLS/browser-fingerprint transport gets this). The params must
	//   be appended to the URL; `state` ("pkce<port>-<hex>") carries the
	//   PKCE flow Guardian created for this challenge.
	loc := resp.Header.Get("Location")
	authURL := loc
	if authURL == "" {
		var doc struct {
			FxaOauth struct {
				URL    string            `json:"url"`
				Params map[string]string `json:"params"`
			} `json:"fxa_oauth"`
		}
		if err := json.Unmarshal(body, &doc); err != nil || doc.FxaOauth.URL == "" {
			return "", fmt.Errorf("guardian login: unexpected HTTP %d response: %s",
				resp.StatusCode, truncateStr(body, 160))
		}
		q := url.Values{}
		for k, v := range doc.FxaOauth.Params {
			q.Set(k, v)
		}
		authURL = doc.FxaOauth.URL + "?" + q.Encode()
	}

	a.mu.Lock()
	a.wgLogin = &wgLoginFlow{verifier: verifier, client: client, started: time.Now()}
	a.mu.Unlock()
	preview := authURL
	if len(preview) > 60 {
		preview = preview[:60] + "…"
	}
	log.Printf("wg: Guardian login flow started — authorization URL: %s", preview)
	return authURL, nil
}

// CompleteWGLogin finishes the PKCE flow with the authorization code the
// browser brought back (accepts the raw code or the full callback URL),
// exchanges it for the Guardian JWT and persists it.
func (a *App) CompleteWGLogin(ctx context.Context, codeOrURL string) error {
	code := wgExtractCode(codeOrURL)
	if code == "" {
		return errors.New("no authorization code found in input")
	}

	a.mu.Lock()
	flow := a.wgLogin
	a.mu.Unlock()
	if flow == nil {
		return fmt.Errorf("%w: no login flow started", ErrWGLoginNeeded)
	}
	if time.Since(flow.started) > wgLoginFlowTTL {
		a.mu.Lock()
		a.wgLogin = nil
		a.mu.Unlock()
		return errors.New("login flow expired — start it again")
	}

	payload, _ := json.Marshal(map[string]string{
		"code":          code,
		"code_verifier": flow.verifier,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(a.Guardian, "/")+"/api/v2/vpn/login/verify", strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", fxa.UA)
	resp, err := flow.client.Do(req)
	if err != nil {
		return fmt.Errorf("guardian verify: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("guardian verify HTTP %d: %s", resp.StatusCode, truncateStr(body, 200))
	}

	var lr struct {
		Token string `json:"token"`
		User  struct {
			Email string `json:"email"`
			UID   string `json:"uid"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &lr); err != nil {
		return fmt.Errorf("parse verify response: %w", err)
	}
	if lr.Token == "" {
		return fmt.Errorf("guardian verify response missing token: %s", truncateStr(body, 200))
	}

	a.mu.Lock()
	a.wgLogin = nil
	a.Store.GuardianJWT = lr.Token
	a.Store.GuardianEmail = lr.User.Email
	a.Store.GuardianJWTAt = time.Now()
	err = a.Store.Save()
	a.mu.Unlock()
	if err != nil {
		return fmt.Errorf("save guardian token: %w", err)
	}
	log.Printf("wg: Guardian login complete — JWT stored for %s", lr.User.Email)
	return nil
}

// wgExtractCode pulls the authorization code out of a raw code or any URL
// carrying ?code= (works for whatever shape Guardian's localhost redirect
// and the manual paste land in). Returns "" when a URL-shaped input carries
// no code — callers surface that as a user error.
func wgExtractCode(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") || strings.Contains(s, "?") {
		if u, err := url.Parse(s); err == nil {
			return u.Query().Get("code") // "" when absent
		}
	}
	// Last resort: a code= parameter anywhere in the string.
	if i := strings.Index(s, "code="); i >= 0 {
		rest := s[i+5:]
		if j := strings.IndexAny(rest, "& "); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	return s // not URL-shaped — treat the whole input as a raw code
}

// handleWGCodeCapture is the catch-all GET handler that fires when
// Guardian's post-login redirect lands back on the console (any path with
// ?code= while a flow is pending). It completes the login and answers with
// a tiny page that closes itself.
func (a *App) handleWGCodeCapture(w http.ResponseWriter, r *http.Request) {
	err := a.CompleteWGLogin(r.Context(), r.URL.String())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err != nil {
		log.Printf("wg: code capture failed: %v", err)
		fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>fxvpn</title>
<p style="font-family:sans-serif;font-size:16px;padding:2em">❌ Đăng nhập Guardian thất bại: %s<br>Hãy quay lại tab console và dán URL thủ công.</p>`, err)
		return
	}
	fmt.Fprint(w, `<!doctype html><meta charset="utf-8"><title>fxvpn</title>
<p style="font-family:sans-serif;font-size:16px;padding:2em">✅ Đã đăng nhập Guardian. Tab này có thể đóng — quay lại console, tunnel WireGuard đang kết nối…</p>
<script>setTimeout(()=>window.close(),1200)</script>`)
}

// guardianCodeGate wraps the static file server: a GET whose query carries
// an authorization code while a Guardian PKCE flow is pending is the
// browser redirect landing back on the console — intercept it and complete
// the login instead of serving the SPA.
func (a *App) guardianCodeGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Query().Get("code") != "" {
			a.mu.Lock()
			pending := a.wgLogin != nil
			a.mu.Unlock()
			if pending {
				a.handleWGCodeCapture(w, r)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// handleWGLoginStart begins the PKCE flow and returns the FxA authorization
// URL (the UI opens it in a new tab/popup).
func (a *App) handleWGLoginStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	// The port the browser redirect must land on: Guardian composes
	// http://localhost:<port>/ after the FxA round-trip (the official
	// client passes the port of its local loopback listener). Extract the
	// numeric port from the console's Host header (default 9090).
	port := "9090"
	if i := strings.LastIndex(r.Host, ":"); i >= 0 && isAllDigits(r.Host[i+1:]) {
		port = r.Host[i+1:]
	}
	authURL, err := a.StartWGLogin(port)
	if err != nil {
		log.Printf("wg: login start failed: %v", err)
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "auth_url": authURL})
}

// handleWGLoginPaste completes the flow from a manually pasted callback URL
// (needed when the browser redirect cannot reach the console, e.g. the
// container port is only reachable as localhost:9090 from the host browser
// while Guardian saw a different host).
func (a *App) handleWGLoginPaste(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": "bad request"})
		return
	}
	if err := a.CompleteWGLogin(r.Context(), req.URL); err != nil {
		log.Printf("wg: login paste failed: %v", err)
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	// JWT just stored — kick the WG connect in the background so the user
	// sees the tunnel come up without another click.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		if err := a.ConnectWG(ctx); err != nil {
			log.Printf("wg: auto-connect after login failed: %v", err)
		}
	}()
	writeJSON(w, 200, map[string]any{"ok": true})
}

// guardianJWT returns the stored Guardian JWT or ErrWGLoginNeeded.
func (a *App) guardianJWT() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.Store.GuardianJWT == "" {
		return "", ErrWGLoginNeeded
	}
	return a.Store.GuardianJWT, nil
}

// ClearGuardianJWT drops a rejected JWT (401/403 from JWT-verified
// endpoints) so the UI surfaces the browser login again.
func (a *App) ClearGuardianJWT() {
	a.mu.Lock()
	a.Store.GuardianJWT = ""
	err := a.Store.Save()
	a.mu.Unlock()
	if err != nil {
		log.Printf("wg: clear guardian jwt: %v", err)
	}
}

// truncateStr trims a response body for logs.
func truncateStr(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		return s[:n]
	}
	return s
}

// isAllDigits reports whether s is a non-empty digit string (port check).
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
