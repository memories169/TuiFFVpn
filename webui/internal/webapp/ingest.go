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
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"fxsocks/webui/internal/browsercapture"
	"fxsocks/webui/internal/fxa"
	"fxsocks/webui/internal/guardian"
)

// ingestKey is the shared secret the PC userscript must present. It lets a
// normal Firefox on the host push captured tokens into the container without
// sharing the admin session cookie across origins.
func ingestKey() string {
	return strings.TrimSpace(os.Getenv("FXVPN_INGEST_KEY"))
}

// ingestRequest is the payload POSTed by the userscript.
//
// The userscript runs on any desktop browser (Mozilla blocks userscript
// managers on their pages in Firefox, so Chromium+Violentmonkey is common).
// It only captures the sessionToken; the container performs the exchange with
// its own Firefox UA — the FxA edge only checks that the UA is Firefox
// (verified live: no challenge cookies needed), so the browser's real UA is
// irrelevant.
type ingestRequest struct {
	Email        string `json:"email"`
	AccessToken  string `json:"access_token"`  // reserved: pre-exchanged tokens
	RefreshToken string `json:"refresh_token"` // reserved: pre-exchanged tokens
	ExpiresIn    int    `json:"expires_in"`    // reserved: pre-exchanged tokens
	Scope        string `json:"scope"`         // reserved: pre-exchanged tokens
	SessionToken string `json:"session_token"`
}

// handleIngest stores tokens pushed from the PC browser (userscript).
//
// Auth: `X-Ingest-Key` must match FXVPN_INGEST_KEY. When that variable is
// unset or empty the endpoint is disabled — no accidental open writer.
func (a *App) handleIngest(w http.ResponseWriter, r *http.Request) {
	key := ingestKey()
	if key == "" {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "ingest disabled: set FXVPN_INGEST_KEY in the container environment",
		})
		return
	}
	if !constantTimeEqual(r.Header.Get("X-Ingest-Key"), key) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid ingest key"})
		return
	}

	var req ingestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad request"})
		return
	}

	// Preferred shape: ready OAuth tokens from the PC exchange.
	if req.AccessToken != "" {
		if req.ExpiresIn <= 0 {
			req.ExpiresIn = 24 * 3600
		}
		a.mu.Lock()
		a.Store.UpsertAccount(strings.TrimSpace(req.Email), strings.TrimSpace(req.AccessToken), strings.TrimSpace(req.RefreshToken), req.ExpiresIn)
		err := a.Store.Save()
		a.mu.Unlock()
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": "persist failed: " + err.Error()})
			return
		}
		a.trackAccount(req.Email, "", "")
		log.Printf("webui: ingested OAuth tokens for %s (PC browser)", req.Email)

		a.probeQuota(strings.TrimSpace(req.AccessToken), strings.TrimSpace(req.Email))

		writeJSON(w, 200, map[string]any{"ok": true, "stored": "oauth", "email": req.Email})
		return
	}

	// Fallback: bare sessionToken — exchange server-side with the container's
	// default Firefox UA (the edge only checks the UA, so this passes).
	req.SessionToken = strings.ToLower(strings.TrimSpace(req.SessionToken))
	if !browsercapture.IsSessionToken(req.SessionToken) {
		writeJSON(w, 400, map[string]any{"error": "need access_token or a 64-hex session_token"})
		return
	}
	tok, err := fxa.ExchangeSessionToken(r.Context(), req.SessionToken)
	if err != nil {
		writeJSON(w, 200, map[string]any{"error": err.Error()})
		return
	}
	a.storeTokens(tok, req.Email)
	log.Printf("webui: ingested sessionToken for %s, exchanged server-side", req.Email)
	writeJSON(w, 200, map[string]any{"ok": true, "stored": "oauth", "email": req.Email})
}

// storeTokens persists OAuth tokens for an account and marks it active.
func (a *App) storeTokens(tok *fxa.TokenResponse, email string) {
	a.mu.Lock()
	a.Store.UpsertAccount(strings.TrimSpace(email), tok.AccessToken, tok.RefreshToken, tok.ExpiresIn)
	err := a.Store.Save()
	a.mu.Unlock()
	if err != nil {
		log.Printf("webui: persist tokens: %v", err)
		return
	}
	a.trackAccount(email, "", "")
	a.probeQuota(tok.AccessToken, email)
}

// probeQuota best-effort fetches the account's proxy quota from Guardian and
// updates the account list. Runs in the background; failures are logged and
// ignored (the quota also refreshes whenever a server is selected).
// It only updates EXISTING accounts — never creates stub entries without
// tokens, which would make the UI show an unusable "active" account.
//
// This mirrors FoxyVPN's fetchUserInfo: on TokenInvalidError it refreshes the
// access token, then provisions the Guardian entitlement via POST /activate
// (this is how a brand-new Firefox account gets registered for the free VPN
// tier without touching vpn.mozilla.org manually) and retries the proxy pass.
func (a *App) probeQuota(accessToken, email string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		client := &guardian.Client{Token: accessToken}
		pass, err := client.FetchProxyPass(ctx)
		if errors.Is(err, guardian.ErrTokenInvalid) {
			// Step 1: provision the entitlement with the CURRENT token — no
			// refresh needed, and the token may be perfectly valid for
			// Guardian even if nearing expiry. (The old order — refresh
			// first — let a Fastly CAPTCHA on the refresh call short-circuit
			// the chain so /activate was never reached.)
			if _, aerr := client.Activate(ctx); aerr == nil {
				if p2, perr := client.FetchProxyPass(ctx); perr == nil {
					a.mu.Lock()
					if ac := a.Store.FindAccount(email); ac != nil {
						ac.QuotaMax = p2.QuotaMax
						ac.QuotaLeft = p2.QuotaLeft
						ac.CheckedAt = time.Now()
						ac.ProbeError = ""
						_ = a.Store.Save()
					}
					a.mu.Unlock()
					log.Printf("webui: quota for %s: %s / %s (after activate)", email, p2.QuotaLeft, p2.QuotaMax)
					return
				} else {
					err = perr
				}
			} else {
				log.Printf("webui: activate for %s failed: %v", email, aerr)
			}
			// Step 2: refresh and retry. A refresh failure (Fastly CAPTCHA
			// from this network) must NOT abort the chain — step 3 still runs.
			a.mu.Lock()
			ac := a.Store.FindAccount(email)
			refresh := ""
			if ac != nil {
				refresh = ac.RefreshToken
			}
			a.mu.Unlock()
			if refresh != "" {
				// Single-flight gated refresh (rotating FxA tokens).
				if tok, rerr := a.refreshAccountToken(ctx, email, refresh); rerr == nil {
					client = &guardian.Client{Token: tok}
					pass, err = client.FetchProxyPass(ctx)
					if errors.Is(err, guardian.ErrTokenInvalid) {
						if _, aerr := client.Activate(ctx); aerr == nil {
							pass, err = client.FetchProxyPass(ctx)
						}
					}
				} else {
					log.Printf("webui: quota probe refresh for %s failed: %v", email, rerr)
				}
			}
		}
		if err != nil {
			reason := err.Error()
			// Mirror FoxyVPN: even when the proxy pass fails, fetch the
			// entitlement from /fpn/status — a 200 there means the account
			// IS entitled and only the pass fetch was transient.
			st, serr := client.FetchUserInfo(ctx)
			if serr == nil && st != nil {
				a.mu.Lock()
				if ac := a.Store.FindAccount(email); ac != nil {
					if st.MaxBytes != "" {
						ac.QuotaMax = st.MaxBytes
					}
					ac.CheckedAt = time.Now()
					ac.ProbeError = ""
					_ = a.Store.Save()
				}
				a.mu.Unlock()
				log.Printf("webui: %s entitled via /fpn/status (pass fetch still failing: %v)", email, err)
				return
			}
			if serr != nil {
				reason = reason + "; /fpn/status: " + serr.Error()
			}
			a.mu.Lock()
			if ac := a.Store.FindAccount(email); ac != nil {
				ac.ProbeError = reason
				ac.CheckedAt = time.Now()
				_ = a.Store.Save()
			}
			a.mu.Unlock()
			log.Printf("webui: quota probe for %s failed: %s", email, reason)
			return
		}
		a.mu.Lock()
		if ac := a.Store.FindAccount(email); ac != nil {
			ac.QuotaMax = pass.QuotaMax
			ac.QuotaLeft = pass.QuotaLeft
			ac.CheckedAt = time.Now()
			ac.ProbeError = ""
			_ = a.Store.Save()
			log.Printf("webui: quota for %s: %s / %s", email, pass.QuotaLeft, pass.QuotaMax)
		}
		a.mu.Unlock()
	}()
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
