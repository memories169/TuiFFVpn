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

// Package guardian talks to the Mozilla VPN (Firefox VPN) Guardian API to
// fetch a proxy pass JWT and account entitlement for an authenticated account.
package guardian

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"fxsocks/webui/internal/edgehttp"
	"fxsocks/webui/internal/fxa"
)

const DefaultEndpoint = "https://vpn.mozilla.org"

// ErrQuotaExceeded indicates the account's monthly proxy quota is exhausted.
var ErrQuotaExceeded = errors.New("quota exceeded")

// ErrTokenInvalid indicates the access token was rejected (no entitlement).
var ErrTokenInvalid = errors.New("token invalid")

// ErrEdgeBlocked marks the Fastly anti-bot 406 family: the request never
// reached the Guardian API, so it says NOTHING about the account's health.
// Callers (webapp) branch on this to keep the current account, fall back to
// a persisted pass, and NEVER rotate/failover — every alternative account's
// fetch would hit the same edge.
var ErrEdgeBlocked = errors.New("edge blocked (Fastly anti-bot)")

// IsEdgeBlocked reports whether err is the Fastly anti-bot 406 family.
// Is() unwraps the fmt.Errorf wrapping; the textual fallback catches the
// plain "HTTP 406" wording from older call sites.
func IsEdgeBlocked(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrEdgeBlocked) {
		return true
	}
	// doFull returns "HTTP %d" after exhausting retries (wrapped by callers
	// with %w where possible); match the 406 marker textually as a fallback.
	return strings.Contains(err.Error(), "HTTP 406")
}

// ProxyPass is a parsed proxy-pass JWT plus quota headers.
type ProxyPass struct {
	RawToken   string
	Sub        string
	Exp        int64
	Nbf        int64
	QuotaMax   string
	QuotaLeft  string
	QuotaReset string
}

// Bearer returns the Proxy-Authorization value.
func (p *ProxyPass) Bearer() string { return "Bearer " + p.RawToken }

// ExpiresAt returns the pass expiry as a time.
func (p *ProxyPass) ExpiresAt() time.Time { return time.Unix(p.Exp, 0) }

// Entitlement is the account's subscription status.
type Entitlement struct {
	Subscribed       bool   `json:"subscribed"`
	UID              int    `json:"uid"`
	MaxBytes         string `json:"maxBytes"`
	LimitedBandwidth bool   `json:"limited_bandwidth"`
}

// Client makes Guardian requests with a bearer access token.
type Client struct {
	Endpoint string
	Token    string
	HTTP     *http.Client

	// Jar carries the Fastly challenge cookies earned for this host. The
	// zero value works: doFull lazily creates it on first use.
	Jar http.CookieJar

	solveOnce sync.Once
}

// edgeCookieMu guards the process-wide solved-challenge cookie cache: the
// cookies one Guardian client earned (webapp builds a fresh Client per
// fetch) are replayed by every other client, so the whole process keeps
// benefiting from ONE successful challenge solve.
var (
	edgeCookieMu sync.Mutex
	edgeCookies  map[string][]*http.Cookie // base endpoint URL → earned cookies
)

// rememberEdgeCookies stashes the challenge cookies a client's jar holds.
func rememberEdgeCookies(base string, jar http.CookieJar) {
	u, err := url.Parse(base + "/")
	if err != nil || jar == nil {
		return
	}
	cs := jar.Cookies(u)
	if len(cs) == 0 {
		return
	}
	edgeCookieMu.Lock()
	if edgeCookies == nil {
		edgeCookies = make(map[string][]*http.Cookie)
	}
	edgeCookies[base] = cs
	edgeCookieMu.Unlock()
}

// reuseEdgeCookies installs cookies previously earned by another client for
// this endpoint (same bot-score network → same challenge → same cookie).
func (c *Client) reuseEdgeCookies(base string) {
	if c.Jar == nil {
		return
	}
	edgeCookieMu.Lock()
	cs := edgeCookies[base]
	edgeCookieMu.Unlock()
	if len(cs) == 0 {
		return
	}
	if u, err := url.Parse(base + "/"); err == nil {
		c.Jar.SetCookies(u, cs)
	}
}

func (c *Client) endpoint() string {
	if c.Endpoint == "" {
		return DefaultEndpoint
	}
	return strings.TrimRight(c.Endpoint, "/")
}

func (c *Client) do(ctx context.Context, method, path string) ([]byte, int, error) {
	b, _, status, err := c.doFull(ctx, method, path)
	return b, status, err
}

func (c *Client) doFull(ctx context.Context, method, path string) ([]byte, http.Header, int, error) {
	if c.HTTP == nil {
		// edgehttp: browser-fingerprint uTLS transport — the default Go
		// fingerprint draws Fastly 406+CAPTCHA where a browser passes.
		c.HTTP = &http.Client{Timeout: 60 * time.Second, Transport: edgehttp.Transport()}
	}
	if c.Jar == nil {
		c.Jar, _ = cookiejar.New(nil)
	}
	reqURL := c.endpoint() + path

	// The Fastly edge in front of vpn.mozilla.org serves intermittent
	// anti-bot 406s (same family as the accounts hosts, see fxa.fxaRetry).
	// One attempt per call means a single unlucky roll shows the account
	// as "? / ?" until the next keeper pass 30 minutes later. Retry with
	// backoff: 2s, 6s.
	// Seed this fresh client's jar with cookies another client already
	// earned from the edge (webapp builds a new Client per fetch; without
	// this every fetch re-solves the challenge from scratch).
	c.reuseEdgeCookies(c.endpoint())

	var body []byte
	var hdr http.Header
	var status int
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, nil, 0, ctx.Err()
			case <-time.After(time.Duration(1<<(attempt-1)*2) * time.Second):
			}
		}
		// First 406: solve the Fastly challenge for this host ONCE per
		// process and stash the earned cookies in the jar — later attempts
		// (and every other call sharing this client) carry them.
		if attempt > 0 && status == http.StatusNotAcceptable {
			c.solveOnce.Do(func() {
				base := c.endpoint()
				cookies, serr := fxa.SolveChallengeCookies(ctx, base, firefoxUA)
				if serr != nil {
					return
				}
				if u, perr := url.Parse(base + "/"); perr == nil {
					c.Jar.SetCookies(u, cookies)
				}
				// Publish the earned cookies so every other Guardian client
				// in this process replays them instead of re-solving.
				rememberEdgeCookies(base, c.Jar)
			})
		}
		var req *http.Request
		req, err = http.NewRequestWithContext(ctx, method, reqURL, nil)
		if err != nil {
			return nil, nil, 0, err
		}
		req.Header.Set("Authorization", "Bearer "+c.Token)
		req.Header.Set("Content-Type", "application/json")
		// Firefox browser UA, NOT the MozillaVPN client UA: the same Fastly
		// edge family fronts vpn.mozilla.org, and from a bot-score-flagged
		// IP it answers the client UA with 403 — which FetchProxyPass maps
		// to ErrTokenInvalid ("invalid token") even though the token is
		// perfectly fine (the tunnel dials with it!). The userscript flow
		// proved the Firefox UA passes where the client UA is challenged.
		req.Header.Set("User-Agent", firefoxUA)
		req.Header.Set("Accept", "application/json")
		var resp *http.Response
		resp, err = c.HTTP.Do(req)
		if err != nil {
			continue
		}
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		hdr, status = resp.Header, resp.StatusCode
		if status != http.StatusNotAcceptable {
			return body, hdr, status, nil
		}
	}
	if err == nil {
		if status == http.StatusNotAcceptable {
			// Fastly anti-bot: the request never reached Guardian. Mark it
			// so callers treat this as a network/edge condition (retry,
			// fall back to a persisted pass) instead of a token problem.
			err = fmt.Errorf("%w: the Fastly edge answered HTTP 406 (anti-bot) — the request never reached Guardian", ErrEdgeBlocked)
		} else {
			err = fmt.Errorf("HTTP %d", status)
		}
	}
	return body, hdr, status, err
}

// truncate clamps a byte string for log lines.
func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}

// firefoxUA mirrors the UA the FxA edge accepts (fxa.DefaultBrowserUA —
// kept as a literal to avoid an import cycle; the two packages share the
// Fastly edge but not their clients).
const firefoxUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0"

// FetchProxyPass returns the proxy pass JWT and quota headers.
func (c *Client) FetchProxyPass(ctx context.Context) (*ProxyPass, error) {
	body, hdr, status, err := c.doFull(ctx, http.MethodGet, "/api/v1/fpn/token")
	if err != nil {
		return nil, err
	}
	if status == http.StatusTooManyRequests {
		return nil, fmt.Errorf("%w (HTTP 429)", ErrQuotaExceeded)
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return nil, fmt.Errorf("%w (HTTP %d)", ErrTokenInvalid, status)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("guardian token HTTP %d: %s", status, body)
	}
	var r struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Token == "" {
		return nil, errors.New("guardian returned no token")
	}
	claims, err := parseJWT(r.Token)
	if err != nil {
		return nil, err
	}
	return &ProxyPass{
		RawToken:   r.Token,
		Sub:        claims.Sub,
		Exp:        claims.Exp,
		Nbf:        claims.Nbf,
		QuotaMax:   hdr.Get("X-Quota-Limit"),
		QuotaLeft:  hdr.Get("X-Quota-Remaining"),
		QuotaReset: hdr.Get("X-Quota-Reset"),
	}, nil
}

// NewProxyPassFromRaw parses an already-fetched proxy-pass JWT (e.g.
// pushed by the PC userscript from the trusted browser) into a ProxyPass.
// quota fields come from the response headers the fetcher saw.
func NewProxyPassFromRaw(rawToken string, quotaMax, quotaLeft, quotaReset string) (*ProxyPass, error) {
	claims, err := parseJWT(rawToken)
	if err != nil {
		return nil, err
	}
	return &ProxyPass{
		RawToken:   rawToken,
		Sub:        claims.Sub,
		Exp:        claims.Exp,
		Nbf:        claims.Nbf,
		QuotaMax:   quotaMax,
		QuotaLeft:  quotaLeft,
		QuotaReset: quotaReset,
	}, nil
}

// FetchUserInfo returns the account entitlement.
func (c *Client) FetchUserInfo(ctx context.Context) (*Entitlement, error) {
	body, status, err := c.do(ctx, http.MethodGet, "/api/v1/fpn/status")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("guardian status HTTP %d: %s", status, body)
	}
	var e Entitlement
	if err := json.Unmarshal(body, &e); err != nil {
		return nil, fmt.Errorf("parse entitlement: %w", err)
	}
	return &e, nil
}

// Activate activates the account for proxy access.
func (c *Client) Activate(ctx context.Context) (*Entitlement, error) {
	body, status, err := c.do(ctx, http.MethodPost, "/api/v1/fpn/activate")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("guardian activate HTTP %d: %s", status, body)
	}
	var e Entitlement
	if err := json.Unmarshal(body, &e); err != nil {
		return nil, fmt.Errorf("parse activation: %w", err)
	}
	return &e, nil
}

type jwtClaims struct {
	Sub string
	Exp int64
	Nbf int64
	Iat int64
}

func parseJWT(token string) (jwtClaims, error) {
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
	if v, ok := claims["sub"].(string); ok {
		c.Sub = v
	}
	for _, k := range []string{"exp", "nbf", "iat"} {
		switch v := claims[k].(type) {
		case float64:
			switch k {
			case "exp":
				c.Exp = int64(v)
			case "nbf":
				c.Nbf = int64(v)
			case "iat":
				c.Iat = int64(v)
			}
		case string:
			var n int64
			fmt.Sscan(v, &n)
			switch k {
			case "exp":
				c.Exp = n
			case "nbf":
				c.Nbf = n
			case "iat":
				c.Iat = n
			}
		}
	}
	return c, nil
}

// ─── WireGuard device registration ───────────────────────────────────────────
// The Mozilla VPN client registers a Curve25519 keypair as a "device" via
// POST /api/v1/vpn/device {name, unique_id, pubkey} and receives a
// device-scoped tunnel IP pair (ipv4_address, ipv6_address). With a device
// registered, the account's WireGuard tunnel endpoints become usable — full
// UDP capability (torrent trackers, DHT) that the FPN proxy-pass path
// cannot offer (the edge 502s CONNECT-UDP to non-allowlisted destinations).

// WGDevice is one registered WireGuard device (Guardian /vpn/device shape).
type WGDevice struct {
	Name       string `json:"name"`
	UniqueID   string `json:"unique_id"`
	CreatedAt  string `json:"created_at"`
	PublicKey  string `json:"pubkey"`
	IPv4       string `json:"ipv4_address"`
	IPv6       string `json:"ipv6_address"`
}

// RegisterDevice registers (or idempotently re-registers) a WireGuard device
// keypair with Guardian. accessToken is the FxA OAuth access token (the same
// one the official client sends: `request->auth()` uses the FxA bearer, NOT
// the FPN proxy pass). Guardian replies 201 with the device JSON carrying
// the assigned tunnel IPs.
func (c *Client) RegisterDevice(ctx context.Context, name, uniqueID, publicKey string) (*WGDevice, error) {
	payload, err := json.Marshal(map[string]string{
		"name":      name,
		"unique_id": uniqueID,
		"pubkey":    publicKey,
	})
	if err != nil {
		return nil, err
	}
	reqURL := c.endpoint() + "/api/v1/vpn/device"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", firefoxUA)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		// 201 = created, 200 = already existed (idempotent re-registration).
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("%w: device registration (HTTP %d): %s", ErrTokenInvalid, resp.StatusCode, truncate(body, 200))
	case http.StatusConflict:
		return nil, fmt.Errorf("device limit reached (HTTP 409) — remove a device at https://accounts.firefox.com/settings#devices then retry: %s", truncate(body, 200))
	default:
		return nil, fmt.Errorf("guardian device HTTP %d: %s", resp.StatusCode, truncate(body, 200))
	}

	// The device object may come back bare or wrapped in {"device": {...}}.
	var probe struct {
		Device *WGDevice `json:"device"`
		WGDevice
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return nil, fmt.Errorf("parse device: %w", err)
	}
	dev := probe.Device
	if dev == nil {
		dev = &probe.WGDevice
	}
	if dev.IPv4 == "" {
		return nil, fmt.Errorf("guardian device response missing ipv4_address: %s", truncate(body, 200))
	}
	return dev, nil
}

// FetchWGServers retrieves the WireGuard server list from Guardian
// (GET /api/v1/vpn/servers) — the list the official client consumes; unlike
// the RemoteSettings MASQUE list it carries per-server WG fields
// (public_key, ipv4_gateway, ipv4_addr_in, port_ranges, multihop_port).
func (c *Client) FetchWGServers(ctx context.Context) (json.RawMessage, error) {
	body, _, status, err := c.doFull(ctx, http.MethodGet, "/api/v1/vpn/servers")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("guardian servers HTTP %d: %s", status, body)
	}
	return json.RawMessage(body), nil
}
