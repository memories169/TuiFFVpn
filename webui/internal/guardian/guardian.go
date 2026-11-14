// Package guardian talks to the Mozilla VPN (Firefox VPN) Guardian API to
// fetch a proxy pass JWT and account entitlement for an authenticated account.
package guardian

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const DefaultEndpoint = "https://vpn.mozilla.org"

// ErrQuotaExceeded indicates the account's monthly proxy quota is exhausted.
var ErrQuotaExceeded = errors.New("quota exceeded")

// ErrTokenInvalid indicates the access token was rejected (no entitlement).
var ErrTokenInvalid = errors.New("token invalid")

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
		c.HTTP = &http.Client{Timeout: 60 * time.Second}
	}
	url := c.endpoint() + path
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "MozillaVPN/2.35.0 (sys:linux; iap:true)")
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return body, resp.Header, resp.StatusCode, nil
}

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
