package fxa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// DefaultOAuthTokenURLs are the endpoints that accept the fxa-credentials
// grant. Only the api host qualifies: it carries the sessionTokenBearer auth
// strategy. The legacy oauth host speaks OAuth client auth only and answers
// errno 109 ("invalid request parameter: headers.authorization") for session
// tokens, so it must not be in this list — its 400 would mask the real error.
var DefaultOAuthTokenURLs = []string{
	AuthServer + "/oauth/token",
}

// SessionStatusResponse is the subset of /recovery_email/status we use.
type SessionStatusResponse struct {
	Email      string `json:"email"`
	UID        string `json:"uid"`
	Verified   bool   `json:"verified"`
	SessionUID string `json:"sessionUid"`
}

// ErrInvalidSessionToken is returned when FxA rejects the session token.
var ErrInvalidSessionToken = errors.New("firefox accounts rejected the session token")

// ErrChallengeStale is returned when the request carried Fastly challenge
// cookies but the edge still answered 406. The cookies were not accepted —
// they are expired (the challenge has a short TTL) or bound to a different
// request context (UA/IP). The fix is a fresh capture, not the solver.
var ErrChallengeStale = errors.New("the Fastly challenge cookie was rejected (expired or context mismatch)")

// TokenOptions carries the browser context a capture produced. FxA sits behind
// a Fastly edge that serves an HTTP 406 CAPTCHA challenge to plain HTTP
// clients. A browser that loaded accounts.firefox.com earns a `_fs_ch_*`
// cookie, but that cookie is bound to the browser's User-Agent, so both the
// cookie and a matching Firefox UA must be replayed for the exchange to reach
// the auth logic. Leaving both empty falls back to the Fastly solver.
type TokenOptions struct {
	// Cookies are the browser cookies to replay (Mozilla domains only).
	Cookies []*http.Cookie
	// UserAgent is the browser's User-Agent. When empty and Cookies are set,
	// DefaultBrowserUA is used.
	UserAgent string
	// TokenURLs overrides DefaultOAuthTokenURLs.
	TokenURLs []string
}

// DefaultBrowserUA is a current desktop Firefox user agent. The Fastly
// challenge cookie is issued against the UA that solved the challenge, so a
// captured Firefox session must replay this, not a MozillaVPN client UA.
const DefaultBrowserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0"

func (o TokenOptions) userAgent() string {
	if o.UserAgent != "" {
		return o.UserAgent
	}
	// The Fastly edge in front of the OAuth endpoints only checks that the UA
	// is a Firefox one (verified live: no cookies needed, any browser UA string
	// containing Firefox passes). The MozillaVPN client UA gets 406'd, so the
	// Firefox UA is the safe default for every session-token exchange.
	return DefaultBrowserUA
}

func (o TokenOptions) urls() []string {
	if len(o.TokenURLs) > 0 {
		return o.TokenURLs
	}
	return DefaultOAuthTokenURLs
}

func (o TokenOptions) install() {
	if len(o.Cookies) == 0 {
		return
	}
	// Fastly validates the challenge cookie per host, so install it for every
	// FxA host we call (plus any caller-supplied endpoint, which keeps this
	// testable). Cookies are installed host-only: a Domain attribute that is
	// broader or mismatched than the target host makes http.CookieJar silently
	// drop the cookie, so it is stripped here on purpose. Secure is preserved
	// only for https targets — the jar rejects Secure cookies against plain
	// http:// URLs (which is also why the httptest-based unit tests pass
	// Secure=false-shaped cookies).
	hosts := []string{AuthServer + "/", fxaSiteURL}
	hosts = append(hosts, o.urls()...)
	for _, host := range hosts {
		u, err := url.Parse(host)
		if err != nil {
			continue
		}
		cleaned := make([]*http.Cookie, 0, len(o.Cookies))
		for _, c := range o.Cookies {
			cc := *c
			cc.Domain = "" // host-only: never rejected by the jar's domain check
			cc.Secure = u.Scheme == "https"
			cleaned = append(cleaned, &cc)
		}
		controlPlane.Jar.SetCookies(u, cleaned)
	}
}

// ExchangeSessionToken trades a browser-captured session token for the OAuth
// access + refresh tokens the VPN entitlement needs.
func ExchangeSessionToken(ctx context.Context, sessionToken string) (*TokenResponse, error) {
	return ExchangeSessionTokenWith(ctx, sessionToken, TokenOptions{})
}

// ExchangeSessionTokenWith is ExchangeSessionToken with browser context.
func ExchangeSessionTokenWith(ctx context.Context, sessionToken string, opts TokenOptions) (*TokenResponse, error) {
	sessionToken = normalizeSessionToken(sessionToken)
	opts.install()
	id, key, err := hawkCredentials(sessionToken, "sessionToken")
	if err != nil {
		return nil, err
	}

	body := map[string]any{
		"client_id":   ClientID,
		"grant_type":  "fxa-credentials",
		"scope":       OAuthScope,
		"access_type": "offline",
		// FxA caps this at oauthServer.expiration.accessToken (6h) but the
		// fxa-credentials grant defaults to a shorter TTL for some clients;
		// asking for the max explicitly keeps rotated accounts alive longer
		// between refreshes.
		"ttl": 21600,
	}
	bj, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	ua := opts.userAgent()

	var lastErr error
	var rejected error
	for _, tokenURL := range opts.urls() {
		hawk, err := hawkHeader(http.MethodPost, tokenURL, id, key, string(bj))
		if err != nil {
			return nil, err
		}
		for _, auth := range []string{"Bearer fxs_" + id, hawk} {
			data, status, err := fxaRetry(ctx, func() (*http.Request, error) {
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(string(bj)))
				if err != nil {
					return nil, err
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("User-Agent", ua)
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Authorization", auth)
				return req, nil
			})
			if err != nil {
				lastErr = err
				continue
			}
			if status != http.StatusOK {
				lastErr = fmt.Errorf("oauth token HTTP %d from %s: %s", status, tokenURL, truncate(data))
				if status == http.StatusUnauthorized || status == http.StatusForbidden {
					err := fmt.Errorf("%w (HTTP %d): %s", ErrInvalidSessionToken, status, truncate(data))
					if rejected == nil {
						rejected = err
					}
					lastErr = err
				}
				continue
			}
			var t TokenResponse
			if err := json.Unmarshal(data, &t); err != nil {
				return nil, fmt.Errorf("parse token: %w", err)
			}
			if t.AccessToken == "" {
				return nil, errors.New("oauth token response is missing access_token")
			}
			return &t, nil
		}
	}
	// A 401 from the primary host is a definitive answer: the token was
	// rejected. Report it rather than a later errno 109 from the legacy OAuth
	// host, which would be misleading.
	if rejected != nil {
		return nil, rejected
	}
	// A 406 despite replayed challenge cookies means the cookies were not
	// accepted (expired / wrong context): say so instead of running the
	// solver, which only ever reaches a CAPTCHA page here.
	if len(opts.Cookies) > 0 && isFastlyCaptchaErr(lastErr) {
		return nil, fmt.Errorf("%w: refresh the capture (reload accounts.firefox.com so new _fs_ch_* cookies are issued) and make sure the User-Agent matches the browser that earned them", ErrChallengeStale)
	}
	if lastErr == nil {
		lastErr = errors.New("no oauth token endpoint configured")
	}
	return nil, lastErr
}

func isFastlyCaptchaErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "406") || strings.Contains(msg, "captcha")
}

// SessionStatus fetches /recovery_email/status for a session token. The
// endpoint is backed by the same HKDF id lookup as the OAuth exchange, so it
// doubles as a cheap "is this token valid and verified" probe.
// SessionStatusWith checks a session token's verified state against an
// overridable endpoint.
func SessionStatusWith(ctx context.Context, sessionToken string, opts TokenOptions, statusURL string) (*SessionStatusResponse, error) {
	sessionToken = normalizeSessionToken(sessionToken)
	opts.install()
	id, key, err := hawkCredentials(sessionToken, "sessionToken")
	if err != nil {
		return nil, err
	}
	hawk, err := hawkHeader(http.MethodGet, statusURL, id, key, "")
	if err != nil {
		return nil, err
	}
	ua := opts.userAgent()

	var lastErr error
	for _, auth := range []string{"Bearer fxs_" + id, hawk} {
		data, status, err := fxaRetry(ctx, func() (*http.Request, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", ua)
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Authorization", auth)
			return req, nil
		})
		if err != nil {
			lastErr = err
			continue
		}
		switch {
		case status == http.StatusOK:
			var out SessionStatusResponse
			if err := json.Unmarshal(data, &out); err != nil {
				return nil, fmt.Errorf("parse session status: %w", err)
			}
			return &out, nil
		case status == http.StatusUnauthorized || status == http.StatusForbidden:
			lastErr = fmt.Errorf("%w (HTTP %d): %s", ErrInvalidSessionToken, status, truncate(data))
		default:
			lastErr = fmt.Errorf("session status HTTP %d: %s", status, truncate(data))
		}
	}
	return nil, lastErr
}

// DestroySession revokes the FxA session token. Callers should only use this
// once the OAuth tokens are stored, because it signs the browser out.
func DestroySession(ctx context.Context, sessionToken string) error {
	return DestroySessionWith(ctx, sessionToken, TokenOptions{})
}

// DestroySessionWith is DestroySession with browser context.
func DestroySessionWith(ctx context.Context, sessionToken string, opts TokenOptions) error {
	sessionToken = normalizeSessionToken(sessionToken)
	opts.install()
	id, key, err := hawkCredentials(sessionToken, "sessionToken")
	if err != nil {
		return err
	}
	endpoint := AuthServer + "/session/destroy"
	body := "{}"
	hawk, err := hawkHeader(http.MethodPost, endpoint, id, key, body)
	if err != nil {
		return err
	}
	ua := opts.userAgent()
	for _, auth := range []string{"Bearer fxs_" + id, hawk} {
		data, status, err := fxaRetry(ctx, func() (*http.Request, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
			if err != nil {
				return nil, err
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", ua)
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Authorization", auth)
			return req, nil
		})
		if err != nil {
			return err
		}
		if status == http.StatusOK || status == http.StatusNoContent || status == http.StatusUnauthorized {
			return nil
		}
		return fmt.Errorf("session destroy HTTP %d: %s", status, truncate(data))
	}
	return nil
}

func normalizeSessionToken(tok string) string {
	return strings.ToLower(strings.NewReplacer(" ", "", "\n", "", "\t", "", "\r", "", "\"", "").Replace(strings.TrimSpace(tok)))
}
