// Package fxa implements the Firefox Accounts (FxA) sign-in flow used by the
// Firefox VPN / Mozilla VPN clients: password-stretched login, email 2FA
// verification, and OAuth token exchange.
package fxa

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

const (
	AuthServer   = "https://api.accounts.firefox.com/v1"
	ClientID     = "5882386c6d801776"
	OAuthScope   = "profile https://identity.mozilla.com/apps/vpn"
	ProtoVersion = "identity.mozilla.com/picl/v1/"
	PBKDF2Rounds = 1000
	UA           = "MozillaVPN/2.35.0 (sys:linux; iap:true)"
)

var (
	// ErrUnverified is returned when login needs an email 2FA code.
	ErrUnverified = errors.New("login requires email verification")
	// ErrInvalidCreds is returned on a bad email/password or 2FA code.
	ErrInvalidCreds = errors.New("invalid credentials")

	// maxChallengeAttempts bounds how many times an FxA call re-solves the
	// Fastly challenge before giving up.
	maxChallengeAttempts = 5
)

// shared control-plane client with a cookie jar so the Fastly anti-bot cookie
// earned by the challenge solver persists across retries.
var (
	jar          http.CookieJar
	controlPlane *http.Client
)

func init() {
	jar, _ = cookiejar.New(nil)
	controlPlane = &http.Client{Jar: jar, Timeout: 90 * time.Second}
}

// LoginResponse is the FxA /account/login response.
type LoginResponse struct {
	SessionToken       string `json:"sessionToken"`
	UID                string `json:"uid"`
	Verified           bool   `json:"verified"`
	AuthAt             int64  `json:"authAt"`
	VerificationMethod string `json:"verificationMethod"`
	VerificationReason string `json:"verificationReason"`
}

// TokenResponse is the FxA /oauth/token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

// deriveAuthPW stretches the password into the authPW value FxA expects.
func deriveAuthPW(email, password string) ([]byte, error) {
	salt := []byte(ProtoVersion + "quickStretch:" + email)
	quick := pbkdf2.Key([]byte(password), salt, PBKDF2Rounds, 32, sha256.New)
	info := []byte(ProtoVersion + "authPW")
	hkdfReader := hkdf.New(sha256.New, quick, []byte{0x00}, info)
	authPW := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, authPW); err != nil {
		return nil, err
	}
	return authPW, nil
}

func hawkCredentials(tokenHex, ctx string) (string, []byte, error) {
	b, err := hex.DecodeString(tokenHex)
	if err != nil {
		return "", nil, fmt.Errorf("invalid token hex: %w", err)
	}
	info := []byte(ProtoVersion + ctx)
	r := hkdf.New(sha256.New, b, nil, info)
	out := make([]byte, 96)
	if _, err := io.ReadFull(r, out); err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(out[:32]), out[32:64], nil
}

func hawkHeader(method, rawURL, id string, key []byte, payload string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 6)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ts := fmt.Sprintf("%d", time.Now().Unix())
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	var payloadHash string
	if payload != "" {
		h := sha256.New()
		h.Write([]byte("hawk.1.payload\napplication/json\n"))
		h.Write([]byte(payload))
		h.Write([]byte("\n"))
		payloadHash = hex.EncodeToString(h.Sum(nil))
	}
	norm := strings.Join([]string{
		"hawk.1.header", ts, hex.EncodeToString(nonce),
		strings.ToUpper(method), u.RequestURI(), u.Hostname(), port,
		payloadHash, "", "",
	}, "\n")
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(norm))
	header := fmt.Sprintf(`Hawk id="%s", ts="%s", nonce="%s", mac="%s"`,
		id, ts, hex.EncodeToString(nonce), hex.EncodeToString(mac.Sum(nil)))
	if payloadHash != "" {
		header += fmt.Sprintf(`, hash="%s"`, payloadHash)
	}
	return header, nil
}

func postJSON(ctx context.Context, url string, body map[string]any) ([]byte, int, error) {
	bj, _ := json.Marshal(body)
	return fxaRetry(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(bj)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", UA)
		req.Header.Set("Accept", "application/json")
		return req, nil
	})
}

func postJSONHawk(ctx context.Context, url string, body map[string]any, id string, key []byte) ([]byte, int, error) {
	bj, _ := json.Marshal(body)
	auth, err := hawkHeader("POST", url, id, key, string(bj))
	if err != nil {
		return nil, 0, err
	}
	return fxaRetry(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(bj)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", UA)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", auth)
		return req, nil
	})
}

// fxaRetry performs the request via the shared control-plane client. When the
// edge answers HTTP 406 (Fastly anti-bot challenge, empty body), it solves the
// challenge and retries with the earned cookie, up to maxChallengeAttempts.
func fxaRetry(ctx context.Context, newRequest func() (*http.Request, error)) ([]byte, int, error) {
	for attempt := 1; attempt <= maxChallengeAttempts; attempt++ {
		req, err := newRequest()
		if err != nil {
			return nil, 0, err
		}
		resp, err := controlPlane.Do(req)
		if err != nil {
			return nil, 0, err
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotAcceptable {
			return data, resp.StatusCode, nil
		}
		if err := solveFastlyChallenge(ctx); err != nil {
			return nil, resp.StatusCode, fmt.Errorf("fastly challenge: %w", err)
		}
	}
	return nil, http.StatusNotAcceptable, fmt.Errorf("fastly challenge still failing after %d attempts", maxChallengeAttempts)
}
