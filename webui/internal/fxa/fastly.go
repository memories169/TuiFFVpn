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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Fastly anti-bot client-challenge solver. Firefox Accounts is fronted by a
// Fastly edge that sometimes answers API requests with an empty HTTP 406. The
// solver performs the challenge handshake and installs the earned cookie into
// the shared control-plane client so the API call retries carry it.

// browserUA mimics a desktop browser so the Fastly edge serves its
// client-challenge page (the MozillaVPN UA does not trigger it).
const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// controlPlaneUA and desktopUA are the other UAs the edge may respond to.
const controlPlaneUA = "MozillaVPN/2.35.0 (sys:linux; iap:true)"
const desktopUA = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"

const (
	fxaSiteURL     = "https://accounts.firefox.com/"
	solveTimeout   = 60 * time.Second
	maxPostBackRnd = 8
)

var (
	prefixRe    = regexp.MustCompile(`/_fs-ch-[A-Za-z0-9]+`)
	initCallRe  = regexp.MustCompile(`init\((\[[^\]]*\]),\s*"([^"]+)",\s*"([^"]+)"`)
	powAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	solveMu     sync.Mutex

	errNoChallengePage      = errors.New("no Fastly challenge page served")
	errChallengeNotAccepted = errors.New("challenge cookie not accepted")

	// ErrFastlyChallenge marks every failure caused by the Fastly anti-bot
	// edge (CAPTCHA served, challenge not accepted, solver out of rounds).
	// It is TRANSIENT and network-level: the account's FxA grant is fine and
	// the VPN keeps working — callers must not treat the account as dead.
	ErrFastlyChallenge = errors.New("fastly anti-bot challenge")
)

type fastlyChallenge struct {
	Ty   string          `json:"ty"`
	Data json.RawMessage `json:"data"`
}

type fastlyPowData struct {
	Base    string `json:"base"`
	Expires string `json:"expires"`
	HMAC    string `json:"hmac"`
	Hash    string `json:"hash"`
}

type fastlyPostBack struct {
	Token string        `json:"token"`
	Data  []interface{} `json:"data"`
}

type fastlyPostBackResponse struct {
	Status string            `json:"status"`
	Ch     []fastlyChallenge `json:"ch"`
	Tok    string            `json:"tok"`
}

// solveFastlyChallenge performs the challenge handshake and installs the
// earned cookie into the control-plane client's jar.
func solveFastlyChallenge(ctx context.Context) error {
	solveMu.Lock()
	defer solveMu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, solveTimeout)
	defer cancel()

	uas := []string{browserUA, controlPlaneUA, desktopUA}
	bases := []string{"https://api.accounts.firefox.com", strings.TrimRight(fxaSiteURL, "/")}
	var lastErr error
	for _, base := range bases {
		for _, ua := range uas {
			err := solveOnHost(ctx, base, ua)
			if err == nil {
				return nil
			}
			lastErr = err
			if errors.Is(err, errNoChallengePage) {
				continue
			}
		}
	}
	if lastErr == nil {
		lastErr = errNoChallengePage
	}
	// Wrap every solver failure in ErrFastlyChallenge so callers can tell a
	// transient edge problem from a dead refresh token.
	return fmt.Errorf("%w: %v", ErrFastlyChallenge, lastErr)
}

// SolveChallengeCookies runs the Fastly anti-bot handshake against the
// given host with the given user agent and returns the earned cookies
// WITHOUT touching the shared control-plane jar. Callers with their own
// HTTP client (e.g. guardian.Client for vpn.mozilla.org) use this to
// pre-seed their jar when the edge starts challenging their requests.
func SolveChallengeCookies(ctx context.Context, base, userAgent string) ([]*http.Cookie, error) {
	solveMu.Lock()
	defer solveMu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, solveTimeout)
	defer cancel()

	jar, err := newJar()
	if err != nil {
		return nil, err
	}
	if err := solveOnHostWith(ctx, base, userAgent, jar); err != nil {
		return nil, err
	}
	parsed, err := url.Parse(base + "/")
	if err != nil {
		return nil, err
	}
	cookies := jar.Cookies(parsed)
	if len(cookies) == 0 {
		return nil, fmt.Errorf("challenge completed but no cookie issued")
	}
	return cookies, nil
}

// solveOnHost runs the challenge flow against one host with a throwaway client
// and a fresh cookie jar.
func solveOnHost(ctx context.Context, base, userAgent string) error {
	jar, err := newJar()
	if err != nil {
		return err
	}
	return solveOnHostWith(ctx, base, userAgent, jar)
}

// solveOnHostWith runs the challenge flow against one host with the given
// cookie jar (so callers can harvest the earned cookies).
func solveOnHostWith(ctx context.Context, base, userAgent string, jar http.CookieJar) error {
	client := &http.Client{Transport: controlPlane.Transport, Jar: jar, Timeout: solveTimeout}

	pageURL := base + "/"
	page, isChallenge, err := fetchPage(ctx, client, pageURL, userAgent)
	if err != nil {
		return err
	}
	if !isChallenge {
		return errNoChallengePage
	}

	prefix := prefixRe.FindString(page)
	if prefix == "" {
		return fmt.Errorf("challenge prefix not found on %s", base)
	}

	script, err := fetchText(ctx, client, base+prefix+"/script.js?reload=true", userAgent)
	if err != nil {
		return err
	}

	challenges, token, err := parseChallengeInit(script)
	if err != nil {
		return err
	}

	for round := 0; round < maxPostBackRnd; round++ {
		answers := make([]interface{}, 0, len(challenges))
		for _, ch := range challenges {
			ans, err := answerChallenge(ctx, client, base+prefix, token, ch, userAgent)
			if err != nil {
				return err
			}
			answers = append(answers, ans)
		}

		postBack, _ := json.Marshal(fastlyPostBack{Token: token, Data: answers})
		resp, err := doPost(ctx, client, base+prefix+"/fst-post-back", postBack, userAgent)
		if err != nil {
			return err
		}
		data := resp.body
		if resp.status != http.StatusOK {
			return fmt.Errorf("challenge post-back HTTP %d: %s", resp.status, truncateStr(string(data), 256))
		}

		var pb fastlyPostBackResponse
		if err := json.Unmarshal(data, &pb); err != nil {
			return fmt.Errorf("parse post-back: %w", err)
		}
		if pb.Status == "success" {
			if _, still, err := fetchPage(ctx, client, pageURL, userAgent); err != nil {
				return err
			} else if still {
				return errChallengeNotAccepted
			}
			return installCookies(jar, pageURL)
		}
		if len(pb.Ch) == 0 || pb.Tok == "" {
			return fmt.Errorf("unexpected post-back: %s", truncateStr(string(data), 256))
		}
		challenges, token = pb.Ch, pb.Tok
	}
	return fmt.Errorf("fastly challenge incomplete after %d rounds", maxPostBackRnd)
}

type httpResult struct {
	status int
	body   []byte
}

func fetchPage(ctx context.Context, client *http.Client, pageURL, userAgent string) (string, bool, error) {
	body, err := fetchText(ctx, client, pageURL, userAgent)
	if err != nil {
		return "", false, err
	}
	isChallenge := len(body) > 0 && len(body) <= 2_000_000 &&
		strings.Contains(body, "/_fs-ch-") &&
		(strings.Contains(body, "Client Challenge") || strings.Contains(body, "script.js") || strings.Contains(body, "fst-post-back"))
	return body, isChallenge, nil
}

func fetchText(ctx context.Context, client *http.Client, rawURL, userAgent string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s returned HTTP %d", rawURL, resp.StatusCode)
	}
	return string(data), nil
}

func doPost(ctx context.Context, client *http.Client, rawURL string, body []byte, userAgent string) (*httpResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Origin", baseOrigin(rawURL))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	return &httpResult{status: resp.StatusCode, body: data}, nil
}

func parseChallengeInit(script string) ([]fastlyChallenge, string, error) {
	matches := initCallRe.FindAllStringSubmatch(script, -1)
	if len(matches) == 0 {
		return nil, "", fmt.Errorf("challenge init call not found")
	}
	m := matches[len(matches)-1]
	var challenges []fastlyChallenge
	if err := json.Unmarshal([]byte(m[1]), &challenges); err != nil {
		return nil, "", err
	}
	if len(challenges) == 0 {
		return nil, "", fmt.Errorf("empty challenge list")
	}
	return challenges, m[2], nil
}

func answerChallenge(ctx context.Context, client *http.Client, prefixURL, token string, ch fastlyChallenge, userAgent string) (interface{}, error) {
	switch ch.Ty {
	case "pow":
		var d fastlyPowData
		if err := json.Unmarshal(ch.Data, &d); err != nil {
			return nil, err
		}
		answer, ok := solvePow(d.Base, d.Hash)
		if !ok {
			return nil, fmt.Errorf("no pow solution for base %q", d.Base)
		}
		return map[string]interface{}{"ty": "pow", "base": d.Base, "answer": answer, "hmac": d.HMAC, "expires": d.Expires}, nil
	case "pat":
		auth, err := fetchPAT(ctx, client, prefixURL, token, userAgent)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"ty": "pat", "auth": auth}, nil
	case "clientmetrics":
		return map[string]interface{}{
			"ty": "clientmetrics", "webdriver": false,
			"bot_detection_result": map[string]interface{}{"bot_detected": false, "bot_kind": nil},
			"browser_metrics":      map[string]interface{}{"client_data": "{}", "error_trace": nil},
			"detector_results":     map[string]interface{}{}, "v": 2,
		}, nil
	case "captcha":
		return nil, fmt.Errorf("Fastly is serving a CAPTCHA challenge (cannot be solved by an automated client); sign in via a browser and paste the OAuth tokens instead")
	default:
		return nil, fmt.Errorf("unsupported challenge type %q", ch.Ty)
	}
}

func solvePow(base, targetHex string) (string, bool) {
	target, err := hex.DecodeString(targetHex)
	if err != nil || len(target) != sha256.Size {
		return "", false
	}
	buf := make([]byte, len(base)+2)
	copy(buf, base)
	for i := 0; i < len(powAlphabet); i++ {
		buf[len(base)] = powAlphabet[i]
		for j := 0; j < len(powAlphabet); j++ {
			buf[len(base)+1] = powAlphabet[j]
			sum := sha256.Sum256(buf)
			if bytes.Equal(sum[:], target) {
				return string(buf[len(base):]), true
			}
		}
	}
	return "", false
}

func fetchPAT(ctx context.Context, client *http.Client, prefixURL, token, userAgent string) (string, error) {
	patURL := prefixURL + "/pat?token=" + url.QueryEscape(token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, patURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Origin", baseOrigin(prefixURL))
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusBadRequest {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("PAT HTTP %d", resp.StatusCode)
	}
	var out struct {
		Auth string `json:"auth"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", err
	}
	return out.Auth, nil
}

func installCookies(solverJar http.CookieJar, pageURL string) error {
	parsed, err := url.Parse(pageURL)
	if err != nil {
		return err
	}
	cookies := solverJar.Cookies(parsed)
	if len(cookies) == 0 {
		return fmt.Errorf("challenge completed but no cookie issued")
	}
	apiURL, _ := url.Parse(AuthServer + "/")
	controlPlane.Jar.SetCookies(apiURL, cookies)
	siteURL, _ := url.Parse(fxaSiteURL)
	controlPlane.Jar.SetCookies(siteURL, cookies)
	return nil
}

func newJar() (http.CookieJar, error) {
	return cookiejar.New(nil)
}

func baseOrigin(prefixURL string) string {
	if idx := strings.Index(prefixURL, "/_fs-ch-"); idx > 0 {
		return prefixURL[:idx]
	}
	return prefixURL
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
