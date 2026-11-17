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

package browsercapture

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// DefaultLoginURL is the Firefox Accounts page FoxyVPN loads: the REAL
// OAuth flow with the engine's client id (oauth_webchannel_v1 context
// makes the page talk WebChannel to the "browser" — our hook — and
// deliver an authorization code via fxaccounts:oauth_login at the end).
// The earlier fx_desktop_v3&service=sync entry was wrong for a
// non-Firefox browser: the page bounced itself to an OAuth URL it built
// from undefined variables (client_id=undefined...), which 400s the
// integration right after 2FA with "clientId ... isHexadecimal".
const DefaultLoginURL = "https://accounts.firefox.com/oauth/" +
	"?client_id=" + OAuthClientID +
	"&state=" + OAuthState +
	"&scope=" + OAuthURLEncodedScope +
	"&access_type=offline" +
	"&response_type=code" +
	"&context=oauth_webchannel_v1" +
	"&entrypoint=fxa_pairflow"

// OAuthClientID / OAuthState / OAuthURLEncodedScope are placeholders
// rewritten when the page is opened (see loginURL()).
const (
	OAuthClientID        = "__OAUTH_CLIENT_ID__"
	OAuthState           = "__OAUTH_STATE__"
	OAuthURLEncodedScope = "profile%20https%3A%2F%2Fidentity.mozilla.com%2Fapps%2Fvpn"
)

// loginURL builds the actual entry URL: the state placeholder becomes a
// fresh random value per run so the code can be tied to this capture.
func loginURL(state string) string {
	return strings.ReplaceAll(DefaultLoginURL, OAuthState, state)
}

// randomHex returns n random bytes, hex-encoded.
func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := crand.Read(buf); err != nil {
		// Crypto/rand failing is unrecoverable for a secure state value.
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(buf)
}

// HookBinding is the JS binding name the injected hook calls with the token.
const HookBinding = "__fxvpnSession"

// DefaultFirefoxUA is a current desktop Firefox user agent. The FxA page only
// enables the WebChannel fxa_status handshake when it believes it is running in
// Firefox, so the browser must present a Firefox UA rather than Chrome's.
const DefaultFirefoxUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0"

// Options configures a capture run.
type Options struct {
	// BrowserPath is the Chrome/Chromium executable. Empty means auto-detect.
	BrowserPath string
	// DebugPort is the DevTools port. 0 picks a free port.
	DebugPort int
	// Headless runs the browser without a window.
	Headless bool
	// UserDataDir is the browser profile directory. Empty means a temp dir.
	UserDataDir string
	// UserAgent overrides DefaultFirefoxUA.
	UserAgent string
	// LoginURL overrides DefaultLoginURL.
	LoginURL string
	// Timeout bounds the whole run.
	Timeout time.Duration
	// KeepBrowser leaves the browser running after a token is captured so the
	// caller can inspect it (only meaningful without Headless).
	KeepBrowser bool
	// AttachURL attaches to an already-running browser's DevTools endpoint
	// (for example http://127.0.0.1:9222) instead of launching one.
	AttachURL string
	// Validate optionally checks a captured token against FxA. When it returns
	// an error the token is discarded and capture keeps waiting.
	Validate ValidateFunc
	// ExtraArgs are appended to the browser command line. In a container the
	// useful set is `--no-sandbox --disable-dev-shm-usage --disable-gpu`.
	ExtraArgs []string
	// Logf receives progress messages.
	Logf func(format string, args ...any)
}

// Result is a captured Firefox Accounts session token.
type Result struct {
	SessionToken string   `json:"session_token"`
	Email        string   `json:"email,omitempty"`
	UID          string   `json:"uid,omitempty"`
	Verified     bool     `json:"verified"`
	Source       string   `json:"source"`
	UserAgent    string   `json:"-"`
	Cookies      []Cookie `json:"-"`
	// OAuthCode is set when the page delivered an fxaccounts:oauth_login
	// (the oauth_webchannel_v1 flow) instead of a raw sessionToken. The
	// caller exchanges it for OAuth tokens via the token endpoint.
	OAuthCode  string `json:"oauth_code,omitempty"`
	OAuthState string `json:"oauth_state,omitempty"`
}

// ValidateFunc verifies a captured token. cookies and userAgent are the
// browser context that produced it, which the control plane needs to get past
// the Fastly edge. Returning an error means the token is unusable and capture
// keeps waiting for another one.
type ValidateFunc func(ctx context.Context, sessionToken string, cookies []Cookie, userAgent string) (email string, uid string, verified bool, err error)

// ErrTimeout is returned when no token arrives before Options.Timeout.
var ErrTimeout = errors.New("timed out waiting for the Firefox Accounts session token")

// IsSessionToken reports whether s looks like a Firefox Accounts sessionToken
// (64 lowercase hex characters).
func IsSessionToken(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// Capture launches (or attaches to) a browser, hooks the FxA WebChannel and
// waits for a sessionToken or an OAuth authorization code. The returned
// browser handle lets the caller keep the window open so a human can type
// credentials.
func Capture(ctx context.Context, opts Options) (*Result, *Browser, error) {
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.LoginURL == "" {
		// Fresh state per run: the OAuth code is tied to it, so a code can
		// only be exchanged by the capture that started this browser.
		opts.LoginURL = loginURL(randomHex(16))
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Minute
	}

	browser, err := startBrowser(opts)
	if err != nil {
		return nil, nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	page, err := browser.newPage(ctx, opts.LoginURL)
	if err != nil {
		browser.Close()
		return nil, nil, err
	}
	if !opts.KeepBrowser {
		defer page.Close()
	}

	res, err := waitForToken(ctx, page, opts)
	if err != nil {
		if opts.KeepBrowser {
			browser.Pages = append(browser.Pages, page)
		} else {
			browser.Close()
		}
		return nil, browser, err
	}
	res.UserAgent = opts.UserAgent
	if res.UserAgent == "" {
		res.UserAgent = DefaultFirefoxUA
	}
	if cookies, err := page.CookiesFor(ctx); err == nil {
		res.Cookies = cookies
	}
	if opts.KeepBrowser {
		browser.Pages = append(browser.Pages, page)
	}
	return res, browser, nil
}

// Browser is a running Chrome/Chromium instance (or an attached one).
type Browser struct {
	DebugURL string
	Profile  string
	Pages    []*Page

	cmd   *exec.Cmd
	owned bool
	logf  func(string, ...any)
}

// Close stops the browser if this process launched it.
func (b *Browser) Close() {
	for _, p := range b.Pages {
		p.Close()
	}
	b.Pages = nil
	if b.owned && b.cmd != nil && b.cmd.Process != nil {
		_ = b.cmd.Process.Kill()
		_, _ = b.cmd.Process.Wait()
	}
}

// Page is one DevTools target.
type Page struct {
	ws   *cdpClient
	logf func(string, ...any)
}

// Close closes the page's DevTools connection.
func (p *Page) Close() { p.ws.close() }

func startBrowser(opts Options) (*Browser, error) {
	if opts.AttachURL != "" {
		base := strings.TrimRight(opts.AttachURL, "/")
		if err := waitForDevTools(context.Background(), base, 2*time.Second); err != nil {
			return nil, fmt.Errorf("attach to %s: %w", base, err)
		}
		return &Browser{DebugURL: base, logf: opts.Logf}, nil
	}

	path, err := findBrowser(opts.BrowserPath)
	if err != nil {
		return nil, err
	}

	profile := opts.UserDataDir
	if profile == "" {
		dir, err := os.MkdirTemp("", "fxvpn-profile-")
		if err != nil {
			return nil, err
		}
		profile = dir
	}

	port := opts.DebugPort
	if port == 0 {
		port, err = freePort()
		if err != nil {
			return nil, err
		}
	}

	ua := opts.UserAgent
	if ua == "-" {
		// "-" disables the spoof entirely (the browser keeps its own UA).
		ua = ""
	} else if ua == "" {
		ua = DefaultFirefoxUA
	}

	// --disable-gpu and --disable-dev-shm-usage are harmless on a desktop and
	// required in most containers (no GPU device, tiny /dev/shm).
	args := []string{
		"--remote-debugging-port=" + strconv.Itoa(port),
		"--remote-debugging-address=127.0.0.1",
		"--user-data-dir=" + profile,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-background-networking",
		"--disable-features=Translate,MediaRouter",
		"--disable-sync",
		"--disable-gpu",
		"--disable-dev-shm-usage",
		"--user-agent=" + ua,
	}
	args = append(args, opts.ExtraArgs...)
	args = append(args, aboutBlank)
	if opts.Headless {
		args = append([]string{"--headless=new", "--hide-scrollbars", "--mute-audio"}, args...)
	}
	if needsNoSandbox(opts) {
		args = append([]string{"--no-sandbox"}, args...)
	}

	cmd := exec.Command(path, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start browser %s: %w", path, err)
	}
	b := &Browser{
		DebugURL: fmt.Sprintf("http://127.0.0.1:%d", port),
		Profile:  profile,
		cmd:      cmd,
		owned:    true,
		logf:     opts.Logf,
	}
	if err := waitForDevTools(context.Background(), b.DebugURL, 30*time.Second); err != nil {
		b.Close()
		return nil, fmt.Errorf("wait for browser DevTools: %w", err)
	}
	opts.Logf("browser started: %s (profile %s)", path, profile)
	return b, nil
}

const aboutBlank = "about:blank"

// needsNoSandbox reports whether Chromium must be started with --no-sandbox.
// That is required as root (Chromium refuses to run), inside most containers
// where user namespaces are unavailable, or when the operator asks for it.
func needsNoSandbox(opts Options) bool {
	if os.Geteuid() == 0 {
		return true
	}
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("FXVPN_NO_SANDBOX"))); v == "1" || v == "true" || v == "yes" {
		return true
	}
	for _, a := range opts.ExtraArgs {
		if a == "--no-sandbox" {
			return true
		}
	}
	// Chromium cannot create its sandbox when user namespaces are disabled,
	// which is the default in Docker.
	if data, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil {
		if strings.TrimSpace(string(data)) == "0" {
			return true
		}
	}
	if data, err := os.ReadFile("/proc/sys/user/max_user_namespaces"); err == nil {
		if strings.TrimSpace(string(data)) == "0" {
			return true
		}
	}
	return false
}

// findBrowser locates a Chromium-family executable.
func findBrowser(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("browser %q: %w", explicit, err)
		}
		return explicit, nil
	}
	if env := os.Getenv("FXVPN_BROWSER"); env != "" {
		return findBrowser(env)
	}
	candidates := []string{
		"google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
		"chrome", "microsoft-edge", "brave-browser", "headless_shell",
		// Helium (https://github.com/imputnet/helium) — privacy-hardened
		// Chromium fork; its binary and desktop entry are "helium".
		"helium", "helium-browser",
	}
	for _, name := range candidates {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	for _, p := range []string{
		"/usr/bin/google-chrome", "/usr/local/bin/google-chrome",
		"/usr/bin/chromium", "/usr/bin/chromium-browser",
		// Helium install locations (official .deb/AppImage / make install).
		"/usr/bin/helium", "/usr/local/bin/helium", "/opt/helium/helium",
		// macOS bundle layouts (Chrome/Chromium/Edge/Brave/Helium).
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
		"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
		"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
		"/Applications/Helium.app/Contents/MacOS/Helium",
		// Windows install layouts (per-user %LOCALAPPDATA% and system-wide).
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files\Chromium\Application\chrome.exe`,
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe`,
	} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", errors.New("no Chrome/Chromium found; set -browser or FXVPN_BROWSER")
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitForDevTools(ctx context.Context, base string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 750 * time.Millisecond}
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/json/version", nil)
		if err == nil {
			if resp, err := client.Do(req); err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errors.New("DevTools endpoint did not become ready")
}

// newPage opens a target, installs the WebChannel hook and navigates.
func (b *Browser) newPage(ctx context.Context, targetURL string) (*Page, error) {
	ws, err := b.openTarget(ctx)
	if err != nil {
		return nil, err
	}
	p := &Page{ws: ws, logf: b.logf}

	if err := p.setup(ctx, targetURL); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}

// openTarget creates a fresh DevTools target and connects to it. A target may
// die between creation and the websocket dial (or the websocket may already be
// claimed), so it retries a few times before giving up.
func (b *Browser) openTarget(ctx context.Context) (*cdpClient, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, b.DebugURL+"/json/new?"+aboutBlank, nil)
		if err != nil {
			return nil, err
		}
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			lastErr = fmt.Errorf("open browser target: %w", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			lastErr = fmt.Errorf("open browser target: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
			time.Sleep(500 * time.Millisecond)
			continue
		}
		var target struct {
			ID                   string `json:"id"`
			WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
		}
		err = json.NewDecoder(resp.Body).Decode(&target)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("decode browser target: %w", err)
			continue
		}
		if target.WebSocketDebuggerURL == "" {
			lastErr = errors.New("browser target has no DevTools websocket")
			continue
		}

		ws, err := dialCDP(ctx, target.WebSocketDebuggerURL)
		if err == nil {
			return ws, nil
		}
		lastErr = err
		// The freshly created target may already be gone (renderer crash,
		// claim race): a short pause then a brand-new target usually clears it.
		time.Sleep(500 * time.Millisecond)
	}
	return nil, lastErr
}

// setup enables the domains, installs the WebChannel hook and navigates.
func (p *Page) setup(ctx context.Context, targetURL string) error {
	// Network domain: intercept /account/login and /oauth/token responses
	// directly. The WebChannel handshake is the primary capture path, but
	// Chromium doesn't speak WebChannel natively and the content server's
	// handshake expectations vary — the login XHR response carries the same
	// sessionToken regardless, so sniffing it makes capture work even when
	// the page-side flow stalls.
	for _, method := range []string{"Page.enable", "Runtime.enable", "Network.enable"} {
		if err := p.ws.call(ctx, method, map[string]any{}, nil); err != nil {
			return err
		}
	}
	if err := p.ws.call(ctx, "Runtime.addBinding", map[string]any{"name": HookBinding}, nil); err != nil {
		return err
	}
	if err := p.ws.call(ctx, "Page.addScriptToEvaluateOnNewDocument", map[string]any{
		"source": hookScript,
	}, nil); err != nil {
		return err
	}
	if err := p.ws.call(ctx, "Page.navigate", map[string]any{"url": targetURL}, nil); err != nil {
		return err
	}
	return nil
}

// evaluate runs an expression and returns its value as JSON.
func (p *Page) evaluate(ctx context.Context, expression string) (json.RawMessage, error) {
	var out struct {
		Result struct {
			Type  string          `json:"type"`
			Value json.RawMessage `json:"value"`
		} `json:"result"`
		ExceptionDetails *struct {
			Text string `json:"text"`
		} `json:"exceptionDetails"`
	}
	err := p.ws.call(ctx, "Runtime.evaluate", map[string]any{
		"expression":    expression,
		"returnByValue": true,
		"awaitPromise":  true,
	}, &out)
	if err != nil {
		return nil, err
	}
	if out.ExceptionDetails != nil {
		return nil, fmt.Errorf("page evaluation failed: %s", out.ExceptionDetails.Text)
	}
	return out.Result.Value, nil
}

// pollScript reads any token the hook stashed plus the FxA localStorage
// account entry. It is deliberately defensive: storage may be unavailable or
// still empty while the page is loading.
const pollScript = `(() => {
  try {
    const out = { token: '', email: '', uid: '', source: '', oauthCode: '', oauthState: '' };
    if (window.__fxvpnCapture) {
      const c = window.__fxvpnCapture;
      if (c.token) {
        out.token = c.token;
        out.email = c.email || '';
        out.uid = c.uid || '';
        out.source = c.source || 'webchannel';
      } else if (c.oauthCode) {
        out.oauthCode = c.oauthCode;
        out.oauthState = c.oauthState || '';
        out.email = c.email || '';
        out.source = c.source || 'webchannel';
      }
    }
    if (!out.token && !out.oauthCode) {
      const accounts = JSON.parse(localStorage.getItem('__fxa_storage.accounts') || '{}');
      const uid = localStorage.getItem('__fxa_storage.currentAccountUid');
      const rawUid = uid ? JSON.parse(uid) : '';
      const entry = accounts[rawUid] || Object.values(accounts)[0];
      if (entry && entry.sessionToken && /^[0-9a-f]{64}$/.test(entry.sessionToken)) {
        out.token = entry.sessionToken;
        out.email = entry.email || '';
        out.uid = entry.uid || '';
        out.source = 'localStorage';
      }
    }
    return out;
  } catch (e) {
    return { token: '', email: '', uid: '', source: '', oauthCode: '', oauthState: '' };
  }
})()`

// hookScript runs in every new document before the page's own scripts. It
// mirrors FoxyVPN's WebView bridge: capture the sessionToken from the FxA
// WebChannel and answer the browser-identification commands so the page
// continues down the fx_desktop_v3 flow.
const hookScript = `(function () {
  if (window.__fxvpnHooked) return;
  window.__fxvpnHooked = true;
  var SESSION_HEX = /^[0-9a-f]{64}$/;
  var CHANNEL = 'account_updates';
  var LOG = '[fxvpn ' + new Date().toISOString() + ' url=' + location.href + ']';

  function dbg(msg, obj) {
    try { console.log(LOG + ' ' + msg, obj === undefined ? '' : obj); } catch (e) {}
  }
  dbg('hook installed (build f07f0c6+)');

  function emit(token, command, data) {
    token = String(token || '').trim().toLowerCase();
    if (!SESSION_HEX.test(token)) return;
    var info = {
      token: token,
      email: (data && data.email) || '',
      uid: (data && data.uid) || '',
      command: command
    };
    window.__fxvpnCapture = {
      token: token,
      email: info.email,
      uid: info.uid,
      source: 'webchannel:' + command,
      at: Date.now()
    };
    try { if (window.__fxvpnSession) window.__fxvpnSession(JSON.stringify(info)); } catch (e) {}
    try { console.log('[fxvpn] sessionToken captured via ' + command); } catch (e) {}
  }

  // emitOAuthCode captures the authorization code delivered by the
  // oauth_webchannel_v1 flow (fxaccounts:oauth_login carries { code,
  // state }). The caller exchanges the code for OAuth tokens.
  function emitOAuthCode(command, data) {
    var code = String((data && data.code) || '').trim();
    if (!/^[A-Za-z0-9_-]{20,}$/.test(code)) return;
    var info = {
      code: code,
      state: (data && data.state) || '',
      email: (data && data.email) || '',
      command: command
    };
    window.__fxvpnCapture = {
      oauthCode: code,
      oauthState: info.state,
      email: info.email,
      source: 'webchannel:' + command,
      at: Date.now()
    };
    try { if (window.__fxvpnSession) window.__fxvpnSession(JSON.stringify(info)); } catch (e) {}
    try { console.log('[fxvpn] oauth code captured via ' + command); } catch (e) {}
  }

  // --- XHR/fetch sniffer -------------------------------------------------
  // The content server returns the sessionToken in the /account/login (and
  // /oauth/token) response body. In Chromium the WebChannel handshake can
  // stall the page flow, but the XHR still completes — sniff the body and
  // grab the token from there. Wraps instances (not the prototype): FxA's
  // browser.ts patches XHR methods on the instance and a prototype-level
  // defineProperty recursion blew the stack (RangeError: Maximum call
  // stack size exceeded).
  function sniff(text) {
    try {
      if (!text || typeof text !== 'string' || text.length > 100000) return;
      var body = JSON.parse(text);
      var tok = body.sessionToken || (body.data && body.data.sessionToken) || '';
      if (!tok) return;
      emit(tok, 'xhr:' + (body.grant_type || 'login'), body);
    } catch (e) { /* not JSON or not a login response — ignore */ }
  }
  if (window.XMLHttpRequest) {
    var RealXHR = window.XMLHttpRequest;
    var sniffOnLoad = function () {
      try { if (this.readyState === 4 && this.responseText) sniff(this.responseText); } catch (e) {}
    };
    window.XMLHttpRequest = function () {
      var xhr = new RealXHR();
      xhr.addEventListener('load', sniffOnLoad);
      return xhr;
    };
    window.XMLHttpRequest.prototype = RealXHR.prototype;
    // Keep statics like UNSENT/DONE intact on the wrapper.
    ['UNSENT', 'OPENED', 'HEADERS_RECEIVED', 'LOADING', 'DONE'].forEach(function (k) {
      try { window.XMLHttpRequest[k] = RealXHR[k]; } catch (e) {}
    });
  }
  var origFetch = window.fetch;
  if (origFetch) {
    window.fetch = function () {
      var args = arguments;
      return origFetch.apply(this, args).then(function (resp) {
        try {
          var url = (resp && resp.url) || String(args[0] || '');
          if (url.indexOf('/account/login') !== -1 || url.indexOf('/oauth/token') !== -1) {
            resp.clone().text().then(sniff).catch(function () {});
          }
        } catch (e) {}
        return resp;
      });
    };
  }

  function parse(detail) {
    var envelope = detail;
    if (typeof envelope === 'string') {
      try { envelope = JSON.parse(envelope); } catch (e) { return null; }
    }
    if (!envelope) return null;
    var message = envelope.message || envelope;
    if (typeof message === 'string') {
      try { message = JSON.parse(message); } catch (e) { return null; }
    }
    if (!message || !message.command) return null;
    return { envelope: envelope, message: message };
  }

  function onChromeEvent(e) {
    var parsed = parse(e && e.detail);
    if (!parsed) return;
    if (parsed.envelope.__fxvpnReply) return;
    var message = parsed.message;
    var command = String(message.command);
    var data = message.data || message.params || {};
    dbg('WebChannel event: ' + command, { messageId: message.messageId, keys: Object.keys(data || {}) });
    var token = data.sessionToken || data.token || '';
    if (token) {
      emit(token, command, data);
      return;
    }
    // OAuth native flow: the oauth_webchannel_v1 page delivers the
    // authorization code here at sign-in completion.
    if (command === 'fxaccounts:oauth_login') {
      emitOAuthCode(command, data);
      return;
    }
    // The page asks the browser questions on the ToChrome channel — this
    // hook IS the browser now, so answer here. Previously the replies were
    // wired to onContentEvent (a channel the page never sends questions
    // on), so fxa_status and can_link_account were never answered and the
    // trusted fx_desktop_v3 flow stalled at the email step with a greyed
    // sign-in button.
    var id = parsed.envelope.id || CHANNEL;
    var messageId = message.messageId || parsed.envelope.messageId || '';
    if (!messageId) return;
    var key = command + ':' + messageId;
    if (replied[key]) return;
    replied[key] = true;
    if (command === 'fxaccounts:fxa_status') {
      // Minimal sync-context reply: a real Firefox desktop answers a
      // plain fx_desktop_v3&service=sync page with NO clientId and NO
      // OAuth capabilities — those fields only exist when the channel
      // belongs to an OAuth relying party. Advertising a clientId (even
      // a valid hex one) makes the page spin up its OAuth native
      // integration, whose model validation then 400s the flow right
      // after 2FA ("property clientId ... isHexadecimal"). Omitting the
      // field keeps the page on the sync path, which delivers the
      // session via fxaccounts:login / the login XHR — both captured.
      reply(id, messageId, command, {
        capabilities: {},
        signedInUser: null
      });
      return;
    }
    if (command === 'fxaccounts:can_link_account') {
      reply(id, messageId, command, { ok: true });
      return;
    }
    reply(id, messageId, command, { ok: true });
  }

  function reply(id, messageId, command, data) {
    var detail = {
      id: id,
      __fxvpnReply: true,
      message: { messageId: messageId, command: command, data: data }
    };
    dbg('reply -> ' + command, data);
    try { window.dispatchEvent(new CustomEvent('WebChannelMessageToContent', { detail: detail })); } catch (e) {}
    try { document.dispatchEvent(new CustomEvent('WebChannelMessageToContent', { detail: detail })); } catch (e) {}
  }

  var replied = {};

  function onContentEvent(e) {
    // Some FxA builds dispatch page->browser messages on the Content
    // channel too (channel name mismatch between builds) — treat those as
    // chrome events so the token emit and replies still work.
    onChromeEvent(e);
  }

  window.addEventListener('WebChannelMessageToChrome', onChromeEvent, true);
  document.addEventListener('WebChannelMessageToChrome', onChromeEvent, true);
  window.addEventListener('WebChannelMessageToContent', onContentEvent, true);
  document.addEventListener('WebChannelMessageToContent', onContentEvent, true);
})();`

// waitForToken polls the page and listens to the binding until a valid token
// appears.
func waitForToken(ctx context.Context, page *Page, opts Options) (*Result, error) {
	tried := make(map[string]bool)

	accept := func(ctx context.Context, token, email, uid, source string) (*Result, bool) {
		token = strings.ToLower(strings.TrimSpace(token))
		if !IsSessionToken(token) || tried[token] {
			return nil, false
		}
		tried[token] = true
		opts.Logf("captured candidate sessionToken (%s)", source)
		if opts.Validate != nil {
			cookies, _ := page.CookiesFor(ctx)
			vEmail, vUID, verified, err := opts.Validate(ctx, token, cookies, opts.UserAgent)
			if err != nil {
				opts.Logf("token rejected by FxA: %v", err)
				return nil, false
			}
			if email == "" {
				email = vEmail
			}
			if uid == "" {
				uid = vUID
			}
			return &Result{SessionToken: token, Email: email, UID: uid, Verified: verified, Source: source}, true
		}
		return &Result{SessionToken: token, Email: email, UID: uid, Source: source}, true
	}

	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ErrTimeout
		case msg, ok := <-page.ws.events:
			if !ok {
				return nil, errors.New("browser page closed before a token was captured")
			}
			if msg.Method != "Runtime.bindingCalled" {
				continue
			}
			var ev struct {
				Name    string `json:"name"`
				Payload string `json:"payload"`
			}
			if err := json.Unmarshal(msg.Params, &ev); err != nil || ev.Name != HookBinding {
				continue
			}
			var info struct {
				Token   string `json:"token"`
				Email   string `json:"email"`
				UID     string `json:"uid"`
				Source  string `json:"source"`
				Command string `json:"command"`
				// OAuth code fields (fxaccounts:oauth_login delivery).
				OAuthCode  string `json:"code"`
				OAuthState string `json:"state"`
			}
			payload := ev.Payload
			if err := json.Unmarshal([]byte(payload), &info); err == nil && info.OAuthCode != "" {
				source := info.Source
				if source == "" {
					source = "webchannel:" + info.Command
				}
				opts.Logf("captured OAuth authorization code (%s)", source)
				return &Result{
					OAuthCode:  info.OAuthCode,
					OAuthState: info.OAuthState,
					Email:      info.Email,
					Source:     source,
				}, nil
			}
			if err := json.Unmarshal([]byte(payload), &info); err == nil && info.Token != "" {
				source := info.Source
				if source == "" {
					source = "webchannel:" + info.Command
				}
				if res, ok := accept(ctx, info.Token, info.Email, info.UID, source); ok {
					return res, nil
				}
				continue
			}
			if res, ok := accept(ctx, payload, "", "", "webchannel"); ok {
				return res, nil
			}
		case <-ticker.C:
			raw, err := page.evaluate(ctx, pollScript)
			if err != nil {
				continue
			}
			var st struct {
				Token      string `json:"token"`
				Email      string `json:"email"`
				UID        string `json:"uid"`
				Source     string `json:"source"`
				OAuthCode  string `json:"oauthCode"`
				OAuthState string `json:"oauthState"`
			}
			if err := json.Unmarshal(raw, &st); err != nil {
				continue
			}
			if st.OAuthCode != "" {
				opts.Logf("captured OAuth authorization code (%s)", st.Source)
				return &Result{
					OAuthCode:  st.OAuthCode,
					OAuthState: st.OAuthState,
					Email:      st.Email,
					Source:     st.Source,
				}, nil
			}
			if res, ok := accept(ctx, st.Token, st.Email, st.UID, st.Source); ok {
				return res, nil
			}
		}
	}
}
