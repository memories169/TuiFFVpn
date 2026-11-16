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

// DefaultLoginURL is the Firefox Accounts page FoxyVPN loads. The
// fx_desktop_v3 context makes the page treat the browser as Firefox and emit
// the fxaccounts:login WebChannel message that carries the sessionToken.
const DefaultLoginURL = "https://accounts.firefox.com/?context=fx_desktop_v3&service=sync&action=email"

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
// waits for a sessionToken. The returned browser handle lets the caller keep
// the window open so a human can type credentials.
func Capture(ctx context.Context, opts Options) (*Result, *Browser, error) {
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.LoginURL == "" {
		opts.LoginURL = DefaultLoginURL
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
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
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
	for _, method := range []string{"Page.enable", "Runtime.enable"} {
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
    const out = { token: '', email: '', uid: '', source: '' };
    if (window.__fxvpnCapture && window.__fxvpnCapture.token) {
      out.token = window.__fxvpnCapture.token;
      out.email = window.__fxvpnCapture.email || '';
      out.uid = window.__fxvpnCapture.uid || '';
      out.source = window.__fxvpnCapture.source || 'webchannel';
    }
    if (!out.token) {
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
    return { token: '', email: '', uid: '', source: '' };
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
    var message = parsed.message;
    var data = message.data || message.params || {};
    var token = data.sessionToken || data.token || '';
    if (token) emit(token, String(message.command), data);
  }

  function reply(id, messageId, command, data) {
    var detail = {
      id: id,
      __fxvpnReply: true,
      message: { messageId: messageId, command: command, data: data }
    };
    try { window.dispatchEvent(new CustomEvent('WebChannelMessageToContent', { detail: detail })); } catch (e) {}
    try { document.dispatchEvent(new CustomEvent('WebChannelMessageToContent', { detail: detail })); } catch (e) {}
  }

  var replied = {};

  function onContentEvent(e) {
    var parsed = parse(e && e.detail);
    if (!parsed) return;
    if (parsed.envelope.__fxvpnReply) return;
    var message = parsed.message;
    var command = String(message.command);
    var id = parsed.envelope.id || CHANNEL;
    var messageId = message.messageId || parsed.envelope.messageId || '';
    if (!messageId) return;
    var key = command + ':' + messageId;
    if (replied[key]) return;
    replied[key] = true;
    if (command === 'fxaccounts:fxa_status') {
      reply(id, messageId, command, { capabilities: {}, signedInUser: null, clientId: '' });
      return;
    }
    if (command === 'fxaccounts:can_link_account') {
      reply(id, messageId, command, { ok: true });
      return;
    }
    reply(id, messageId, command, { ok: true });
  }

  window.addEventListener('WebChannelMessageToChrome', onChromeEvent, true);
  document.addEventListener('WebChannelMessageToChrome', onChromeEvent, true);
  window.addEventListener('WebChannelMessageToContent', onContentEvent, true);
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
			}
			payload := ev.Payload
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
				Token  string `json:"token"`
				Email  string `json:"email"`
				UID    string `json:"uid"`
				Source string `json:"source"`
			}
			if err := json.Unmarshal(raw, &st); err != nil {
				continue
			}
			if res, ok := accept(ctx, st.Token, st.Email, st.UID, st.Source); ok {
				return res, nil
			}
		}
	}
}
