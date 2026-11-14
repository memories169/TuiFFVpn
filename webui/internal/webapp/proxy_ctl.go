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
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"fxsocks/webui/internal/fxa"
	"fxsocks/webui/internal/proxy"
)

// TestResult describes a successful connection check.
type TestResult struct {
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	ExitIP    string `json:"exit_ip,omitempty"`
	Country   string `json:"country,omitempty"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	Server    string `json:"server,omitempty"`
}

// startProxy (re)starts the SOCKS5 proxy against the given server with the
// given bearer proxy pass. The dialer keeps a bearerProvider closure so a
// CONNECT answered 401 (proxy pass expired) fetches a fresh pass through
// the Guardian chain and retries transparently.
//
// Important: the provider must NOT rebuild the SOCKS listener mid-flight —
// replacing a.proxySrv would close the listener under the very connection
// that triggered the refresh, killing it with "http2: client conn could
// not be established". It only refreshes tokens/pass in place and hands
// back the raw pass.
func (a *App) startProxy(host string, port int, bearer string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.proxySrv != nil {
		a.proxySrv.Close()
		a.proxySrv = nil
	}
	bearerProvider := func() (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		pass, err := a.refreshProxyPass(ctx)
		if err != nil {
			return "", err
		}
		a.mu.Lock()
		a.currentPass = pass.RawToken
		a.mu.Unlock()
		return pass.RawToken, nil
	}
	dial := proxy.HTTP2Dialer(host, port, bearer, bearerProvider)
	srv := &proxy.Server{Listen: a.ProxyAddr, Dial: dial}
	a.proxySrv = srv
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("proxy: %v", err)
		}
	}()
}

// proxyState describes the running proxy.
func (a *App) proxyState() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.proxySrv == nil {
		return map[string]any{"running": false}
	}
	return map[string]any{
		"running": true,
		"listen":  a.ProxyAddr,
		"server":  a.Store.Selected.ServerHost,
		"account": a.Store.Active,
	}
}

// stopProxyIfActiveAccount stops the proxy when it is running on the given
// (just-deleted) account.
func (a *App) stopProxyIfActiveAccount(email string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.Store.Active == email && a.proxySrv != nil {
		a.proxySrv.Close()
		a.proxySrv = nil
	}
}

// testProxy dials Cloudflare's trace endpoint through the running proxy tunnel
// and reports the public exit IP + country, proving traffic exits via the VPN.
func (a *App) testProxy() TestResult {
	a.mu.Lock()
	srv := a.proxySrv
	server := a.Store.Selected.ServerHost
	lastErr := a.lastErr
	a.mu.Unlock()

	if srv == nil {
		if lastErr != "" {
			return TestResult{OK: false, Error: "proxy did not start: " + lastErr, Server: server}
		}
		return TestResult{OK: false, Error: "no proxy running; select a location first", Server: server}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	start := time.Now()

	// Exit check via a real http.Client whose dialer goes through the tunnel.
	// http.Transport then performs the TLS handshake to www.cloudflare.com
	// itself *inside* the tunnel — the same pattern as the reference client's
	// verifyExit. (An earlier attempt passed DialTLSContext returning a raw
	// conn, which made the transport skip TLS and send plain HTTP to the :443
	// listener — hence Cloudflare's "The plain HTTP request was sent to
	// HTTPS port" 400 page.)
	tunnelDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return srv.Dial(ctx, addr)
	}
	client := &http.Client{
		Timeout: 18 * time.Second,
		Transport: &http.Transport{
			DialContext:           tunnelDial,
			TLSHandshakeTimeout:   10 * time.Second,
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: 10 * time.Second,
		},
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.cloudflare.com/cdn-cgi/trace", nil)
	if err != nil {
		return TestResult{OK: false, Error: "build request: " + err.Error(), Server: server}
	}
	httpReq.Header.Set("User-Agent", fxa.DefaultBrowserUA)
	httpReq.Header.Set("Accept", "text/plain, application/json")
	resp, err := client.Do(httpReq)
	if err != nil {
		// The tunnel dial itself can still fail (expired proxy pass etc.).
		msg := err.Error()
		if strings.Contains(msg, "parsing JWT failed") {
			msg = "proxy pass rejected by the edge (invalid/expired JWT) — re-select the location to fetch a fresh pass, or re-add the account"
		}
		return TestResult{OK: false, Error: "tunnel request failed: " + msg, Server: server}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	latency := time.Since(start).Milliseconds()

	ip, country := parseTrace(string(body))
	if ip == "" {
		// The tunnel is up but the inner response is not a Cloudflare trace.
		// Common causes: the edge cuts the inner stream for a quota-burned
		// account, a captive portal intercepting DNS, or an HTML error page.
		// Surface a snippet so the user can see what came back.
		snippet := fmt.Sprintf("HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
		if len(snippet) > 160 {
			snippet = snippet[:160] + "…"
		}
		return TestResult{OK: false, Error: "tunnel connected but no exit IP returned; inner response: " + snippet, Server: server, LatencyMS: latency}
	}
	return TestResult{OK: true, ExitIP: ip, Country: country, LatencyMS: latency, Server: server}
}

func parseTrace(body string) (ip, country string) {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "ip=") {
			ip = strings.TrimPrefix(line, "ip=")
		} else if strings.HasPrefix(line, "loc=") {
			country = strings.TrimPrefix(line, "loc=")
		}
	}
	return ip, country
}
