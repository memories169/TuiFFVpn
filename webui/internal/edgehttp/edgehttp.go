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

// Package edgehttp provides the process-wide control-plane HTTP transport.
//
// Firefox Accounts (api.accounts.firefox.com) and the Guardian API
// (vpn.mozilla.org) sit behind a Fastly edge whose anti-bot rules score
// every client by its TLS + HTTP/2 fingerprint (JA3/JA4, SETTINGS frame
// order, header pseudo-order). Go's default crypto/tls stack has one of
// the most-flagged fingerprints on those rulesets, so from a marginally
// suspicious IP the edge answers Go clients with HTTP 406 and escalates
// its challenge to an unsolvable CAPTCHA — while a real browser on the
// SAME IP sails through. That is exactly why the docker image and the
// desktop app behaved differently from the userscript on one LAN.
//
// The fix is to speak browser TLS: uTLS with a full Firefox ClientHello
// (same fingerprint stack the data-plane MASQUE dialer already uses in
// internal/proxy) carried over HTTP/2, wrapped behind a plain
// http.RoundTripper so every caller just sets Transport.
package edgehttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

var (
	once     sync.Once
	shared   http.RoundTripper
	buildErr error
)

// Transport returns the shared browser-like transport (Firefox uTLS
// ClientHello + HTTP/2). It is built lazily once per process; if the
// build ever fails the default Go transport is returned so callers never
// receive nil and calls keep working (just with the flaggable
// fingerprint).
func Transport() http.RoundTripper {
	once.Do(build)
	if shared != nil {
		return shared
	}
	return http.DefaultTransport
}

// BuildErr reports why the browser-like transport fell back to the
// default one, if it did (nil when uTLS is live).
func BuildErr() error {
	once.Do(build)
	return buildErr
}

func build() {
	dialTLS := func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		rawConn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		uconn := utls.UClient(rawConn, &utls.Config{
			ServerName: host,
			NextProtos: []string{"h2", "http/1.1"},
			MinVersion: utls.VersionTLS12,
		}, utls.HelloFirefox_Auto)
		if err := uconn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, err
		}
		// The http2.Transport below can only drive h2 connections.
		if uconn.ConnectionState().NegotiatedProtocol != "h2" {
			uconn.Close()
			return nil, fmt.Errorf("edgehttp: %s did not negotiate h2", addr)
		}
		return uconn, nil
	}

	shared = router{https: &http2.Transport{
		DialTLSContext:  dialTLS,
		ReadIdleTimeout: 30 * time.Second,
		PingTimeout:     15 * time.Second,
	}}
}

// router sends https requests through the browser-fingerprint transport and
// everything else (plain-http test servers, localhost consoles) through the
// default Go transport — the edge only fronts the https hosts.
type router struct{ https http.RoundTripper }

func (r router) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" {
		return r.https.RoundTrip(req)
	}
	return http.DefaultTransport.RoundTrip(req)
}
