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

// WireGuard mode: register a device with Guardian, connect over the
// userspace netstack tunnel, and expose SOCKS5 on it. Unlike the MASQUE
// proxy-pass path, WireGuard carries real IP packets — udp:// trackers,
// DHT, QUIC, everything — with no edge destination allowlist.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"runtime"
	"strings"
	"time"

	"fxsocks/webui/internal/guardian"
	"fxsocks/webui/internal/proxy"
	"fxsocks/webui/internal/state"
)

// EnsureWGDevice returns the registered WireGuard device for the active
// account, registering (or re-registering after an account switch) as
// needed. The FxA OAuth access token for the ACTIVE account is used, same
// as the official client.
func (a *App) EnsureWGDevice(ctx context.Context, accessToken string) (*state.WGDeviceState, error) {
	a.mu.Lock()
	email := a.Store.Active
	existing := a.Store.WGDevice
	a.mu.Unlock()

	if existing != nil && existing.Email == email && existing.PrivKey != "" {
		return existing, nil
	}

	// Generate (or reuse an orphaned keypair if the email matches but the
	// registration was interrupted) and register with Guardian.
	keys, err := GenerateWGKeys()
	if err != nil {
		return nil, err
	}
	host := DeviceName()
	gc := guardianClientFor(a, accessToken)
	dev, err := gc.RegisterDevice(ctx, host, a.uniqueID(), keys.Public)
	if err != nil {
		return nil, err
	}

	st := &state.WGDeviceState{
		Name:      host,
		UniqueID:  a.uniqueID(),
		PrivKey:   keys.Private,
		PubKey:    keys.Public,
		IPv4:      dev.IPv4,
		IPv6:      dev.IPv6,
		Email:     email,
		CreatedAt: dev.CreatedAt,
	}
	a.mu.Lock()
	a.Store.WGDevice = st
	err = a.Store.Save()
	a.mu.Unlock()
	if err != nil {
		return st, fmt.Errorf("save wg device: %w", err)
	}
	log.Printf("webui: WireGuard device registered for %s — tunnel %s", email, st.IPv4)
	return st, nil
}

// guardianClientFor builds a Guardian client bound to the given FxA token.
func guardianClientFor(a *App, accessToken string) *guardian.Client {
	return &guardian.Client{Endpoint: a.Guardian, Token: accessToken}
}

// uniqueID returns a stable per-installation device id: reuse the previous
// registration's id when present (Guardian dedupes on it), else derive a
// stable one from the admin creation timestamp.
func (a *App) uniqueID() string {
	if a.Store.WGDevice != nil && a.Store.WGDevice.UniqueID != "" {
		return a.Store.WGDevice.UniqueID
	}
	return fmt.Sprintf("fxvpn-%x", a.Store.Admin.ChangedAt.UnixNano())
}

// DeviceName mirrors the official client ("<hostname> <os> <version>").
func DeviceName() string { return "fxvpn " + runtime.GOOS }

// StartWGProxy connects the WireGuard tunnel to the given server and serves
// SOCKS5 through it. a.mu must NOT be held.
func (a *App) StartWGProxy(ctx context.Context, accessToken string, server state.WGServerInfo) error {
	st, err := a.EnsureWGDevice(ctx, accessToken)
	if err != nil {
		return err
	}

	// DNS: the server's in-tunnel gateway (what the official client uses:
	// exitConfig.m_dnsServer = exitServer.ipv4Gateway()); fallback to
	// Guardian's block-ads resolver range at 100.64.0.1.
	dns := server.IPv4Gateway
	if dns == "" {
		dns = "100.64.0.1"
	}
	tun, err := DialWGTunnel(ctx, WGTunnelConfig{
		PrivateKey:  st.PrivKey,
		AddressIPv4: st.IPv4,
		AddressIPv6: st.IPv6,
		PeerPubKey:  server.PublicKey,
		Endpoint:    fmt.Sprintf("%s:%d", server.IPv4AddrIn, server.Port),
		AllowedIPs:  []string{"0.0.0.0/0", "::/0"},
		DNS:         []string{dns},
	})
	if err != nil {
		return err
	}

	a.mu.Lock()
	if a.wgTunnel != nil {
		a.wgTunnel.Close()
	}
	a.wgTunnel = tun
	a.wgMode = true // keeper/rotator must not replace this with MASQUE
	a.Store.WGLastServer = &server
	_ = a.Store.Save()
	if a.proxySrv != nil {
		a.proxySrv.Close()
		a.proxySrv = nil
	}
	a.mu.Unlock()

	// earlyDialRetries: the first dial races the WG handshake (and the
	// netstack's first DNS query to the in-tunnel resolver), so the first
	// attempt or two may fail with timeouts. Retry briefly instead of
	// failing the announce/download outright.
	srv := &proxy.Server{
		Listen: a.ProxyAddr,
		Dial: func(ctx context.Context, dst string) (net.Conn, error) {
			var lastErr error
			for attempt := 0; attempt < 3; attempt++ {
				c, err := tun.DialContext(ctx, "tcp", dst)
				if err == nil {
					return c, nil
				}
				lastErr = err
				if !wgRetryable(err) || ctx.Err() != nil {
					return nil, err
				}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(time.Duration(attempt+1) * 500 * time.Millisecond):
				}
			}
			return nil, lastErr
		},
		DialUDP: func(ctx context.Context, host string, port int) (net.Conn, error) {
			// A UDP "session" over WireGuard is a datagram socket in the
			// netstack — net.Conn semantics fit the existing relay.
			dst := net.JoinHostPort(host, fmt.Sprint(port))
			var lastErr error
			for attempt := 0; attempt < 3; attempt++ {
				c, err := tun.DialContext(ctx, "udp", dst)
				if err == nil {
					return c, nil
				}
				lastErr = err
				if !wgRetryable(err) || ctx.Err() != nil {
					return nil, err
				}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(time.Duration(attempt+1) * 500 * time.Millisecond):
				}
			}
			return nil, lastErr
		},
		UDPEndpoint: func() (string, int) { return server.IPv4AddrIn, server.Port },
	}
	a.mu.Lock()
	a.proxySrv = srv
	a.mu.Unlock()
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("proxy: %v", err)
		}
	}()
	log.Printf("proxy: WireGuard tunnel up on %s → %s (%s:%d udp+tcp); SOCKS5 on %s",
		st.IPv4, server.PublicKey[:8]+"…", server.IPv4AddrIn, server.Port, a.ProxyAddr)
	return nil
}

// RestoreWGOnBoot re-establishes the WireGuard tunnel from the persisted
// device + last server — no pass renewal needed (WG device keys don't
// expire; the tunnel key is the device key). Called from startRotator's
// boot path when WG mode was the last-used transport.
func (a *App) RestoreWGOnBoot(ctx context.Context) error {
	a.mu.Lock()
	sel := a.Store.WGLastServer
	email := a.Store.Active
	a.mu.Unlock()
	if sel == nil || sel.PublicKey == "" {
		log.Printf("boot: no WireGuard server recorded — skip WG restore")
		return nil
	}
	a.mu.Lock()
	active := a.Store.ActiveAccount()
	var access string
	if active != nil {
		access = active.AccessToken
	}
	a.mu.Unlock()
	if access == "" {
		return fmt.Errorf("wg restore: no active account")
	}
	_ = email
	// Token may be stale — activeAccessToken refreshes through the normal
	// gate; registration is idempotent so EnsureWGDevice is safe to re-run.
	if err := a.ConnectWGWithServer(ctx, access, *sel); err != nil {
		return err
	}
	log.Printf("boot: WireGuard tunnel restored on %s (%s:%d)", sel.Hostname, sel.IPv4AddrIn, sel.Port)
	return nil
}

// ConnectWGWithServer is ConnectWG pinned to a specific server.
func (a *App) ConnectWGWithServer(ctx context.Context, accessToken string, server state.WGServerInfo) error {
	if _, err := a.EnsureWGDevice(ctx, accessToken); err != nil {
		return fmt.Errorf("wg: device: %w", err)
	}
	a.mu.Lock()
	if a.edgeDialer != nil {
		a.edgeDialer.Close()
		a.edgeDialer = nil
	}
	a.mu.Unlock()
	return a.StartWGProxy(ctx, accessToken, server)
}

// InWGMode reports whether the WireGuard transport is currently selected.
func (a *App) InWGMode() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.wgMode
}

// wgRetryable reports whether a netstack dial error is worth retrying
// (handshake racing, transient netstack state) as opposed to a hard refusal.
func wgRetryable(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, s := range []string{"timeout", "connection refused", "no route", "i/o timeout", "network is unreachable"} {
		if strings.Contains(strings.ToLower(msg), s) {
			return true
		}
	}
	return false
}

// StopWG tears the WireGuard tunnel down (the SOCKS5 listener dies with it).
func (a *App) StopWG() {
	a.mu.Lock()
	t := a.wgTunnel
	a.wgTunnel = nil
	a.wgMode = false
	a.mu.Unlock()
	if t != nil {
		t.Close()
		log.Printf("proxy: WireGuard tunnel closed")
	}
}

// ParseWGServers extracts the flat server list from the Guardian response
// ({"countries":[{name, code, cities:[{servers:[...]}]}]}).
func ParseWGServers(raw json.RawMessage) ([]state.WGServerInfo, error) {
	var doc struct {
		Countries []struct {
			Name   string `json:"name"`
			Code   string `json:"code"`
			Cities []struct {
				Name    string `json:"name"`
				Code    string `json:"code"`
				Servers []state.WGServerInfo `json:"servers"`
			} `json:"cities"`
		} `json:"countries"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var out []state.WGServerInfo
	for _, c := range doc.Countries {
		for _, city := range c.Cities {
			out = append(out, city.Servers...)
		}
	}
	return out, nil
}

var _ = time.Now
