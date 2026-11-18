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
func (a *App) StartWGProxy(ctx context.Context, accessToken string, server WGServer) error {
	st, err := a.EnsureWGDevice(ctx, accessToken)
	if err != nil {
		return err
	}

	tun, err := DialWGTunnel(ctx, WGTunnelConfig{
		PrivateKey:  st.PrivKey,
		AddressIPv4: st.IPv4,
		AddressIPv6: st.IPv6,
		PeerPubKey:  server.PublicKey,
		Endpoint:    fmt.Sprintf("%s:%d", server.IPv4AddrIn, server.Port),
		AllowedIPs:  []string{"0.0.0.0/0", "::/0"},
		DNS:         []string{"10.64.0.1"},
	})
	if err != nil {
		return err
	}

	a.mu.Lock()
	if a.wgTunnel != nil {
		a.wgTunnel.Close()
	}
	a.wgTunnel = tun
	if a.proxySrv != nil {
		a.proxySrv.Close()
		a.proxySrv = nil
	}
	a.mu.Unlock()

	srv := &proxy.Server{
		Listen: a.ProxyAddr,
		Dial: func(ctx context.Context, dst string) (net.Conn, error) {
			network := "tcp"
			return tun.DialContext(ctx, network, dst)
		},
		DialUDP: func(ctx context.Context, host string, port int) (net.Conn, error) {
			// A UDP "session" over WireGuard is a datagram socket in the
			// netstack — net.Conn semantics fit the existing relay.
			return tun.DialContext(ctx, "udp", net.JoinHostPort(host, fmt.Sprint(port)))
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

// StopWG tears the WireGuard tunnel down (the SOCKS5 listener dies with it).
func (a *App) StopWG() {
	a.mu.Lock()
	t := a.wgTunnel
	a.wgTunnel = nil
	a.mu.Unlock()
	if t != nil {
		t.Close()
		log.Printf("proxy: WireGuard tunnel closed")
	}
}

// WGServer is one WireGuard-capable server from Guardian /api/v1/vpn/servers.
type WGServer struct {
	Hostname    string `json:"hostname"`
	IPv4AddrIn  string `json:"ipv4_addr_in"`
	IPv6AddrIn  string `json:"ipv6_addr_in"`
	PublicKey   string `json:"public_key"`
	Port        int    `json:"port"`
	Weight      int    `json:"weight"`
}

// ParseWGServers extracts the flat server list from the Guardian response
// ({"countries":[{name, code, cities:[{servers:[...]}]}]}).
func ParseWGServers(raw json.RawMessage) ([]WGServer, error) {
	var doc struct {
		Countries []struct {
			Name   string `json:"name"`
			Code   string `json:"code"`
			Cities []struct {
				Name    string `json:"name"`
				Code    string `json:"code"`
				Servers []WGServer `json:"servers"`
			} `json:"cities"`
		} `json:"countries"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var out []WGServer
	for _, c := range doc.Countries {
		for _, city := range c.Cities {
			out = append(out, city.Servers...)
		}
	}
	return out, nil
}

var _ = time.Now
