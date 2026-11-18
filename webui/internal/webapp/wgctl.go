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

// wgctl.go — the control path for WireGuard mode: resolve the active
// account's access token, register the device, fetch the WG server list,
// and bring the SOCKS5 proxy up over the userspace tunnel.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"

	"fxsocks/webui/internal/guardian"
	"fxsocks/webui/internal/state"
)

// ConnectWG brings the WireGuard tunnel up and replaces the SOCKS5 backend
// (the MASQUE dialer is torn down — one transport at a time on a.Port).
func (a *App) ConnectWG(ctx context.Context) error {
	// Resolve the active account's (fresh) FxA access token.
	tok, err := a.activeAccessToken(ctx)
	if err != nil {
		return fmt.Errorf("wg: active token: %w", err)
	}

	// Register (or reuse) the WireGuard device for this account.
	dev, err := a.EnsureWGDevice(ctx, tok)
	if err != nil {
		return fmt.Errorf("wg: device: %w", err)
	}

	// Pick a WG-capable server: same city as the MASQUE selection when
	// possible, else weighted-random over everything Guardian offers.
	server, err := a.pickWGServer(ctx, tok)
	if err != nil {
		return fmt.Errorf("wg: server: %w", err)
	}

	// Tear the MASQUE transport down and stand the WG one up.
	a.mu.Lock()
	if a.edgeDialer != nil {
		a.edgeDialer.Close()
		a.edgeDialer = nil
	}
	a.mu.Unlock()

	if err := a.StartWGProxy(ctx, tok, server); err != nil {
		return err
	}
	log.Printf("wg: connected — device %s, tunnel %s, server %s (%s:%d)",
		dev.PubKey[:8]+"…", dev.IPv4, server.Hostname, server.IPv4AddrIn, server.Port)
	return nil
}

// activeAccessToken returns the active account's access token, refreshing
// through the single-flight gate if it is stale. Same flow the MASQUE pass
// fetch uses (fetchProxyPassWithRefresh's inner half).
func (a *App) activeAccessToken(ctx context.Context) (string, error) {
	a.mu.Lock()
	active := a.Store.ActiveAccount()
	var access, refresh string
	if active != nil {
		access = active.AccessToken
		refresh = active.RefreshToken
	}
	a.mu.Unlock()
	if active == nil {
		return "", errors.New("no account")
	}

	gc := &guardian.Client{Endpoint: a.Guardian, Token: access}
	// Probe with a cheap auth'd call; 401 → refresh once.
	if _, err := gc.FetchUserInfo(ctx); err == nil {
		return access, nil
	} else if !errors.Is(err, guardian.ErrTokenInvalid) && refresh == "" {
		return access, nil // non-auth error: try with what we have
	}
	if refresh == "" {
		return "", errors.New("account token expired and no refresh token")
	}
	tok, err := a.refreshAccountToken(ctx, active.Email, refresh)
	if err != nil {
		return "", err
	}
	return tok, nil
}

// pickWGServer fetches Guardian's WG server list and chooses one: the city
// matching the current MASQUE selection if Guardian has it, else weighted
// random (same weight semantics as the official client).
func (a *App) pickWGServer(ctx context.Context, accessToken string) (state.WGServerInfo, error) {
	gc := &guardian.Client{Endpoint: a.Guardian, Token: accessToken}
	raw, err := gc.FetchWGServers(ctx)
	if err != nil {
		return state.WGServerInfo{}, err
	}
	servers, err := ParseWGServers(raw)
	if err != nil {
		return state.WGServerInfo{}, fmt.Errorf("parse wg servers: %w", err)
	}
	// Guardian entries carry a weight for load-balancing (official client
	// semantics) — default it when absent.
	for i := range servers {
		if servers[i].Weight <= 0 {
			servers[i].Weight = 1
		}
	}
	if len(servers) == 0 {
		return state.WGServerInfo{}, errors.New("guardian returned no WireGuard servers")
	}

	a.mu.Lock()
	sel := a.Store.Selected
	a.mu.Unlock()

	// Guardian server entries don't carry city names in the flat struct —
	// match by hostname against the MASQUE selection when both exist.
	var chosen *state.WGServerInfo
	if sel.ServerHost != "" {
		for i := range servers {
			if sameHostFamily(servers[i].Hostname, sel.ServerHost) {
				chosen = &servers[i]
				break
			}
		}
	}
	if chosen == nil {
		// Weighted random over all servers (official client semantics).
		total := 0
		for i := range servers {
			total += max(servers[i].Weight, 1)
		}
		roll := rand.Intn(total)
		for i := range servers {
			roll -= max(servers[i].Weight, 1)
			if roll < 0 {
				chosen = &servers[i]
				break
			}
		}
		if chosen == nil {
			chosen = &servers[0]
		}
	}

	return state.WGServerInfo{
		Hostname:   chosen.Hostname,
		IPv4AddrIn: chosen.IPv4AddrIn,
		PublicKey:  chosen.PublicKey,
		Port:       chosen.Port,
	}, nil
}

// sameHostFamily reports whether two server hostnames are plausibly the same
// location (Guardian and MASQUE hostnames differ in shape: "nl107-wg" vs
// "nl107.m1.fastly-masque.net" — compare the leading location token).
func sameHostFamily(a, b string) bool {
	ta := hostToken(a)
	tb := hostToken(b)
	return ta != "" && ta == tb
}

func hostToken(host string) string {
	for i := 0; i < len(host); i++ {
		if host[i] == '.' || host[i] == '-' {
			return host[:i]
		}
	}
	return host
}

// WGStatus describes the current WireGuard mode for the status API.
func (a *App) WGStatus() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := map[string]any{"available": false, "version_tag": ""}
	if dev := a.Store.WGDevice; dev != nil {
		st["available"] = true
		st["device"] = dev.Name
		st["ipv4"] = dev.IPv4
		st["email"] = dev.Email
	}
	if a.wgTunnel != nil {
		st["connected"] = true
		st["tunnel_ipv4"] = a.wgTunnel.IPv4()
	}
	return st
}

