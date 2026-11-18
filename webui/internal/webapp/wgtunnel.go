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

// WireGuard tunnel over wireguard-go's gVisor netstack: a userspace IP
// stack with no kernel TUN device — works inside unprivileged docker
// containers and as a plain desktop process. The stack routes the tunnel
// IPs; callers dial destinations through it like an ordinary network.

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// WGTunnel is a live WireGuard session over the userspace netstack.
type WGTunnel struct {
	tnd  *netstack.Net
	dev  *device.Device
	ipv4 string // tunnel v4 (device address)
	ipv6 string // tunnel v6 (device address)
}

// WGTunnelConfig is everything needed to establish one tunnel.
type WGTunnelConfig struct {
	PrivateKey  string   // base64 device private key
	AddressIPv4 string   // device tunnel IPv4 (from Guardian)
	AddressIPv6 string   // device tunnel IPv6 (optional)
	PeerPubKey  string   // base64 server public key
	Endpoint    string   // server host:port (UDP)
	AllowedIPs  []string // "0.0.0.0/0", "::/0"
	DNS         []string // tunnel DNS resolvers (optional)
}

// DialWGTunnel establishes a WireGuard session over the userspace netstack.
// It returns immediately after the device is created; the first handshake
// happens on the first dial (wireguard-go dials lazily).
func DialWGTunnel(ctx context.Context, cfg WGTunnelConfig) (*WGTunnel, error) {
	addrs := []string{}
	if cfg.AddressIPv4 != "" {
		if !strings.Contains(cfg.AddressIPv4, "/") {
			cfg.AddressIPv4 += "/32"
		}
		addrs = append(addrs, cfg.AddressIPv4)
	}
	if cfg.AddressIPv6 != "" {
		if !strings.Contains(cfg.AddressIPv6, "/") {
			cfg.AddressIPv6 += "/128"
		}
		addrs = append(addrs, cfg.AddressIPv6)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("wgtunnel: no device address assigned")
	}

	localAddrs := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		ipp, err := netip.ParsePrefix(a)
		if err != nil {
			return nil, fmt.Errorf("wgtunnel: parse address %q: %w", a, err)
		}
		localAddrs = append(localAddrs, ipp.Addr())
	}
	dnsAddrs := make([]netip.Addr, 0, len(cfg.DNS))
	for _, d := range cfg.DNS {
		ip, err := netip.ParseAddr(d)
		if err != nil {
			return nil, fmt.Errorf("wgtunnel: parse dns %q: %w", d, err)
		}
		dnsAddrs = append(dnsAddrs, ip)
	}
	tnd, tnet, err := netstack.CreateNetTUN(localAddrs, dnsAddrs, 1420)
	if err != nil {
		return nil, fmt.Errorf("wgtunnel: netstack: %w", err)
	}
	dev := device.NewDevice(tnd, conn.NewDefaultBind(), device.NewLogger(
		device.LogLevelError, "fxvpn-wg"))

	pk, err := wgPrivateKeyBytes(&WGKeys{Private: cfg.PrivateKey})
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("wgtunnel: private key: %w", err)
	}
	if err := dev.IpcSet(fmt.Sprintf("private_key=%x\n", pk)); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wgtunnel: ipc private_key: %w", err)
	}

	// wireguard-go IPC expects keys hex-encoded (uapi spec), while the
	// config/store form is base64 — decode then re-encode.
	pubRaw, err := base64.StdEncoding.DecodeString(cfg.PeerPubKey)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("wgtunnel: peer public key: %w", err)
	}
	peerCfg := fmt.Sprintf("public_key=%x\nendpoint=%s\npersistent_keepalive_interval=25\n",
		pubRaw, cfg.Endpoint)
	for _, a := range cfg.AllowedIPs {
		peerCfg += "allowed_ip=" + a + "\n"
	}
	if err := dev.IpcSet(peerCfg); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wgtunnel: ipc peer: %w", err)
	}

	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wgtunnel: device up: %w", err)
	}

	return &WGTunnel{tnd: tnet, dev: dev, ipv4: cfg.AddressIPv4, ipv6: cfg.AddressIPv6}, nil
}

// DialContext dials dst ("host:port") through the tunnel — TCP and UDP both
// traverse WireGuard at the IP layer, so udp:// trackers and DHT work.
func (t *WGTunnel) DialContext(ctx context.Context, network, dst string) (net.Conn, error) {
	return t.tnd.DialContext(ctx, network, dst)
}

// Close tears down the session.
func (t *WGTunnel) Close() error {
	t.dev.Close()
	return nil
}

// IPv4 returns the device's tunnel IPv4 address (diagnostics).
func (t *WGTunnel) IPv4() string { return t.ipv4 }

// Device returns the underlying wireguard device (for tests / advanced use).
func (t *WGTunnel) Device() *device.Device { return t.dev }
