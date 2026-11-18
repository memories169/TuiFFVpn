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

// WireGuard device identity: the Curve25519 keypair registered with
// Guardian as a "device" (mirrors mozilla-vpn-client's TaskAddDevice —
// generate private key, derive public key, POST both; Guardian assigns the
// tunnel IPs). Keys persist in state.json; re-registration with the same
// pubkey is idempotent.

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// WGKeys is a WireGuard device keypair (base64, WireGuard string format).
type WGKeys struct {
	Private string // base64 32-byte private key
	Public  string // base64 32-byte public key, derived from Private
}

// GenerateWGKeys creates a fresh Curve25519 keypair.
func GenerateWGKeys() (*WGKeys, error) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return nil, fmt.Errorf("read random: %w", err)
	}
	// Clamp per RFC 7748 / WireGuard spec.
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}
	return &WGKeys{
		Private: base64.StdEncoding.EncodeToString(priv),
		Public:  base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// wgPrivateKeyBytes decodes the base64 private key for wireguard-go.
func wgPrivateKeyBytes(k *WGKeys) ([]byte, error) {
	return base64.StdEncoding.DecodeString(k.Private)
}

// wgPublicKeyString is the public key as a WireGuard config string.
func wgPublicKeyString(k *WGKeys) string { return k.Public }
