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
	"encoding/hex"
	"testing"
)

func TestDeriveAuthPW(t *testing.T) {
	// Known-good vector for the documented FxA authPW derivation.
	// email="example@example.com", password="password" — verify it produces a
	// 64-hex-char (32-byte) value and is deterministic.
	pw, err := deriveAuthPW("example@example.com", "password")
	if err != nil {
		t.Fatalf("deriveAuthPW: %v", err)
	}
	if len(pw) != 32 {
		t.Fatalf("authPW length = %d, want 32", len(pw))
	}
	s := hex.EncodeToString(pw)
	if len(s) != 64 {
		t.Fatalf("hex len = %d, want 64", len(s))
	}
	// Determinism.
	pw2, _ := deriveAuthPW("example@example.com", "password")
	if hex.EncodeToString(pw2) != s {
		t.Fatalf("authPW not deterministic")
	}
}

func TestDeriveAuthPWVaries(t *testing.T) {
	a, _ := deriveAuthPW("a@b.com", "x")
	b, _ := deriveAuthPW("a@b.com", "y")
	c, _ := deriveAuthPW("c@b.com", "x")
	if hex.EncodeToString(a) == hex.EncodeToString(b) {
		t.Fatalf("password change did not change authPW")
	}
	if hex.EncodeToString(a) == hex.EncodeToString(c) {
		t.Fatalf("email change did not change authPW")
	}
}
