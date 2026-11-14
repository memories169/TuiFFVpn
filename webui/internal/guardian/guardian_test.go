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

package guardian

import "testing"

func TestParseJWT(t *testing.T) {
	// Build a JWT payload {"sub":"u123","exp":1700000000,"nbf":1699990000}
	// (base64url without padding) and wrap in a fake token.
	payload := base64url(`{"sub":"u123","exp":1700000000,"nbf":1699990000}`)
	token := "header." + payload + ".sig"
	c, err := parseJWT(token)
	if err != nil {
		t.Fatalf("parseJWT: %v", err)
	}
	if c.Sub != "u123" {
		t.Fatalf("sub = %q, want u123", c.Sub)
	}
	if c.Exp != 1700000000 {
		t.Fatalf("exp = %d, want 1700000000", c.Exp)
	}
	if c.Nbf != 1699990000 {
		t.Fatalf("nbf = %d, want 1699990000", c.Nbf)
	}
}

func TestParseJWTBad(t *testing.T) {
	if _, err := parseJWT("not-a-jwt"); err == nil {
		t.Fatal("expected error for malformed JWT")
	}
}
