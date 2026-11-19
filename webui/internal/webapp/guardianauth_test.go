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
	"strings"
	"testing"
)

func TestWGPKCEVerifierShape(t *testing.T) {
	v, err := wgPKCEVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 128 {
		t.Fatalf("verifier length = %d, want 128", len(v))
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	for i, c := range v {
		if !strings.ContainsRune(alphabet, c) {
			t.Fatalf("verifier[%d] = %q not in official alphabet", i, c)
		}
	}
	v2, _ := wgPKCEVerifier()
	if v == v2 {
		t.Fatal("verifiers not random")
	}
}

func TestWGPKCEChallenge(t *testing.T) {
	// RFC 7636 appendix B vector.
	v := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := wgPKCEChallenge(v); got != want {
		t.Fatalf("challenge = %q, want %q", got, want)
	}
	// Shape check against a generated verifier: 43-44 chars, base64url.
	got := wgPKCEChallenge(func() string { s, _ := wgPKCEVerifier(); return s }())
	if len(got) != 43 && len(got) != 44 {
		t.Fatalf("challenge length = %d", len(got))
	}
	if strings.Contains(got, "+") || strings.Contains(got, "/") || strings.Contains(got, "=") {
		t.Fatalf("challenge not base64url-no-pad: %q", got)
	}
}

func TestWGExtractCode(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"abc123", "abc123"},
		{"https://vpn.mozilla.org/oauth/success?code=Xyz&state=s", "Xyz"},
		{"http://localhost:9090/?code=Q9&extra=1", "Q9"},
		{"https://accounts.firefox.com/?action=done", ""},
		{"   https://x.org/?code=TrimMe  ", "TrimMe"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := wgExtractCode(tc.in); got != tc.want {
			t.Errorf("wgExtractCode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
