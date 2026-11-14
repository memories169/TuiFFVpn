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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const vectorToken = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

// The bearer id and hawk key must match Mozilla's HKDF derivation. These
// vectors were produced with PyFxA's fxa.crypto.derive_key.
func TestHawkCredentialsVectors(t *testing.T) {
	id, key, err := hawkCredentials(vectorToken, "sessionToken")
	if err != nil {
		t.Fatalf("hawkCredentials: %v", err)
	}
	const wantID = "5fa7b1a9a3266f052b766e956f525b583607e777f264a5bb67b57ed5e34c2c5c"
	const wantKey = "4f05fbeb8c81b662f52d5c21595c1033a5126f3b7dabd872c4cfd8298254651c"
	if id != wantID {
		t.Fatalf("id = %s, want %s", id, wantID)
	}
	if got := hexOf(key); got != wantKey {
		t.Fatalf("key = %s, want %s", got, wantKey)
	}
}

func TestExchangeSessionTokenUsesBearer(t *testing.T) {
	var gotAuth, gotGrant, gotScope, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotUA = r.Header.Get("User-Agent")
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotGrant = body["grant_type"]
		gotScope = body["scope"]
		_, _ = w.Write([]byte(`{"access_token":"at","refresh_token":"rt","expires_in":3600,"scope":"profile"}`))
	}))
	defer srv.Close()

	tok, err := ExchangeSessionTokenWith(context.Background(), vectorToken, TokenOptions{TokenURLs: []string{srv.URL}})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if tok.AccessToken != "at" || tok.RefreshToken != "rt" || tok.ExpiresIn != 3600 {
		t.Fatalf("unexpected tokens: %+v", tok)
	}
	if !strings.HasPrefix(gotAuth, "Bearer fxs_") {
		t.Fatalf("authorization = %q, want Bearer fxs_ prefix", gotAuth)
	}
	if gotGrant != "fxa-credentials" {
		t.Fatalf("grant_type = %q", gotGrant)
	}
	if !strings.Contains(gotScope, "identity.mozilla.com/apps/vpn") {
		t.Fatalf("scope = %q", gotScope)
	}
	if gotUA != DefaultBrowserUA {
		t.Fatalf("user-agent = %q, want the default Firefox UA (the edge only accepts a Firefox UA)", gotUA)
	}
}

// A captured browser session must replay the browser's Firefox UA, because the
// Fastly challenge cookie is bound to it.
func TestExchangeSessionTokenWithCookiesUsesBrowserUA(t *testing.T) {
	var gotUA, gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotCookie = r.Header.Get("Cookie")
		_, _ = w.Write([]byte(`{"access_token":"at","expires_in":60}`))
	}))
	defer srv.Close()

	_, err := ExchangeSessionTokenWith(context.Background(), vectorToken, TokenOptions{
		// Host-only cookie (no Domain) so the jar attaches it to the test
		// server's host; install() strips Domain anyway, mirroring what real
		// captures send.
		Cookies:   []*http.Cookie{{Name: "_fs_ch_st_x", Value: "v", Path: "/"}},
		UserAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
		TokenURLs: []string{srv.URL},
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if !strings.HasPrefix(gotUA, "Mozilla/5.0") {
		t.Fatalf("user-agent = %q, want the browser UA", gotUA)
	}
	if !strings.Contains(gotCookie, "_fs_ch_st_x") {
		t.Fatalf("cookie header = %q, want the replayed Fastly cookie", gotCookie)
	}
}

func TestDefaultTokenURLsPreferAPIHost(t *testing.T) {
	if len(DefaultOAuthTokenURLs) == 0 || !strings.HasPrefix(DefaultOAuthTokenURLs[0], AuthServer) {
		t.Fatalf("first token URL = %v, want the api host", DefaultOAuthTokenURLs)
	}
}

func TestExchangeSessionTokenFallsBackToHawk(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		seen = append(seen, auth)
		if strings.HasPrefix(auth, "Bearer") {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"errno":110}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"at2","expires_in":60}`))
	}))
	defer srv.Close()

	tok, err := ExchangeSessionTokenWith(context.Background(), vectorToken, TokenOptions{TokenURLs: []string{srv.URL}})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if tok.AccessToken != "at2" {
		t.Fatalf("access_token = %q", tok.AccessToken)
	}
	if len(seen) != 2 || !strings.HasPrefix(seen[1], "Hawk ") {
		t.Fatalf("auth attempts = %v, want Bearer then Hawk", seen)
	}
}

func TestExchangeSessionTokenRejectsBadToken(t *testing.T) {
	if _, err := ExchangeSessionToken(context.Background(), "not-hex"); err == nil {
		t.Fatal("expected an error for a non-hex token")
	}
}

func TestSessionStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer fxs_") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"email":"u@example.com","uid":"abc","verified":true}`))
	}))
	defer srv.Close()

	st, err := SessionStatusWith(context.Background(), vectorToken, TokenOptions{}, srv.URL)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.Email != "u@example.com" || !st.Verified {
		t.Fatalf("unexpected status: %+v", st)
	}
}

func TestNormalizeSessionToken(t *testing.T) {
	in := "  \"ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789\"\n"
	want := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	if got := normalizeSessionToken(in); got != want {
		t.Fatalf("normalize = %q, want %q", got, want)
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = digits[c>>4]
		out[i*2+1] = digits[c&0x0f]
	}
	return string(out)
}
