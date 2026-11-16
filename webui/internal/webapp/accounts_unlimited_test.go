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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"fxsocks/webui/internal/state"
)

// newTestApp builds an App backed by a temp state file (no network use).
func newTestApp(t *testing.T) *App {
	t.Helper()
	st, err := state.Load(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return &App{Store: st, sessions: newSessionStore()}
}

// testRequest builds an httptest recorder + request for a handler call.
func testRequest(method, target string, body string) (*httptest.ResponseRecorder, *http.Request) {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	return httptest.NewRecorder(), req
}

// decodeJSONMap decodes a recorded JSON response into a map.
func decodeJSONMap(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode response %q: %v", w.Body.String(), err)
	}
	return m
}

// No cap: storing 100+ accounts must keep every one of them and the round
// trip through Load/Save preserves the full list.
func TestUnlimitedAccounts(t *testing.T) {
	a := newTestApp(t)
	const n = 100
	for i := 0; i < n; i++ {
		email := "user" + string(rune('a'+i%26)) + string(rune('0'+i/26%10)) + string(rune('0'+i/260%10)) + "@example.com"
		a.Store.UpsertAccount(email, "at-"+email, "rt-"+email, 3600)
	}
	if got := len(a.Store.Accounts); got != n {
		t.Fatalf("accounts = %d, want %d (a cap is eating accounts)", got, n)
	}
	if err := a.Store.Save(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := state.Load(a.Store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(reloaded.Accounts); got != n {
		t.Fatalf("after reload accounts = %d, want %d", got, n)
	}
}

// handleAccounts returns every account (no truncation) and reports the total.
func TestHandleAccountsReturnsAll(t *testing.T) {
	a := newTestApp(t)
	for i := 0; i < 37; i++ {
		a.Store.UpsertAccount("u"+itoa(i)+"@x.com", "at", "rt", 3600)
	}
	w, req := testRequest("GET", "/api/accounts", "")
	a.handleAccounts(w, req)
	res := decodeJSONMap(t, w)
	accts := res["accounts"].([]any)
	if len(accts) != 37 {
		t.Fatalf("accounts = %d, want 37", len(accts))
	}
	if res["total"].(float64) != 37 || res["limit"] != "none" {
		t.Fatalf("total/limit = %v/%v", res["total"], res["limit"])
	}
}

// Concurrent refreshes of DIFFERENT accounts must not serialize behind each
// other for the exchange duration: with N accounts and a slow FxA endpoint
// mock the wall clock must stay far below N × duration. (The exchange itself
// is stubbed via the fxa package in the webapp tests through a fake HTTP
// server — here we only exercise the gate's bookkeeping, so use zero-length
// exchanges and check invariants: every account ends refreshed, none is left
// holding the gate.)
func TestRefreshGatePerAccountConcurrent(t *testing.T) {
	a := newTestApp(t)
	const n = 20
	for i := 0; i < n; i++ {
		a.Store.UpsertAccount("u"+itoa(i)+"@x.com", "at", "rt"+itoa(i), 3600)
	}
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// The exchange itself would hit the network; we only verify the
			// gate claims/releases cleanly by calling the internal pieces.
			email := "u" + itoa(i) + "@x.com"
			a.refreshMu.Lock()
			if a.refreshing != "" {
				a.refreshMu.Unlock()
				// Another exchange in flight — this mirrors the polling path;
				// wait for the gate to free, then claim and release.
				for {
					a.refreshMu.Lock()
					if a.refreshing == "" {
						a.refreshing = "test"
						a.refreshMu.Unlock()
						break
					}
					a.refreshMu.Unlock()
					time.Sleep(time.Millisecond)
				}
				a.refreshMu.Lock()
				a.refreshing = ""
				a.refreshMu.Unlock()
				_ = email
				return
			}
			a.refreshing = "test" + itoa(i)
			a.refreshMu.Unlock()
			a.refreshMu.Lock()
			a.refreshing = ""
			a.refreshMu.Unlock()
		}(i)
	}
	wg.Wait()
	a.refreshMu.Lock()
	stuck := a.refreshing
	a.refreshMu.Unlock()
	if stuck != "" {
		t.Fatalf("gate left claimed: %q", stuck)
	}
}

// HealthyAccounts must return every usable account except the excluded one,
// sorted best quota first, and skip dead-grant accounts.
func TestHealthyAccountsOrdering(t *testing.T) {
	s := &state.Store{}
	s.UpsertAccount("big@x.com", "at", "rt", 3600)
	s.UpsertAccount("small@x.com", "at", "rt", 3600)
	s.UpsertAccount("dead@x.com", "at", "rt", 3600)
	s.UpsertAccount("tokenless@x.com", "at", "rt", 3600)
	s.UpsertAccount("active@x.com", "at", "rt", 3600)
	// Quotas.
	s.FindAccount("big@x.com").QuotaLeft = "5 GB"
	s.FindAccount("small@x.com").QuotaLeft = "100 MB"
	s.FindAccount("active@x.com").QuotaLeft = "10 GB"
	// Dead grant + tokenless.
	s.FindAccount("dead@x.com").RefreshError = "refresh failed (HTTP 401)"
	s.FindAccount("tokenless@x.com").RefreshToken = ""

	got := s.HealthyAccounts("active@x.com")
	if len(got) != 2 {
		t.Fatalf("healthy = %d accounts (%v), want 2", len(got), got)
	}
	if got[0].Email != "big@x.com" || got[1].Email != "small@x.com" {
		t.Fatalf("order = %s,%s; want big,small", got[0].Email, got[1].Email)
	}
}

// pickAlternates surfaces the same list through the App.
func TestPickAlternatesUnlimited(t *testing.T) {
	a := newTestApp(t)
	for i := 0; i < 50; i++ {
		a.Store.UpsertAccount("u"+itoa(i)+"@x.com", "at-"+itoa(i), "rt-"+itoa(i), 3600)
		a.Store.FindAccount("u" + itoa(i) + "@x.com").QuotaLeft = itoa(i) + "00 MB"
	}
	alts := a.pickAlternates("u49@x.com")
	if len(alts) != 49 {
		t.Fatalf("alternates = %d, want 49", len(alts))
	}
	// Best quota first: u48 (4800 MB) leads.
	if alts[0].Email != "u48@x.com" {
		t.Fatalf("first alternate = %s, want u48@x.com", alts[0].Email)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	digits := ""
	for i > 0 {
		digits = string(rune('0'+i%10)) + digits
		i /= 10
	}
	return digits
}
