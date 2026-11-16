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
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"fxsocks/webui/internal/state"
)

// Manual refresh-all: the UI button kicks a full token-keeper pass over
// EVERY account (active included) without waiting for the 24 h tick. Runs in
// the background with the same worker pool as the keeper; the endpoint
// returns immediately so the UI can poll /api/accounts for per-account
// refreshed_at / refresh_error updates.

// refreshAllState tracks a running manual refresh-all pass (single one at a
// time; a second click while one runs is answered with running=true).
type refreshAllState struct {
	mu        sync.Mutex
	running   bool
	startedAt time.Time
}

// handleAccountsRefreshAll starts a manual refresh of every account's tokens.
// GET returns the pass status without starting anything; POST starts a pass.
func (a *App) handleAccountsRefreshAll(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.refreshAll.mu.Lock()
		running, startedAt := a.refreshAll.running, a.refreshAll.startedAt
		a.refreshAll.mu.Unlock()
		writeJSON(w, 200, map[string]any{"running": running, "started_at": startedAt})
		return
	}
	if !a.refreshAll.tryStart() {
		writeJSON(w, 200, map[string]any{
			"ok": true, "running": true, "started": false,
			"note": "một đợt refresh khác đang chạy — xem trạng thái trong danh sách account",
		})
		return
	}
	go a.refreshAllAccounts()
	writeJSON(w, 200, map[string]any{
		"ok": true, "running": true, "started": true,
		"note": "đang refresh token của tất cả account — danh sách account sẽ tự cập nhật",
	})
}

// tryStart claims the single in-flight slot.
func (rs *refreshAllState) tryStart() bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.running {
		return false
	}
	rs.running = true
	rs.startedAt = time.Now()
	return true
}

// done releases the slot.
func (rs *refreshAllState) done() {
	rs.mu.Lock()
	rs.running = false
	rs.mu.Unlock()
}

// refreshAllAccounts performs one keeper-style pass over every account with
// FXVPN_KEEPER_WORKERS concurrency (the active account included — a manual
// pass is explicitly requested, so it refreshes everything). Transient
// Fastly failures land on ProbeError, real dead grants on RefreshError; the
// UI shows each account's outcome after its next poll.
func (a *App) refreshAllAccounts() {
	defer a.refreshAll.done()

	a.mu.Lock()
	accts := append([]state.Account(nil), a.Store.Accounts...)
	a.mu.Unlock()

	var wg sync.WaitGroup
	sem := make(chan struct{}, keeperWorkers)
	var mu sync.Mutex
	ok, transient, dead, skipped := 0, 0, 0, 0

	for _, ac := range accts {
		if ac.RefreshToken == "" {
			mu.Lock()
			skipped++
			mu.Unlock()
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(email, refresh string) {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			err := a.refreshAccountErr(ctx, email)
			cancel()
			mu.Lock()
			switch {
			case err == nil:
				ok++
				log.Printf("refresh-all: %s ✓", email)
			case isTransientRefreshErr(err):
				transient++
				log.Printf("refresh-all: %s tạm thời (Fastly/mạng): %v — account vẫn dùng được", email, err)
			default:
				dead++
				log.Printf("refresh-all: %s token chết (cần thêm lại account): %v", email, err)
			}
			mu.Unlock()
		}(ac.Email, ac.RefreshToken)
	}
	wg.Wait()
	log.Printf("refresh-all: xong — %d ok, %d tạm thời (Fastly), %d chết, %d bỏ qua (không có refresh token), %d account",
		ok, transient, dead, skipped, len(accts))
}
