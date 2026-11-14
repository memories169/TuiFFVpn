package webapp

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"fxsocks/webui/internal/state"
)

// handleAccounts returns the list of managed Firefox accounts with quota state.
func (a *App) handleAccounts(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	// Normalize first: merges quota-only stubs into their token twins and
	// prunes tokenless entries, so the list never shows an unusable active.
	a.Store.ActiveAccount()
	a.Store.Save()
	accts := a.Store.Accounts
	a.mu.Unlock()
	type item struct {
		Email      string `json:"email"`
		QuotaMax   string `json:"quota_max"`
		QuotaLeft  string `json:"quota_left"`
		Active     bool   `json:"active"`
		HasToken   bool   `json:"has_token"`
		ProbeError string `json:"probe_error,omitempty"`
	}
	out := make([]item, 0, len(accts))
	for i := range accts {
		ac := &accts[i]
		out = append(out, item{
			Email:      ac.Email,
			QuotaMax:   ac.QuotaMax,
			QuotaLeft:  ac.QuotaLeft,
			Active:     ac.Email == a.Store.Active,
			HasToken:   ac.AccessToken != "",
			ProbeError: ac.ProbeError,
		})
	}
	writeJSON(w, 200, map[string]any{"accounts": out, "active": a.Store.Active})
}

// handleAccountDelete removes a managed account by email. If the proxy is
// running on it, the proxy stops.
func (a *App) handleAccountDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad request"})
		return
	}
	if req.Email == "" {
		writeJSON(w, 400, map[string]any{"error": "email is required"})
		return
	}
	a.mu.Lock()
	removed := a.Store.RemoveAccount(req.Email)
	err := a.Store.Save()
	a.mu.Unlock()
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if removed {
		a.stopProxyIfActiveAccount(req.Email)
	}
	writeJSON(w, 200, map[string]any{"ok": true, "removed": removed})
}

// handleAccountSelect switches the active account. If a server is already
// selected, the proxy restarts on the new account's credentials.
func (a *App) handleAccountSelect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad request"})
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		writeJSON(w, 400, map[string]any{"error": "email is required"})
		return
	}
	a.mu.Lock()
	ok := a.Store.SetActive(req.Email)
	sel := a.Store.Selected
	a.mu.Unlock()
	if !ok {
		writeJSON(w, 200, map[string]any{"error": "unknown account: " + req.Email})
		return
	}
	a.mu.Lock()
	err := a.Store.Save()
	a.mu.Unlock()
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	log.Printf("webui: active account switched to %s", req.Email)

	// Restart the proxy on the new account when a server is already chosen.
	if sel.ServerHost != "" && sel.ServerPort != 0 {
		perr := a.restartProxyOnActive(r.Context(), sel.ServerHost, sel.ServerPort)
		if perr != nil {
			writeJSON(w, 200, map[string]any{"ok": true, "switched": true, "proxy": "stopped", "error": perr.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "switched": true, "proxy": "running", "server": sel.ServerHost})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "switched": true})
}

// trackAccount records or updates an account's quota in the list. Quota-only
// callers (probe before tokens exist) create a stub entry; UpsertAccount
// later fills in credentials.
func (a *App) trackAccount(email, quotaMax, quotaLeft string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	email = strings.TrimSpace(email)
	if email == "" {
		return
	}
	now := time.Now()
	if ac := a.Store.FindAccount(email); ac != nil {
		ac.QuotaMax = quotaMax
		ac.QuotaLeft = quotaLeft
		ac.CheckedAt = now
		return
	}
	a.Store.Accounts = append(a.Store.Accounts, state.Account{
		Email:     email,
		QuotaMax:  quotaMax,
		QuotaLeft: quotaLeft,
		CheckedAt: now,
		AddedAt:   now,
	})
}

func (a *App) saveState() {
	if err := a.Store.Save(); err != nil {
		// best effort; quota tracking is advisory
	}
}
