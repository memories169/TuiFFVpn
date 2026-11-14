package webapp

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// handleLoginToken stores manually-supplied OAuth tokens. This is the fallback
// when automated FxA login is blocked (e.g. Fastly issues a CAPTCHA challenge
// that a non-browser client cannot solve): obtain the tokens from a browser
// session or the reference CLI and paste them here.
func (a *App) handleLoginToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Email        string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, LoginResponse{Error: "bad request"})
		return
	}
	if req.AccessToken == "" {
		writeJSON(w, 400, LoginResponse{Error: "access_token is required"})
		return
	}
	if req.ExpiresIn == 0 {
		req.ExpiresIn = 3600
	}
	a.mu.Lock()
	a.Store.UpsertAccount(strings.TrimSpace(req.Email), req.AccessToken, req.RefreshToken, req.ExpiresIn)
	err := a.Store.Save()
	a.mu.Unlock()
	if err != nil {
		writeJSON(w, 200, LoginResponse{Error: "failed to persist tokens: " + err.Error()})
		return
	}
	a.trackAccount(req.Email, "", "")
	log.Printf("webui: stored manual OAuth tokens for %s", req.Email)
	a.probeQuota(req.AccessToken, req.Email)
	writeJSON(w, 200, map[string]any{"ok": true})
}
