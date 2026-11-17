// fxvpn-desktop — native Linux GUI for the Firefox VPN console.
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

package desktop

// Localhost ingest endpoint: the desktop app's counterpart of the web
// console's /api/ingest. The PC userscript (fxvpn-desktop-grabber.user.js)
// captures tokens in the user's REAL browser — the only client the Fastly
// edge trusts on a bot-score-flagged network — and POSTs the ready OAuth
// tokens here. Same payload shape and key auth as the container endpoint,
// bound to 127.0.0.1, disabled unless a key is configured.

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
)

// ingestRequest is the payload POSTed by the userscript — identical shape
// to the container's webapp ingestRequest.
type ingestRequest struct {
	Email        string `json:"email"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	SessionToken string `json:"session_token"`
}

// ingestKey returns the configured key, or a freshly generated one when
// the user didn't set FXVPN_INGEST_KEY (generated per run so a stray
// open port can't accumulate accounts silently).
func ingestKey() string {
	if k := os.Getenv("FXVPN_INGEST_KEY"); k != "" {
		return k
	}
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

// StartIngestServer launches the localhost token receiver (non-blocking).
func (e *Engine) StartIngestServer(addr string) { e.ingestServer(addr) }

// ingestServer runs the localhost token receiver. It never exits while
// the engine lives; failures are logged, not fatal — the GUI keeps
// working without it.
func (e *Engine) ingestServer(addr string) {
	key := ingestKey()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/ingest", func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Ingest-Key")), []byte(key)) != 1 {
			writeIngestJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid ingest key"})
			return
		}
		var req ingestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeIngestJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request"})
			return
		}
		if req.AccessToken == "" {
			// The desktop userscript exchanges on the PC; a bare session
			// token would have to be exchanged from THIS machine, which
			// the edge is blocking. Tell the userscript to exchange.
			writeIngestJSON(w, http.StatusBadRequest, map[string]any{
				"error": "need access_token — set EXCHANGE_ON_PC=true in the userscript",
			})
			return
		}
		if req.ExpiresIn <= 0 {
			req.ExpiresIn = 6 * 3600
		}
		if err := e.AddAccountWithTokens(req.Email, req.AccessToken, req.RefreshToken, req.ExpiresIn); err != nil {
			writeIngestJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		log.Printf("desktop: ingested OAuth tokens for %s (PC browser)", req.Email)
		writeIngestJSON(w, http.StatusOK, map[string]any{"ok": true, "stored": "oauth", "email": req.Email})
	})

	srv := &http.Server{Addr: addr, Handler: mux}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("desktop: ingest server unavailable on %s: %v (userscript push disabled)", addr, err)
		return
	}
	log.Printf("desktop: ingest server on http://%s/api/ingest (X-Ingest-Key=%s)", addr, key)
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("desktop: ingest server stopped: %v", err)
		}
	}()
}

func writeIngestJSON(w http.ResponseWriter, status int, v map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// IngestAddr resolves the listen address: --ingest flag value, then
// FXVPN_INGEST_ADDR, then the 127.0.0.1:9091 default.
func IngestAddr(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if v := os.Getenv("FXVPN_INGEST_ADDR"); v != "" {
		return v
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(9091))
}
