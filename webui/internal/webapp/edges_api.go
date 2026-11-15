package webapp

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"

	"fxsocks/webui/internal/serverlist"
)

// Edge control API: lets an external orchestrator (e.g. a telegram/discord
// bot driving sing-box on another machine — see github.com/ppptran/super-bot-go)
// list ffvpn's servers and switch the selected one, without opening a port
// per server. Traffic still flows through the single SOCKS5 listener;
// these endpoints are the control plane, authenticated with the same
// FXVPN_INGEST_KEY the userscript uses (X-Ingest-Key header).

type edgeSummary struct {
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	CityName    string `json:"city_name"`
	ServerHost  string `json:"server_host"`
	ServerPort  int    `json:"server_port"`
	Current     bool   `json:"current"`
}

type edgeListResponse struct {
	Current   edgeSummary    `json:"current"`
	Proxy     map[string]any `json:"proxy"`
	Servers   []edgeSummary  `json:"servers"`
	EdgeCount int            `json:"edge_count"`
}

// handleEdges lists every server from Remote Settings with a "current"
// marker on the selected one.
func (a *App) handleEdges(w http.ResponseWriter, r *http.Request) {
	servers, err := serverlist.Fetch(r.Context())
	if err != nil {
		writeJSON(w, 200, map[string]any{"error": "load servers: " + err.Error()})
		return
	}
	proxyState := a.proxyState()
	a.mu.Lock()
	sel := a.Store.Selected
	a.mu.Unlock()

	out := edgeListResponse{Servers: make([]edgeSummary, 0, 64)}
	out.Current = edgeSummary{
		CountryCode: sel.CountryCode,
		CountryName: sel.CountryName,
		CityName:    sel.CityName,
		ServerHost:  sel.ServerHost,
		ServerPort:  sel.ServerPort,
		Current:     sel.ServerHost != "",
	}
	for _, c := range servers {
		for _, ct := range c.Cities {
			for _, srv := range ct.Servers {
				if srv.Quarantined {
					continue
				}
				out.Servers = append(out.Servers, edgeSummary{
					CountryCode: c.Code,
					CountryName: c.Name,
					CityName:    ct.Name,
					ServerHost:  srv.Hostname,
					ServerPort:  srv.Port,
					Current:     srv.Hostname == sel.ServerHost,
				})
			}
		}
	}
	sort.Slice(out.Servers, func(i, j int) bool {
		if out.Servers[i].CountryName != out.Servers[j].CountryName {
			return out.Servers[i].CountryName < out.Servers[j].CountryName
		}
		return out.Servers[i].ServerHost < out.Servers[j].ServerHost
	})
	out.EdgeCount = len(out.Servers)
	out.Proxy = proxyState
	writeJSON(w, 200, out)
}

// handleEdgesSelect switches the selected server. Same healing chain as the
// web UI's /api/select: persist selection → fetch pass (activate/refresh as
// needed) → restart the SOCKS proxy on the new edge.
func (a *App) handleEdgesSelect(w http.ResponseWriter, r *http.Request) {
	var req SelectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad request"})
		return
	}
	if req.ServerHost == "" || req.ServerPort == 0 {
		writeJSON(w, 400, map[string]any{"error": "server_host and server_port required"})
		return
	}
	token, terr := a.validAccessToken(r.Context())
	if token == "" {
		if terr == nil {
			terr = fmt.Errorf("not logged in")
		}
		writeJSON(w, 200, map[string]any{"error": terr.Error(), "action": "re_add_account"})
		return
	}

	// Persist selection before fetching the pass (mirrors handleSelect).
	a.mu.Lock()
	a.Store.Select(req.CountryCode, req.CountryName, req.CityCode, req.CityName, req.ServerHost, req.ServerPort)
	err := a.Store.Save()
	a.mu.Unlock()
	if err != nil {
		writeJSON(w, 200, map[string]any{"error": "persist failed: " + err.Error()})
		return
	}

	pass, err := a.fetchProxyPassWithRefresh(r, token)
	if err != nil {
		a.mu.Lock()
		a.lastErr = err.Error()
		a.mu.Unlock()
		writeJSON(w, 200, map[string]any{"error": err.Error(), "server": req.ServerHost})
		return
	}
	a.mu.Lock()
	a.lastErr = ""
	a.currentPass = pass.RawToken
	a.mu.Unlock()

	a.startProxy(req.ServerHost, req.ServerPort, pass.Bearer(), pass.ExpiresAt())
	log.Printf("edges: selected %s/%s server=%s:%d (control API)", req.CountryName, req.CityName, req.ServerHost, req.ServerPort)
	writeJSON(w, 200, map[string]any{
		"ok":     true,
		"server": req.ServerHost,
		"port":   req.ServerPort,
		"note":   "proxy restarted on the new edge; sing-box outbound (single :1080) needs no change",
	})
}

// handleEdgesStatus returns the current selection + proxy state (used by
// bots to display state and by health checks).
func (a *App) handleEdgesStatus(w http.ResponseWriter, r *http.Request) {
	proxyState := a.proxyState()
	a.mu.Lock()
	sel := a.Store.Selected
	suspect := a.suspectEdge == sel.ServerHost && a.suspectEdge != ""
	a.mu.Unlock()
	writeJSON(w, 200, map[string]any{
		"selected":     sel,
		"proxy":        proxyState,
		"edge_suspect": suspect,
	})
}

// registerEdgeRoutes mounts the control API with ingest-key auth.
func (a *App) registerEdgeRoutes(mux *http.ServeMux) {
	auth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			key := ingestKey()
			if key == "" || !constantTimeEqual(strings.TrimSpace(r.Header.Get("X-Ingest-Key")), key) {
				writeJSON(w, 401, map[string]any{"error": "invalid or missing X-Ingest-Key"})
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("/api/edges", auth(a.handleEdges))
	mux.HandleFunc("/api/edges/select", auth(a.handleEdgesSelect))
	mux.HandleFunc("/api/edges/status", auth(a.handleEdgesStatus))
}
