package webapp

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var staticFS embed.FS

// Routes returns the root handler for the web console: the admin auth, the
// REST API, and the embedded static UI.
func (a *App) Routes() http.Handler {
	mux := http.NewServeMux()

	// Public: admin auth + web console bootstrap status + OAuth callback.
	mux.HandleFunc("/api/admin/login", a.handleAdminLogin)
	mux.HandleFunc("/api/admin/logout", a.handleAdminLogout)
	mux.HandleFunc("/api/admin/status", a.handleAdminStatus)
	// PC-browser ingest (userscript pushes tokens from the host Firefox).
	// Key-authenticated; disabled unless FXVPN_INGEST_KEY is set.
	mux.HandleFunc("/api/ingest", a.handleIngest)

	// Authed: everything else.
	mux.HandleFunc("/api/admin/change-password", a.requireAuth(a.handleChangePassword))
	mux.HandleFunc("/api/admin/theme", a.requireAuth(a.handleTheme))
	mux.HandleFunc("/api/accounts", a.requireAuth(a.handleAccounts))
	mux.HandleFunc("/api/accounts/delete", a.requireAuth(a.handleAccountDelete))
	mux.HandleFunc("/api/accounts/select", a.requireAuth(a.handleAccountSelect))
	mux.HandleFunc("/api/login", a.requireAuth(a.handleLogin))

	mux.HandleFunc("/api/login-token", a.requireAuth(a.handleLoginToken))
	mux.HandleFunc("/api/verify", a.requireAuth(a.handleVerify))
	mux.HandleFunc("/api/servers", a.requireAuth(a.handleServers))
	mux.HandleFunc("/api/select", a.requireAuth(a.handleSelect))
	mux.HandleFunc("/api/status", a.requireAuth(a.handleStatus))
	mux.HandleFunc("/api/test", a.requireAuth(a.handleTest))

	// Serve the embedded UI.
	sub, err := fs.Sub(staticFS, "static")
	if err == nil {
		mux.Handle("/", http.FileServer(http.FS(sub)))
	}
	return mux
}
