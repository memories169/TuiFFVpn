package webapp

import "net/http"

// handleTest runs a live connection check through the active proxy tunnel.
func (a *App) handleTest(w http.ResponseWriter, r *http.Request) {
	res := a.testProxy()
	writeJSON(w, 200, res)
}
