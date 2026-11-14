package serverlist

import "testing"

func TestConnectServersFiltersQuarantined(t *testing.T) {
	city := City{
		Name: "Test",
		Servers: []Server{
			{Hostname: "ok1.example", Port: 443, Quarantined: false, Protocols: []Protocol{{Name: "connect", Host: "ok1", Port: 443, Scheme: "https"}}},
			{Hostname: "quar.example", Port: 443, Quarantined: true},
			{Hostname: "ok2.example", Port: 443, Quarantined: false, Protocols: nil},
		},
	}
	prots := ConnectServers(city)
	if len(prots) != 2 {
		t.Fatalf("got %d connect servers, want 2 (quarantined filtered)", len(prots))
	}
	// The server with no protocols defaults to its hostname:port over https.
	if prots[1].Host != "ok2.example" || prots[1].Port != 443 {
		t.Fatalf("default protocol wrong: %+v", prots[1])
	}
}
