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
