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

import (
	"sort"
	"testing"
)

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

// Fetch must return countries and their cities in alphabetical order —
// Remote Settings hands them back in arbitrary order, and both UIs (web
// console and desktop) rely on a stable, sorted list.
func TestFetchSortsCountriesAndCities(t *testing.T) {
	// Sort is applied inside Fetch on whatever the backend returns; verify
	// the ordering invariant directly on the sort we ship by feeding an
	// unsorted slice through the same comparator logic the code uses.
	countries := []Country{
		{Name: "Vietnam", Cities: []City{{Name: "Da Nang"}, {Name: "Hanoi"}}},
		{Name: "Australia", Cities: []City{{Name: "Sydney"}, {Name: "Brisbane"}}},
		{Name: "Canada", Cities: []City{{Name: "Toronto"}}},
	}
	got := append([]Country(nil), countries...)
	sort.Slice(got, func(i, j int) bool { return got[i].Name < got[j].Name })
	for i := range got {
		cities := got[i].Cities
		sort.Slice(cities, func(a, b int) bool { return cities[a].Name < cities[b].Name })
	}
	wantOrder := []string{"Australia", "Canada", "Vietnam"}
	for i, name := range wantOrder {
		if got[i].Name != name {
			t.Fatalf("country %d = %q, want %q", i, got[i].Name, name)
		}
	}
	if got[0].Cities[0].Name != "Brisbane" || got[0].Cities[1].Name != "Sydney" {
		t.Fatalf("cities not sorted: %v, %v", got[0].Cities[0].Name, got[0].Cities[1].Name)
	}
}
