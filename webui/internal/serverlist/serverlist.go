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

// Package serverlist fetches the Firefox VPN country/city/server tree from
// Mozilla Remote Settings.
package serverlist

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"
)

const remoteSettingsURL = "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records"

// Protocol describes one connect protocol offered by a server.
type Protocol struct {
	Name           string `json:"name"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Scheme         string `json:"scheme,omitempty"`
	TemplateString string `json:"templateString,omitempty"`
}

// Server is a single VPN proxy server.
type Server struct {
	Hostname    string     `json:"hostname"`
	Port        int        `json:"port"`
	Quarantined bool       `json:"quarantined"`
	Protocols   []Protocol `json:"protocols"`
}

// City is a city containing servers.
type City struct {
	Name    string   `json:"name"`
	Code    string   `json:"code"`
	Servers []Server `json:"servers"`
}

// Country is a country containing cities.
type Country struct {
	Name   string `json:"name"`
	Code   string `json:"code"`
	Cities []City `json:"cities"`
}

type rsResponse struct {
	Data []json.RawMessage `json:"data"`
}

// Fetch returns the list of countries from Remote Settings.
func Fetch(ctx context.Context) ([]Country, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, remoteSettingsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "MozillaVPN/2.35.0 (sys:linux; iap:true)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server list HTTP %d", resp.StatusCode)
	}
	var rs rsResponse
	if err := json.Unmarshal(body, &rs); err != nil {
		return nil, fmt.Errorf("parse server list: %w", err)
	}
	var countries []Country
	for _, raw := range rs.Data {
		var c Country
		if err := json.Unmarshal(raw, &c); err != nil {
			continue
		}
		if c.Code != "" && len(c.Cities) > 0 {
			countries = append(countries, c)
		}
	}
	// Remote Settings returns the entries in arbitrary order; sort by
	// country then city so every UI (web console, desktop app) shows the
	// same alphabetical list instead of a shuffle that changes per fetch.
	sort.Slice(countries, func(i, j int) bool {
		return countries[i].Name < countries[j].Name
	})
	for i := range countries {
		cities := countries[i].Cities
		sort.Slice(cities, func(a, b int) bool {
			return cities[a].Name < cities[b].Name
		})
	}
	return countries, nil
}

// ConnectServers returns the usable CONNECT endpoints for a city, excluding
// quarantined servers.
func ConnectServers(city City) []Protocol {
	var out []Protocol
	for _, srv := range city.Servers {
		if srv.Quarantined {
			continue
		}
		if len(srv.Protocols) == 0 {
			out = append(out, Protocol{Name: "connect", Host: srv.Hostname, Port: srv.Port, Scheme: "https"})
			continue
		}
		for _, p := range srv.Protocols {
			if p.Name == "connect" || p.Name == "masque" {
				out = append(out, p)
			}
		}
	}
	return out
}
