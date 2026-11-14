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

package browsercapture

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Cookie is a browser cookie in a transport-neutral shape.
type Cookie struct {
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	Domain   string  `json:"domain"`
	Path     string  `json:"path"`
	Secure   bool    `json:"secure"`
	HTTPOnly bool    `json:"http_only"`
	SameSite string  `json:"same_site"`
	Expires  float64 `json:"expires"`
}

// HTTPCookies converts the browser cookies into net/http cookies.
func HTTPCookies(in []Cookie) []*http.Cookie {
	out := make([]*http.Cookie, 0, len(in))
	for _, c := range in {
		hc := &http.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Secure:   c.Secure,
			HttpOnly: c.HTTPOnly,
		}
		if c.Expires > 0 {
			hc.Expires = time.Unix(int64(c.Expires), 0)
		}
		out = append(out, hc)
	}
	return out
}

// FirefoxCookies returns only the cookies scoped to Mozilla domains.
func FirefoxCookies(in []Cookie) []Cookie {
	out := make([]Cookie, 0, len(in))
	for _, c := range in {
		if isMozillaDomain(c.Domain) {
			out = append(out, c)
		}
	}
	return out
}

func isMozillaDomain(domain string) bool {
	for _, suffix := range []string{"firefox.com", "mozilla.org", "mozilla.com", "mozilla.net"} {
		if domain == suffix || len(domain) > len(suffix)+1 && domain[len(domain)-len(suffix)-1:] == "."+suffix {
			return true
		}
	}
	return false
}

// Cookies reads every cookie the browser holds. The FxA edge sets a
// `_fs_ch_*` anti-bot cookie while loading accounts.firefox.com; carrying it
// into the Go control-plane client lets the token exchange skip the Fastly
// challenge the same way the page does.
func (p *Page) Cookies(ctx context.Context) ([]Cookie, error) {
	var out struct {
		Cookies []Cookie `json:"cookies"`
	}
	if err := p.ws.call(ctx, "Storage.getCookies", map[string]any{}, &out); err != nil {
		return nil, fmt.Errorf("read browser cookies: %w", err)
	}
	return out.Cookies, nil
}

// CookiesFor returns the Mozilla-scoped cookies for a page.
func (p *Page) CookiesFor(ctx context.Context) ([]Cookie, error) {
	all, err := p.Cookies(ctx)
	if err != nil {
		return nil, err
	}
	return FirefoxCookies(all), nil
}
