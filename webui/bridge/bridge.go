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

// Package bridge is the supported embedding API for fxsocks/webui. The
// native desktop GUI (desktop/) links the whole engine through it; internal
// packages stay internal while every operation the web console exposes is
// available here with identical semantics (single-flight refresh, healing
// chain, transient-Fastly handling, keeper + rotator loops).
package bridge

import (
	"fxsocks/webui/internal/state"
	"fxsocks/webui/internal/webapp"
)

// App is the engine handle (a thin alias — no wrapper state of its own).
type App = webapp.App

// TestResult re-exports for embedders.
type TestResult = webapp.TestResult

// Load opens (or creates) the state file and boots the engine, including its
// token keeper and rotator background loops.
func Load(statePath, guardianEndpoint, proxyAddr string) (*webapp.App, error) {
	st, err := state.Load(statePath)
	if err != nil {
		return nil, err
	}
	if err := st.EnsureAdmin(); err != nil {
		return nil, err
	}
	return webapp.New(st, guardianEndpoint, proxyAddr), nil
}
