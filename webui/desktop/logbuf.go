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

// Ring-buffer capture of the standard log package. Everything the engine
// (webapp.App: keeper, rotator, healing chain, edge diagnostics) logs via
// log.Printf funnels through here once log.SetOutput installs the ring at
// boot — the Logs tab renders it verbatim, so the user sees exactly what
// the docker console logs print.

import (
	"io"
	"log"
	"os"
	"strings"
	"sync"
)

// logRing keeps the last N log lines in memory.
type logRing struct {
	mu      sync.Mutex
	lines   []string
	max     int
	partial string // tail of a Write that didn't end with '\n'
}

func newLogRing(max int) *logRing {
	return &logRing{max: max}
}

// Write implements io.Writer. The log package writes whole lines (it
// timestamp-prefixes each Println/Printf call), but a Write may still
// split mid-line — buffer the tail until a newline arrives.
func (r *logRing) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	text := string(p)
	if r.partial != "" {
		text = r.partial + text
		r.partial = ""
	}
	for {
		idx := strings.IndexByte(text, '\n')
		if idx < 0 {
			r.partial = text
			break
		}
		line := strings.TrimRight(text[:idx], "\r")
		text = text[idx+1:]
		if strings.TrimSpace(line) != "" {
			r.lines = append(r.lines, line)
			if len(r.lines) > r.max {
				r.lines = r.lines[len(r.lines)-r.max:]
			}
		}
	}
	return len(p), nil
}

// Snapshot returns the buffered lines, oldest first.
func (r *logRing) Snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.lines))
	copy(out, r.lines)
	return out
}

// Clear empties the buffer.
func (r *logRing) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = nil
	r.partial = ""
}

var ring = newLogRing(500)

// InstallLogCapture routes the standard log package into the ring (and
// still prints to stderr so CLI/debug output is unaffected).
func InstallLogCapture() {
	log.SetOutput(io.MultiWriter(os.Stderr, ring))
}
