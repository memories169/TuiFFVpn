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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type cdpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cdpMessage struct {
	ID     int             `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *cdpError       `json:"error,omitempty"`
	// Session metadata for events (flat mode / automatic attach).
	SessionID string `json:"sessionId,omitempty"`
}

// cdpClient is a minimal DevTools protocol client over a single websocket.
type cdpClient struct {
	conn *websocket.Conn

	writeMu sync.Mutex
	mu      sync.Mutex
	nextID  int
	pending map[int]chan cdpMessage
	closed  bool

	events chan cdpMessage
	err    error
}

// dialCDP connects to a DevTools target websocket.
//
// Chromium only accepts a DevTools websocket whose Origin header is either
// absent or exactly the DevTools host:port — anything else gets HTTP 403.
// gorilla's Dialer sends no Origin at all (x/net/websocket always does, which
// is what produced "bad status"), so a plain dial works and, when the target
// is stale, the real HTTP status from Chrome is surfaced instead of a generic
// error.
func dialCDP(ctx context.Context, wsURL string) (*cdpClient, error) {
	d := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}
	conn, resp, err := d.DialContext(ctx, wsURL, nil)
	if err != nil {
		// resp is nil unless the handshake got an HTTP response; surface the
		// status so a stale/closed target is distinguishable from a network
		// failure.
		if resp != nil {
			body := ""
			if resp.Body != nil {
				var buf [256]byte
				n, _ := resp.Body.Read(buf[:])
				body = strings.TrimSpace(string(buf[:n]))
			}
			return nil, fmt.Errorf("dial devtools websocket: HTTP %d (%s) %s", resp.StatusCode, http.StatusText(resp.StatusCode), body)
		}
		var opErr *net.OpError
		if errors.As(err, &opErr) {
			return nil, fmt.Errorf("dial devtools websocket: %s %s: %w", opErr.Op, opErr.Addr, opErr.Err)
		}
		return nil, fmt.Errorf("dial devtools websocket: %w", err)
	}
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	conn.SetReadLimit(64 << 20)
	c := &cdpClient{
		conn:    conn,
		pending: make(map[int]chan cdpMessage),
		events:  make(chan cdpMessage, 256),
	}
	go c.readLoop()
	return c, nil
}

// readLoop demultiplexes responses by id and pushes events onto the channel.
func (c *cdpClient) readLoop() {
	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			c.mu.Lock()
			c.closed = true
			c.err = err
			pending := c.pending
			c.pending = make(map[int]chan cdpMessage)
			c.mu.Unlock()
			for _, ch := range pending {
				close(ch)
			}
			close(c.events)
			return
		}
		var msg cdpMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		if msg.ID != 0 {
			c.mu.Lock()
			ch := c.pending[msg.ID]
			delete(c.pending, msg.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- msg
			}
			continue
		}
		if msg.Method == "" {
			continue
		}
		select {
		case c.events <- msg:
		default:
			// Slow consumer: drop the event. Capture also polls, so a dropped
			// event cannot lose the token permanently.
		}
	}
}

// call sends a command and waits for its result.
func (c *cdpClient) call(ctx context.Context, method string, params any, result any) error {
	ch := make(chan cdpMessage, 1)
	c.mu.Lock()
	if c.closed {
		err := c.err
		c.mu.Unlock()
		if err == nil {
			err = errors.New("devtools connection closed")
		}
		return err
	}
	c.nextID++
	id := c.nextID
	c.pending[id] = ch
	c.mu.Unlock()

	payload := map[string]any{"id": id, "method": method}
	if params != nil {
		payload["params"] = params
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	c.writeMu.Lock()
	err = c.conn.WriteMessage(websocket.TextMessage, raw)
	c.writeMu.Unlock()
	if err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return fmt.Errorf("send %s: %w", method, err)
	}

	select {
	case msg, ok := <-ch:
		if !ok {
			return fmt.Errorf("%s: devtools connection closed", method)
		}
		if msg.Error != nil {
			return fmt.Errorf("%s: %s (code %d)", method, msg.Error.Message, msg.Error.Code)
		}
		if result != nil && len(msg.Result) > 0 {
			if err := json.Unmarshal(msg.Result, result); err != nil {
				return fmt.Errorf("%s: decode result: %w", method, err)
			}
		}
		return nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return ctx.Err()
	}
}

func (c *cdpClient) close() {
	if c == nil || c.conn == nil {
		return
	}
	_ = c.conn.Close()
}
