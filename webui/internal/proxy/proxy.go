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

// Package proxy implements the SOCKS5 listener and the upstream HTTP/2 CONNECT
// tunnel to a selected Firefox VPN server, authenticated with the proxy pass.
package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/net/http2"

	utls "github.com/refraction-networking/utls"
	"time"
)

// Target is a resolved CONNECT endpoint for a server.
type Target struct {
	// Host is the server host.
	Host string
	// Port is the server TLS port (usually 443).
	Port int
}

// Addr returns host:port.
func (t Target) Addr() string { return net.JoinHostPort(t.Host, fmt.Sprint(t.Port)) }

// Dialer dials a client CONNECT destination through the active VPN server.
type Dialer func(ctx context.Context, dst string) (net.Conn, error)

// Server is the SOCKS5 listener.
type Server struct {
	Listen string
	// Dial connects to the destination through the VPN.
	Dial Dialer
	// Auth validates SOCKS5 user/pass; nil disables.
	Auth func(user, pass string) bool
	// Timeout bounds upstream dials.
	Timeout time.Duration

	mu     sync.Mutex
	closed bool
	ln     net.Listener
}

// ListenAndServe serves SOCKS5 until Close.
func (s *Server) ListenAndServe() error {
	if s.Dial == nil {
		return errors.New("proxy: nil Dial")
	}
	if s.Timeout <= 0 {
		s.Timeout = 20 * time.Second
	}
	ln, err := net.Listen("tcp", s.Listen)
	if err != nil {
		return fmt.Errorf("proxy listen %s: %w", s.Listen, err)
	}
	s.ln = ln
	log.Printf("proxy: SOCKS5 listening on %s", s.Listen)
	for {
		c, err := ln.Accept()
		if err != nil {
			if s.isClosed() {
				return nil
			}
			continue
		}
		go s.handle(c)
	}
}

// Close stops the listener.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	if s.ln != nil {
		return s.ln.Close()
	}
	return nil
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)

	// Greeting.
	method, err := readGreeting(br, s.Auth != nil)
	if err != nil {
		return
	}
	conn.Write([]byte{5, method})

	if s.Auth != nil {
		ok, err := readUserPass(br, s.Auth)
		if err != nil {
			return
		}
		if !ok {
			conn.Write([]byte{1, 1})
			return
		}
		conn.Write([]byte{1, 0})
	}

	// Request.
	cmd, dst, err := readRequest(br)
	if err != nil {
		conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	if cmd != 1 {
		conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()
	up, err := s.Dial(ctx, dst)
	if err != nil {
		conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()

	conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})

	errc := make(chan error, 2)
	go func() { errc <- copyData(conn, up) }()
	go func() { errc <- copyData(up, conn) }()
	<-errc
}

func copyData(dst, src net.Conn) error {
	_, err := io.Copy(dst, src)
	return err
}

func readGreeting(r *bufio.Reader, wantUser bool) (byte, error) {
	ver := []byte{0}
	if _, err := io.ReadFull(r, ver); err != nil {
		return 0, err
	}
	if ver[0] != 5 {
		return 0, errors.New("bad version")
	}
	n := []byte{0}
	if _, err := io.ReadFull(r, n); err != nil {
		return 0, err
	}
	methods := make([]byte, int(n[0]))
	if _, err := io.ReadFull(r, methods); err != nil {
		return 0, err
	}
	want := byte(0)
	if wantUser {
		want = 2
	}
	for _, m := range methods {
		if m == want {
			return want, nil
		}
	}
	return 0xFF, nil
}

func readUserPass(r *bufio.Reader, check func(u, p string) bool) (bool, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return false, err
	}
	un := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(r, un); err != nil {
		return false, err
	}
	pl := []byte{0}
	if _, err := io.ReadFull(r, pl); err != nil {
		return false, err
	}
	pw := make([]byte, int(pl[0]))
	if _, err := io.ReadFull(r, pw); err != nil {
		return false, err
	}
	return check(string(un), string(pw)), nil
}

func readRequest(r *bufio.Reader) (byte, string, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, "", err
	}
	if hdr[0] != 5 {
		return 0, "", errors.New("bad version")
	}
	var host string
	switch hdr[3] {
	case 1:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(r, ip); err != nil {
			return 0, "", err
		}
		host = net.IP(ip).String()
	case 4:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(r, ip); err != nil {
			return 0, "", err
		}
		host = net.IP(ip).String()
	case 3:
		l := []byte{0}
		if _, err := io.ReadFull(r, l); err != nil {
			return 0, "", err
		}
		name := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, name); err != nil {
			return 0, "", err
		}
		host = string(name)
	default:
		return 0, "", errors.New("bad atyp")
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(r, port); err != nil {
		return 0, "", err
	}
	return hdr[1], net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(port))), nil
}

// HTTP2Dialer returns a Dialer that tunnels through the given Firefox VPN
// server over HTTP/2 CONNECT, authenticated with the proxy pass.
// HTTP2Dialer returns a Dialer that tunnels through the MASQUE edge. The
// proxy pass comes from bearerProvider when the edge answers 401 (pass
// expired — Guardian passes are short-lived); after refreshing, the CONNECT
// is retried once, so a running proxy survives pass expiry without user
// intervention.
//
// Edge-session reuse: all tunnels multiplex over ONE persistent edge session
// (utls+h2 ClientConn). Mozilla's edge farm maps each upstream session to a
// NAT egress, so a fresh session per CONNECT would rotate the exit IP on
// every connection. One session = one stable exit IP; the session is
// re-established only when it dies or the pass changes.
// DialerOption customizes the MASQUE dialer (tests use it to skip TLS
// verification against a local mock edge; production never does).
type DialerOption func(*edgeSession)

// masqueDialer is HTTP2Dialer's return type: a Dialer that also reports
// edge-session diagnostics.
type MasqueDialer struct {
	fn Dialer
	s  *edgeSession
	// keepaliveStop ends the session keepalive loop on Close.
	keepaliveStop chan struct{}

	// passMu guards proxyPass (the current raw pass used by new CONNECTs).
	passMu    sync.Mutex
	proxyPass string
	// renewProvider fetches a fresh pass BEFORE the current one expires so
	// the edge never tears down the session for auth — preserving the egress
	// IP. Mirrors firefox-vpn-client's runRenewalLoop (renew lead 2 min).
	renewProvider func() (string, error)
	// renewStop ends the renewal loop on Close.
	renewStop chan struct{}
}

// SetRenewProvider installs the proactive pass-renewal provider. The
// provider (the webapp's refreshProxyPass healing chain) is invoked ~2 min
// before the current pass expires; the fresh pass is swapped in without
// touching the edge session.
func (m *MasqueDialer) SetRenewProvider(provider func() (string, error), expiresAt time.Time) {
	m.renewProvider = provider
	if expiresAt.IsZero() {
		return
	}
	if m.renewStop != nil {
		select {
		case <-m.renewStop:
		default:
			close(m.renewStop)
		}
	}
	m.renewStop = make(chan struct{})
	go m.renewalLoop(expiresAt)
}

// UpdatePass swaps the current pass atomically; new CONNECTs use it
// immediately on the SAME edge session.
func (m *MasqueDialer) UpdatePass(raw string) {
	m.passMu.Lock()
	m.proxyPass = raw
	m.passMu.Unlock()
}

func (m *MasqueDialer) currentPass() string {
	m.passMu.Lock()
	defer m.passMu.Unlock()
	return m.proxyPass
}

// renewalLoop renews the pass 2 minutes before it expires, indefinitely.
func (m *MasqueDialer) renewalLoop(expiresAt time.Time) {
	for {
		delay := time.Until(expiresAt.Add(-2 * time.Minute))
		if delay <= 0 {
			delay = time.Second
		}
		select {
		case <-m.renewStop:
			return
		case <-time.After(delay):
		}
		if m.renewProvider == nil {
			return
		}
		np, err := m.renewProvider()
		if err != nil {
			// Retry shortly; the in-band 401 path still covers us.
			select {
			case <-m.renewStop:
				return
			case <-time.After(30 * time.Second):
			}
			continue
		}
		expiresAt = time.Now().Add(30 * time.Minute) // Guardian pass TTL guard
		m.UpdatePass(np)
	}
}

// Close stops the keepalive + renewal loops and drops the edge session.
func (m *MasqueDialer) Close() {
	if m.keepaliveStop != nil {
		select {
		case <-m.keepaliveStop:
		default:
			close(m.keepaliveStop)
		}
	}
	if m.renewStop != nil {
		select {
		case <-m.renewStop:
		default:
			close(m.renewStop)
		}
	}
	m.s.reset()
}

func (m *MasqueDialer) Dial(ctx context.Context, dst string) (net.Conn, error) {
	return m.fn(ctx, dst)
}

// Generation reports how many distinct edge sessions have been built.
func (m *MasqueDialer) Generation() int64 { return m.s.Generation() }

// WithInsecureTLS skips edge-certificate verification. Test-only.
func WithInsecureTLS() DialerOption { return func(s *edgeSession) { s.insecureTLS = true } }

func HTTP2Dialer(host string, port int, proxyPass string, bearerProvider func() (string, error), opts ...DialerOption) *MasqueDialer {
	s := &edgeSession{host: host, port: port, transport: &http2.Transport{
		// Detect a dead idle edge session quickly: the edge sends PING when
		// the stream stays idle; if no ack comes back the session is marked
		// closed and the next dial rebuilds instead of hanging on a zombie.
		ReadIdleTimeout:  30 * time.Second,
		PingTimeout:      15 * time.Second,
		WriteByteTimeout: 15 * time.Second,
	}}
	for _, o := range opts {
		o(s)
	}
	m := &MasqueDialer{s: s, proxyPass: proxyPass}
	m.fn = func(ctx context.Context, dst string) (net.Conn, error) {
		conn, err := s.dial(ctx, dst, m.currentPass())
		if err == nil {
			return conn, nil
		}
		// 401 = expired/invalid pass → refresh via the provider; any other
		// dial error (dead idle edge session, network blip) → just rebuild
		// the session. Either way reset + retry exactly once.
		if strings.Contains(err.Error(), "HTTP 401") && bearerProvider != nil {
			fresh, perr := bearerProvider()
			if perr != nil {
				return nil, fmt.Errorf("proxy pass refresh failed: %w (first error: %v)", perr, err)
			}
			m.UpdatePass(fresh)
		}
		s.reset()
		conn, err = s.dial(ctx, dst, m.currentPass())
		return conn, err
	}
	// Background keepalive: ping the edge session while it is idle so the
	// server does not reap it (Mozilla edges drop sessions after a few idle
	// minutes — diagnostics confirmed the exit IP rotates exactly when the
	// session count bumps). A failed ping drops the session; the next dial
	// rebuilds. Mirrors firefox-vpn-client's runKeepAlive.
	m.keepaliveStop = make(chan struct{})
	go s.keepalive(m.keepaliveStop, 45*time.Second)
	return m
}

// keepalive pings the live edge session on an interval. Between manual
// clicks there are no active streams (so the transport-level idle PINGs
// never fire); this explicit loop keeps the session from being reaped.
func (s *edgeSession) keepalive(stop <-chan struct{}, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			s.mu.Lock()
			cc := s.cc
			s.mu.Unlock()
			if cc == nil {
				continue
			}
			pctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := cc.Ping(pctx)
			cancel()
			if err != nil {
				// Session is dead (network drop / edge reaped it). Drop it;
				// the next dial establishes a fresh one.
				s.reset()
			}
		}
	}
}

// edgeSession is a single reusable MASQUE edge session (utls + http2).
type edgeSession struct {
	mu          sync.Mutex
	host        string
	port        int
	transport   *http2.Transport
	cc          *http2.ClientConn
	tconn       *utls.UConn
	insecureTLS bool
	generation  int64 // bumped each time a NEW edge session is established
}

// Generation reports how many distinct edge sessions the dialer has built.
// A stable exit IP needs this to stay at 1 across repeated dials.
func (s *edgeSession) Generation() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generation
}

// get returns the live edge session, establishing one if absent or dead.
func (s *edgeSession) get(ctx context.Context) (*http2.ClientConn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cc != nil && s.cc.CanTakeNewRequest() {
		return s.cc, nil
	}
	s.closeLocked()
	proxyHost := net.JoinHostPort(s.host, fmt.Sprint(s.port))
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", proxyHost)
	if err != nil {
		return nil, err
	}
	tconn := utls.UClient(rawConn, &utls.Config{
		ServerName:         s.host,
		MinVersion:         utls.VersionTLS12,
		NextProtos:         []string{"h2"},
		InsecureSkipVerify: s.insecureTLS,
	}, utls.HelloFirefox_Auto)
	if err := tconn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	if tconn.ConnectionState().NegotiatedProtocol != "h2" {
		tconn.Close()
		return nil, errors.New("server did not negotiate h2")
	}
	cc, err := s.transport.NewClientConn(tconn)
	if err != nil {
		tconn.Close()
		return nil, err
	}
	s.cc = cc
	s.tconn = tconn
	s.generation++
	return cc, nil
}

// reset tears the session down; the next dial builds a fresh one.
func (s *edgeSession) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked()
}

func (s *edgeSession) closeLocked() {
	if s.cc != nil {
		_ = s.cc.Close()
		s.cc = nil
	}
	if s.tconn != nil {
		_ = s.tconn.Close()
		s.tconn = nil
	}
}

// dial issues one CONNECT tunnel over the shared edge session.
func (s *edgeSession) dial(ctx context.Context, dst, proxyPass string) (net.Conn, error) {
	cc, err := s.get(ctx)
	if err != nil {
		return nil, err
	}
	proxyHost := net.JoinHostPort(s.host, fmt.Sprint(s.port))
	// Bidirectional tunnel: http2 CONNECT reads the request body to send
	// client->upstream data, and returns the upstream->client stream in the
	// response body. Wire them with an io.Pipe.
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "http://"+dst, pr)
	if err != nil {
		pw.Close()
		return nil, err
	}
	req.Host = dst
	req.URL.Host = proxyHost
	// The caller passes the raw JWT; a double "Bearer Bearer ..." or
	// missing scheme both make the edge answer "parsing JWT failed".
	auth := proxyPass
	if !strings.HasPrefix(auth, "Bearer ") {
		auth = "Bearer " + auth
	}
	req.Header.Set("Proxy-Authorization", auth)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		pw.Close()
		// A failed RoundTrip often means the shared session died; drop it so
		// the next dial establishes a fresh one.
		s.reset()
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		resp.Body.Close()
		pw.Close()
		return nil, fmt.Errorf("connect refused (HTTP %d)", resp.StatusCode)
	}
	return &http2TunnelConn{reader: resp.Body, writer: pw, cc: cc}, nil
}

// http2TunnelConn adapts an HTTP/2 CONNECT tunnel to net.Conn: reads come from
// the response body, writes go into the request body pipe.
type http2TunnelConn struct {
	reader io.ReadCloser
	writer io.WriteCloser
	cc     *http2.ClientConn
}

func (c *http2TunnelConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *http2TunnelConn) Write(p []byte) (int, error) { return c.writer.Write(p) }

// closeTunnel ends a single tunnel without tearing down the shared edge
// session: closing the request-body pipe ends the client->upstream half,
// closing the response body ends the other half. The underlying h2 session
// stays alive for the next tunnel.
func (c *http2TunnelConn) Close() error {
	_ = c.writer.Close()
	_ = c.reader.Close()
	return nil
}
func (c *http2TunnelConn) LocalAddr() net.Addr                { return nil }
func (c *http2TunnelConn) RemoteAddr() net.Addr               { return nil }
func (c *http2TunnelConn) SetDeadline(t time.Time) error      { return nil }
func (c *http2TunnelConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *http2TunnelConn) SetWriteDeadline(t time.Time) error { return nil }

// http2TunnelConn adapts an HTTP/2 CONNECT response body to net.Conn.
