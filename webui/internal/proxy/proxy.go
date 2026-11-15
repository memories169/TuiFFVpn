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
type DialerOption func(*MasqueDialer)

// masqueDialer is HTTP2Dialer's return type: a Dialer that also reports
// edge-session diagnostics.
type MasqueDialer struct {
	fn   Dialer
	pool *sessionPool
	// host/port/insecureTLS describe the edge endpoint for new sessions.
	host        string
	port        int
	insecureTLS bool
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

// ResetSession tears down the ENTIRE pool unconditionally (test-connection
// retry path). Rationale: the pooled sessions may be invalidated
// server-side (edge NAT/state expiry after hours) while still looking
// healthy client-side — keeping them would poison the retry, and live
// traffic on a server-invalidated session is already dead; sing-box
// reconnects instantly on its own.
func (m *MasqueDialer) ResetSession() {
	m.pool.mu.Lock()
	sessions := m.pool.sessions
	m.pool.sessions = nil
	m.pool.mu.Unlock()
	for _, ses := range sessions {
		ses.reset()
	}
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

// Close stops the keepalive + renewal loops and drops all sessions.
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
	m.ResetSession()
}

func (m *MasqueDialer) Dial(ctx context.Context, dst string) (net.Conn, error) {
	return m.fn(ctx, dst)
}

// Generation reports how many distinct edge sessions have been built.
func (m *MasqueDialer) Generation() int64 {
	m.pool.mu.Lock()
	defer m.pool.mu.Unlock()
	return m.pool.gen
}

// WithInsecureTLS skips edge-certificate verification. Test-only.
func WithInsecureTLS() DialerOption { return func(m *MasqueDialer) { m.insecureTLS = true } }

func HTTP2Dialer(host string, port int, proxyPass string, bearerProvider func() (string, error), opts ...DialerOption) *MasqueDialer {
	m := &MasqueDialer{
		pool:        &sessionPool{},
		host:        host,
		port:        port,
		insecureTLS: false,
		proxyPass:   proxyPass,
	}
	for _, o := range opts {
		o(m)
	}
	m.fn = func(ctx context.Context, dst string) (net.Conn, error) {
		conn, err := m.dial(ctx, dst, m.currentPass())
		if err == nil {
			return conn, nil
		}
		// 401 = expired/invalid pass → refresh via the provider; any other
		// dial error (dead idle edge session, network blip) → the failed
		// session was already dropped inside dial(); retry once — acquire()
		// will pick another pooled session or open a new one.
		if strings.Contains(err.Error(), "HTTP 401") && bearerProvider != nil {
			fresh, perr := bearerProvider()
			if perr != nil {
				return nil, fmt.Errorf("proxy pass refresh failed: %w (first error: %v)", perr, err)
			}
			m.UpdatePass(fresh)
		}
		conn, err = m.dial(ctx, dst, m.currentPass())
		return conn, err
	}
	// Background keepalive: ping pooled sessions while idle so the server
	// does not reap them (Mozilla edges drop sessions after a few idle
	// minutes). A failed ping marks the session dead only when it has no
	// in-flight tunnels; the next dial rebuilds. Mirrors firefox-vpn-client's
	// runKeepAlive.
	m.keepaliveStop = make(chan struct{})
	go m.keepalive(m.keepaliveStop, 45*time.Second)
	return m
}

// keepalive pings every pooled session on an interval. Between client
// clicks there are no active streams (so transport-level idle PINGs never
// fire); this loop keeps sessions from being reaped.
func (m *MasqueDialer) keepalive(stop <-chan struct{}, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			m.pool.mu.Lock()
			sessions := append([]*edgeSession(nil), m.pool.sessions...)
			m.pool.mu.Unlock()
			for _, ses := range sessions {
				ses.mu.Lock()
				cc := ses.cc
				open := ses.openTunnels
				ses.mu.Unlock()
				if cc == nil {
					continue
				}
				pctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				err := cc.Ping(pctx)
				cancel()
				if err != nil && open == 0 {
					// Only tear down idle sessions — never kill one with
					// traffic in flight.
					ses.reset()
				}
			}
		}
	}
}

// keepalive pings the live edge session on an interval. Between manual
// clicks there are no active streams (so the transport-level idle PINGs
// never fire); this explicit loop keeps the session from being reaped.

// edgeSession is a single reusable MASQUE edge session (utls + http2).
// sessionPool holds the dialer's live edge sessions.
type sessionPool struct {
	mu       sync.Mutex
	sessions []*edgeSession
	gen      int64
}

type edgeSession struct {
	mu          sync.Mutex
	host        string
	port        int
	cc          *http2.ClientConn
	tconn       *utls.UConn
	insecureTLS bool
	generation  int64     // bumped when this session is established
	openTunnels int       // tunnels currently open on this session
	lastUsed    time.Time // last time a CONNECT was issued on this session
	createdAt   time.Time // when this session was established (age cap)
}

// maxStreamsPerSession caps concurrent tunnels per edge session (sing-box
// default 32): when full, NEW dials go onto another session — existing
// sessions are left to drain, never torn down under live traffic.
const maxStreamsPerSession = 32

// maxSessionsPerDialer bounds the session pool (like sing-box's upstream
// session pool). Beyond it, the least-loaded session is used anyway.
const maxSessionsPerDialer = 8

// maxSessionAge caps how long a session may serve NEW tunnels (10 min —
// opera-proxy's lesson: nothing long-lived can break mid-use). Mozilla
// edges kill long-lived h2 sessions server-side after a while; retiring
// sessions proactively (once drained) means the kill moment never lands
// on live traffic — the dial that would have hit it rotates onto a fresh
// session instead.
const maxSessionAge = 10 * time.Minute

// Generation reports how many distinct edge sessions the dialer has built.
// A stable exit IP needs this to stay at 1 across repeated dials.
func (s *edgeSession) Generation() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generation
}

// acquire returns a session with capacity for one more tunnel, creating one
// when needed. Sessions with in-flight tunnels are NEVER closed here —
// full/idle sessions are simply not chosen; they drain on their own and get
// pruned by reapIdleLocked.
func (p *sessionPool) acquire(ctx context.Context, host string, port int, insecureTLS bool) (*edgeSession, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Prefer a live session with capacity.
	for _, ses := range p.sessions {
		if ses.usableLocked() {
			return ses, nil
		}
	}
	// Drop dead/full sessions beyond the pool cap before growing.
	p.pruneLocked()
	if len(p.sessions) >= maxSessionsPerDialer {
		// All sessions are full or unhealthy — use the least loaded alive one.
		var best *edgeSession
		for _, ses := range p.sessions {
			if best == nil || ses.openTunnels < best.openTunnels {
				best = ses
			}
		}
		if best != nil {
			return best, nil
		}
	}
	ses, err := newEdgeSession(ctx, host, port, insecureTLS, &p.gen)
	if err != nil {
		return nil, err
	}
	p.sessions = append(p.sessions, ses)
	return ses, nil
}

// usableLocked reports whether this session can take one more tunnel right
// now, pinging first when it has been idle long enough to be possibly reaped.
func (s *edgeSession) usableLocked() bool {
	if s.cc == nil || !s.cc.CanTakeNewRequest() || s.openTunnels >= maxStreamsPerSession {
		return false
	}
	// Age cap: retire sessions older than maxSessionAge from NEW dials.
	// Existing tunnels on them keep flowing; once drained they are pruned.
	if time.Since(s.createdAt) > maxSessionAge {
		return false
	}
	// Session hygiene (mirrors sing-box idle_timeout): a session idle for
	// too long may be half-dead — the edge reaped it but our conn object
	// doesn't know. Verify with a ping BEFORE handing it to a new CONNECT.
	// A failed ping means "do not use this session for this dial" — but
	// NEVER close it while tunnels/handshakes are in flight: closing would
	// kill those streams ("closed pipe" under sing-box load). An idle
	// session that fails the ping is closed outright.
	if idle := time.Since(s.lastUsed); idle > 25*time.Second {
		pctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		err := s.cc.Ping(pctx)
		cancel()
		if err != nil {
			if s.openTunnels == 0 {
				s.closeLocked()
			}
			return false
		}
		s.lastUsed = time.Now()
	}
	return true
}

// pruneLocked removes sessions that are closed, empty and idle past their
// usefulness. Never touches sessions with open tunnels.
func (p *sessionPool) pruneLocked() {
	keep := p.sessions[:0]
	for _, ses := range p.sessions {
		ses.mu.Lock()
		dead := ses.cc == nil
		empty := ses.openTunnels == 0
		idle := time.Since(ses.lastUsed) > 2*time.Minute
		aged := time.Since(ses.createdAt) > maxSessionAge
		ses.mu.Unlock()
		if dead || ((empty && idle) || (empty && aged)) {
			ses.closeLocked()
			continue
		}
		keep = append(keep, ses)
	}
	p.sessions = keep
}

// newEdgeSession dials TCP+utls+h2 to the edge and returns a live session.
func newEdgeSession(ctx context.Context, host string, port int, insecureTLS bool, gen *int64) (*edgeSession, error) {
	proxyHost := net.JoinHostPort(host, fmt.Sprint(port))
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", proxyHost)
	if err != nil {
		return nil, err
	}
	tconn := utls.UClient(rawConn, &utls.Config{
		ServerName:         host,
		MinVersion:         utls.VersionTLS12,
		NextProtos:         []string{"h2"},
		InsecureSkipVerify: insecureTLS,
	}, utls.HelloFirefox_Auto)
	if err := tconn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	if tconn.ConnectionState().NegotiatedProtocol != "h2" {
		tconn.Close()
		return nil, errors.New("server did not negotiate h2")
	}
	transport := &http2.Transport{
		ReadIdleTimeout:  30 * time.Second,
		PingTimeout:      15 * time.Second,
		WriteByteTimeout: 15 * time.Second,
	}
	cc, err := transport.NewClientConn(tconn)
	if err != nil {
		tconn.Close()
		return nil, err
	}
	if gen != nil {
		*gen++
	}
	return &edgeSession{
		mu:          sync.Mutex{},
		cc:          cc,
		tconn:       tconn,
		host:        host,
		port:        port,
		insecureTLS: insecureTLS,
		generation:  derefGen(gen),
		lastUsed:    time.Now(),
		createdAt:   time.Now(),
	}, nil
}

func derefGen(gen *int64) int64 {
	if gen == nil {
		return 0
	}
	return *gen
}

// canReset reports whether no tunnels are currently open on the session.
func (s *edgeSession) canReset() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.openTunnels == 0
}

// reset tears the session down; only safe when no tunnels are in flight
// (callers gate with canReset or accept the disconnect explicitly).
func (s *edgeSession) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked()
}

// closeLocked closes the underlying connection. Callers must hold s.mu.
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

// dial issues one CONNECT tunnel over a pooled edge session.
func (m *MasqueDialer) dial(ctx context.Context, dst, proxyPass string) (net.Conn, error) {
	ses, err := m.pool.acquire(ctx, m.host, m.port, m.insecureTLS)
	if err != nil {
		return nil, err
	}
	proxyHost := net.JoinHostPort(m.host, fmt.Sprint(m.port))
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
	// Reserve the session BEFORE starting the CONNECT: keepalive/prune must
	// never reap a session with an in-flight handshake (the busy counter
	// only counted established tunnels before — an in-flight CONNECT was
	// invisible, and a concurrent reap killed it with "closed pipe").
	ses.mu.Lock()
	ses.openTunnels++
	ses.lastUsed = time.Now()
	ses.mu.Unlock()
	tunnelClosed := false
	release := func() {
		ses.mu.Lock()
		if !tunnelClosed {
			tunnelClosed = true
			ses.openTunnels--
		}
		ses.mu.Unlock()
	}

	// Bound the CONNECT handshake (waiting for response headers) with its
	// own 12s budget — a stalled session must fail fast here instead of
	// hanging until the caller's outer timeout.
	//
	// IMPORTANT: do NOT put this deadline into the request context —
	// x/net/http2 ties the stream's whole lifetime to req.Context(); a
	// canceled handshake context would murder the tunnel right after the
	// headers arrive ("context canceled" on every subsequent read). Instead
	// race the RoundTrip against a timer and drop the session on timeout
	// (closing the session aborts the blocked stream).
	type rtResult struct {
		resp *http.Response
		err  error
	}
	rtCh := make(chan rtResult, 1)
	go func() {
		resp, err := ses.cc.RoundTrip(req)
		rtCh <- rtResult{resp, err}
	}()
	var resp *http.Response
	select {
	case r := <-rtCh:
		if r.err != nil {
			pw.Close()
			release()
			// Mark the session dead so acquire() won't reuse it; tunnels in
			// flight on it (if any) keep their streams until they fail.
			ses.mu.Lock()
			ses.closeLocked()
			ses.mu.Unlock()
			return nil, r.err
		}
		resp = r.resp
	case <-time.After(12 * time.Second):
		pw.Close()
		release()
		ses.mu.Lock()
		ses.closeLocked()
		ses.mu.Unlock()
		return nil, errors.New("connect handshake timed out (12s) — session dropped")
	}
	tc := &http2TunnelConn{
		reader:  resp.Body,
		writer:  pw,
		cc:      ses.cc,
		onClose: release,
	}
	return tc, nil
}

// http2TunnelConn adapts an HTTP/2 CONNECT tunnel to net.Conn: reads come from
// the response body, writes go into the request body pipe.
type http2TunnelConn struct {
	reader  io.ReadCloser
	writer  io.WriteCloser
	cc      *http2.ClientConn
	onClose func()
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
	if c.onClose != nil {
		c.onClose()
	}
	return nil
}
func (c *http2TunnelConn) LocalAddr() net.Addr  { return nil }
func (c *http2TunnelConn) RemoteAddr() net.Addr { return nil }

// SetDeadline mirrors firefox-vpn-client's tunnelConn: deadlines are not
// supported for CONNECT tunnel streams. A close-based watchdog was tried
// here and caused "io: read/write on closed pipe" — the outer transport
// sets generous per-operation deadlines (TLS handshake, response header)
// that legitimately expire on slow-but-healthy tunnels, and closing the
// pipe then corrupted subsequent operations on the same tunnel. Stalls are
// handled at their proper layers instead: the 12s CONNECT handshake race
// in the dialer, session keepalive pings, the session age cap, and the
// caller's own Client.Timeout.
var errTunnelDeadline = errors.New("deadlines are not supported for HTTP CONNECT tunnel streams")

func (c *http2TunnelConn) SetDeadline(time.Time) error      { return errTunnelDeadline }
func (c *http2TunnelConn) SetReadDeadline(time.Time) error  { return errTunnelDeadline }
func (c *http2TunnelConn) SetWriteDeadline(time.Time) error { return errTunnelDeadline }

// http2TunnelConn adapts an HTTP/2 CONNECT response body to net.Conn.
