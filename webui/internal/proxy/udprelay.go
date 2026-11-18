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

package proxy

// MASQUE UDP relay: RFC 9298 CONNECT-UDP over the existing HTTP/2 edge
// session, so UDP datagrams (torrent udp:// trackers, DHT, QUIC, DNS)
// traverse the same Mozilla edge that carries the TCP tunnels.
//
// Discovered live: the fastly-masque edge answers
// GET /.well-known/masque/udp/ with "405 method not allowed" — the route
// EXISTS and expects the RFC 9298 extended CONNECT (:protocol: connect-udp).
// The official Mozilla VPN client instead ships full WireGuard (UDP at the
// IP layer) registered per-device via Guardian /api/v1/vpn/device — that
// path needs a device public key + system TUN and is a different feature;
// for the proxy-pass flow (what fxvpn has), CONNECT-UDP is the only UDP
// carrier the edge offers.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// udpContextTimeout bounds a CONNECT-UDP session handshake.
const udpSessionTimeout = 12 * time.Second

// ErrUDPSession marks CONNECT-UDP session failures (401 refresh handled by
// the caller, edge rejection, unsupported).
var ErrUDPSession = errors.New("proxy: CONNECT-UDP session failed")

// udpSession is one RFC 9298 CONNECT-UDP tunnel: a stream-paired net.Conn
// carrying UDP datagrams wrapped in the HTTP Datagrams capsule format.
type udpSession struct {
	tun  net.Conn // the CONNECT tunnel (http2TunnelConn)
	flow []byte   // pending datagram bytes (capsule-unwrapped)
	mu   sync.Mutex
}

// readCapsule reads one HTTP Datagram capsule from the tunnel.
// Capsule format: 1-byte type, variable-length int length, payload.
// We only care about type 0x00 (HTTP DATAGRAM).
func readCapsule(r io.Reader) (dtype byte, payload []byte, err error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr[:1]); err != nil {
		return 0, nil, err
	}
	dtype = hdr[0]
	// Variable-length integer (RFC 9000 §16).
	var length uint64
	b := make([]byte, 1)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, nil, err
	}
	switch prefix := b[0] >> 6; {
	case prefix == 0:
		length = uint64(b[0] & 0x3F)
	case prefix == 1:
		ext := make([]byte, 1)
		if _, err := io.ReadFull(r, ext); err != nil {
			return 0, nil, err
		}
		length = uint64(b[0]&0x3F)<<8 | uint64(ext[0])
	case prefix == 2:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(r, ext); err != nil {
			return 0, nil, err
		}
		length = uint64(b[0]&0x3F)<<16 | uint64(ext[0])<<8 | uint64(ext[1])
	default:
		ext := make([]byte, 4)
		if _, err := io.ReadFull(r, ext); err != nil {
			return 0, nil, err
		}
		length = uint64(b[0]&0x3F)<<24 | uint64(ext[0])<<16 | uint64(ext[1])<<8 | uint64(ext[2])
	}
	payload = make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return dtype, payload, nil
}

// writeCapsule writes one HTTP Datagram capsule.
func writeCapsule(w io.Writer, dtype byte, payload []byte) error {
	// Variable-length int (RFC 9000 §16): 1/2/4-byte forms.
	var hdr []byte
	switch {
	case len(payload) < 64:
		hdr = []byte{dtype, byte(len(payload))}
	case len(payload) < 0x4000:
		hdr = []byte{dtype, byte(0x40 | (len(payload) >> 8)), byte(len(payload))}
	default:
		hdr = []byte{dtype, 0x40 | byte(len(payload)>>16), byte(len(payload) >> 8), byte(len(payload))}
	}
	// ONE write: header+payload must land as a unit — splitting into two
	// writes can produce two TCP segments, and a gateway reading one
	// segment at a time would see a bare capsule header with no payload.
	out := make([]byte, 0, len(hdr)+len(payload))
	out = append(out, hdr...)
	out = append(out, payload...)
	_, err := w.Write(out)
	return err
}

// writeUDPCapsule wraps a UDP datagram (RFC 9298 §4: the QUIC stream
// carries an HTTP Datagram whose payload is the UDP payload — the QUIC
// datagram ID prefix only applies to QUIC datagram frames, not the
// capsule encoding on an h2 stream).
func writeUDPCapsule(w io.Writer, dgram []byte) error {
	return writeCapsule(w, 0x00, dgram)
}

// Read returns the next UDP datagram's payload (capsule-decoded).
func (u *udpSession) Read(p []byte) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.flow) > 0 {
		n := copy(p, u.flow)
		u.flow = u.flow[n:]
		return n, nil
	}
	for {
		dtype, payload, err := readCapsule(u.tun)
		if err != nil {
			return 0, err
		}
		switch dtype {
		case 0x00: // HTTP DATAGRAM — the UDP payload
			n := copy(p, payload)
			if n < len(payload) {
				u.flow = append([]byte(nil), payload[n:]...)
			}
			return n, nil
		default:
			// Other capsule types (CLOSE, etc.) — skip.
		}
	}
}

// Write sends one UDP datagram as a capsule.
func (u *udpSession) Write(p []byte) (int, error) {
	if err := writeUDPCapsule(u.tun, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (u *udpSession) Close() error                 { return u.tun.Close() }
func (u *udpSession) LocalAddr() net.Addr          { return nil }
func (u *udpSession) RemoteAddr() net.Addr         { return nil }
func (u *udpSession) SetDeadline(t time.Time) error      { return u.tun.SetDeadline(t) }
func (u *udpSession) SetReadDeadline(t time.Time) error  { return u.tun.SetReadDeadline(t) }
func (u *udpSession) SetWriteDeadline(t time.Time) error { return u.tun.SetWriteDeadline(t) }

// dialUDPSession opens an RFC 9298 CONNECT-UDP session to host:port over the
// pooled MASQUE edge, authenticated with the current proxy pass. It uses
// the same edge sessions as TCP CONNECT (same exit IP, same pass rotation).
func (m *MasqueDialer) dialUDPSession(ctx context.Context, host string, port int) (net.Conn, error) {
	dst := net.JoinHostPort(host, fmt.Sprint(port))
	// RFC 9298: path is /.well-known/masque/udp/{host}/{port}/
	path := fmt.Sprintf("/.well-known/masque/udp/%s/%d/", host, port)

	ses, err := m.pool.acquire(ctx, m.host, m.port, m.insecureTLS)
	if err != nil {
		return nil, err
	}

	proxyHost := net.JoinHostPort(m.host, fmt.Sprint(m.port))
	pr, pw := io.Pipe()
	auth := m.currentPass()
	if !strings.HasPrefix(auth, "Bearer ") {
		auth = "Bearer " + auth
	}

	// Extended CONNECT via x/net http2: Method=CONNECT + :protocol header
	// (transport.go:1502 — req.Header[":protocol"] triggers the extended
	// CONNECT path when the server advertises SETTINGS_ENABLE_CONNECT_PROTOCOL).
	// http.Header with a colon key is emitted verbatim by enumerateHeaders.
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+proxyHost+path, pr)
	if err != nil {
		pw.Close()
		return nil, err
	}
	req.Host = proxyHost
	req.URL.Host = proxyHost
	req.Header.Set(":protocol", "connect-udp")
	req.Header.Set("Proxy-Authorization", auth)
	req.Header.Set("Capsule-Protocol", "true")

	// Reserve the session like dial() does.
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

	type rtResult struct {
		resp *http.Response
		err  error
	}
	rtCh := make(chan rtResult, 1)
	go func() {
		resp, rerr := ses.cc.RoundTrip(req)
		rtCh <- rtResult{resp, rerr}
	}()
	var resp *http.Response
	select {
	case r := <-rtCh:
		if r.err != nil {
			pw.Close()
			release()
			ses.mu.Lock()
			ses.closeLocked()
			ses.mu.Unlock()
			return nil, fmt.Errorf("%w: %v (target %s)", ErrUDPSession, r.err, dst)
		}
		resp = r.resp
	case <-time.After(udpSessionTimeout):
		pw.Close()
		release()
		ses.mu.Lock()
		ses.closeLocked()
		ses.mu.Unlock()
		return nil, fmt.Errorf("%w: handshake timed out (%s)", ErrUDPSession, dst)
	}

	if resp.StatusCode != http.StatusOK {
		body := make([]byte, 256)
		n, _ := io.ReadFull(resp.Body, body)
		resp.Body.Close()
		pw.Close()
		release()
		log.Printf("proxy: UDP CONNECT-UDP to %s:%d FAILED — edge answered HTTP %d: %s",
			host, port, resp.StatusCode, strings.TrimSpace(string(body[:n])))
		return nil, fmt.Errorf("%w: edge answered HTTP %d for %s: %s",
			ErrUDPSession, resp.StatusCode, dst, strings.TrimSpace(string(body[:n])))
	}
	log.Printf("proxy: UDP CONNECT-UDP session to %s:%d established via %s (exit = MASQUE edge)", host, port, proxyHost)

	tc := &http2TunnelConn{
		reader:  resp.Body,
		writer:  pw,
		cc:      ses.cc,
		onClose: release,
	}
	return &udpSession{tun: tc}, nil
}

// sockUDPProxy serves one UDP ASSOCIATE: a local UDP socket that maps each
// client (srcIP, dstHostPort) tuple to a CONNECT-UDP session through the
// edge. Replies (tracker responses) flow back to the client's UDP endpoint.
type sockUDPProxy struct {
	srv    *Server
	socket *net.UDPConn
	addr   *net.UDPAddr
	mu          sync.Mutex
	conns       map[string]net.Conn // "host:port" → CONNECT-UDP session
	lastSrc     map[string]*net.UDPAddr
	stop        chan struct{}
	pumpStarted bool
}

func newUDPRelay(srv *Server) (*sockUDPProxy, error) {
	// Bind the relay on the SAME port as the SOCKS5 TCP listener (RFC 1928
	// §6: BND.PORT is advisory, clients send datagrams there; sharing one
	// port TCP+UDP is the de-facto behavior every real SOCKS5 server uses).
	// Critical for docker: compose maps exactly one port pair (1080/1080) —
	// a random relay port would be unreachable from outside the container
	// and every tracker datagram would silently die at the NAT layer.
	var bind *net.UDPAddr
	if host, portStr, err := net.SplitHostPort(srv.Listen); err == nil {
		if port, perr := strconv.Atoi(portStr); perr == nil {
			// Listen on all interfaces of the same address family the TCP
			// listener uses; empty host or 0.0.0.0 → wildcard.
			ip := net.IPv4zero
			if host != "" && host != "0.0.0.0" && host != "::" {
				ip = net.ParseIP(host)
				if ip == nil {
					ip = net.IPv4zero
				}
			}
			bind = &net.UDPAddr{IP: ip, Port: port}
		}
	}
	if bind == nil {
		bind = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	}
	socket, err := net.ListenUDP("udp", bind)
	if err != nil {
		// Port already taken (rare — TCP and UDP namespaces are separate,
		// but a second association while the first lives rebinds fine since
		// we reuse ONE relay per association... we bind per association, so
		// a second concurrent ASSOCIATE on the same port fails): fall back
		// to a random port and say so — the docker mapping won't cover it.
		socket, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			return nil, err
		}
		log.Printf("proxy: UDP relay could not bind %s (in use?) — fell back to random port %d; OUTSIDE the container this port is unreachable",
			bind, socket.LocalAddr().(*net.UDPAddr).Port)
	}
	return &sockUDPProxy{
		srv:    srv,
		socket: socket,
		addr:   socket.LocalAddr().(*net.UDPAddr),
		conns:   map[string]net.Conn{},
		lastSrc: map[string]*net.UDPAddr{},
		stop:    make(chan struct{}),
	}, nil
}

func (u *sockUDPProxy) close() {
	u.mu.Lock()
	select {
	case <-u.stop:
	default:
		close(u.stop)
	}
	u.mu.Unlock()
	u.socket.Close()
	u.mu.Lock()
	for _, c := range u.conns {
		c.Close()
	}
	u.conns = map[string]net.Conn{}
	u.mu.Unlock()
}

// serve starts the datagram pump (once, on the shared relay) and waits
// until this association's TCP control connection drops. The socket and
// pump live as long as the Server; a new ASSOCIATE just reuses them.
func (u *sockUDPProxy) serve(control net.Conn, srv *Server) {
	u.startPump()
	io.Copy(io.Discard, control)
	log.Printf("proxy: UDP ASSOCIATE from %s closed (relay socket stays for other associations)", control.RemoteAddr())
}

// startPump launches the datagram reader exactly once.
func (u *sockUDPProxy) startPump() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.pumpStarted {
		return
	}
	u.pumpStarted = true
	go u.readDatagrams()
}

// readDatagrams consumes client datagrams for the relay's lifetime.
func (u *sockUDPProxy) readDatagrams() {
	buf := make([]byte, 65536)
	for {
		n, src, err := u.socket.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("proxy: UDP relay read error: %v", err)
			return
		}
		host, port, payload, err := parseUDPHeader(buf[:n])
		if err != nil {
			log.Printf("proxy: UDP relay bad datagram from %s: %v", src, err)
			continue
		}
		key := net.JoinHostPort(host, fmt.Sprint(port))
		u.mu.Lock()
		u.lastSrc[key] = src
		u.mu.Unlock()
		if !u.hasSession(key) {
			log.Printf("proxy: UDP datagram %d bytes → %s:%d (first for this dst — opening CONNECT-UDP session)", len(payload), host, port)
		}
		sess, err := u.sessionFor(host, port)
		if err != nil {
			log.Printf("proxy: UDP relay %s:%d session: %v", host, port, err)
			continue
		}
		if _, err := sess.Write(payload); err != nil {
			log.Printf("proxy: UDP relay %s:%d write: %v", host, port, err)
			u.dropSession(key)
		}
	}
}

// hasSession reports whether a CONNECT-UDP session for dst already exists.
func (u *sockUDPProxy) hasSession(key string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	_, ok := u.conns[key]
	return ok
}

// sessionFor returns (and lazily creates) the CONNECT-UDP session for dst.
func (u *sockUDPProxy) sessionFor(host string, port int) (net.Conn, error) {
	key := net.JoinHostPort(host, fmt.Sprint(port))
	u.mu.Lock()
	if c, ok := u.conns[key]; ok {
		u.mu.Unlock()
		return c, nil
	}
	u.mu.Unlock()

	if u.srv.DialUDP == nil {
		return nil, errors.New("UDP relay disabled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), udpSessionTimeout)
	defer cancel()
	sess, err := u.srv.DialUDP(ctx, host, port)
	if err != nil {
		return nil, err
	}
	u.mu.Lock()
	// Double-check after the async dial.
	if c, ok := u.conns[key]; ok {
		u.mu.Unlock()
		sess.Close()
		return c, nil
	}
	u.conns[key] = sess
	u.mu.Unlock()

	// Response pump: datagrams from the edge go back to the client with a
	// SOCKS5 UDP header. The client's endpoint is unknown until it sends;
	// remember the last source per key.
	go u.pumpResponses(key, sess)
	return sess, nil
}

// lastSrc tracks the client's UDP endpoint per destination.
func (u *sockUDPProxy) pumpResponses(key string, sess net.Conn) {
	buf := make([]byte, 65536)
	for {
		n, err := sess.Read(buf)
		if err != nil {
			log.Printf("proxy: UDP relay %s response pump ended: %v", key, err)
			u.dropSession(key)
			return
		}
		log.Printf("proxy: UDP relay %s response %d bytes → client", key, n)
		u.mu.Lock()
		src := u.lastSrc[key]
		u.mu.Unlock()
		if src == nil {
			continue
		}
		host, portStr, _ := net.SplitHostPort(key)
		port, _ := strconv.Atoi(portStr)
		hdr, err := buildUDPHeader(host, port)
		if err != nil {
			continue
		}
		out := append(hdr, buf[:n]...)
		u.socket.WriteToUDP(out, src)
	}
}

// dropSession closes and forgets a session (edge drop, write failure).
func (u *sockUDPProxy) dropSession(key string) {
	u.mu.Lock()
	c, ok := u.conns[key]
	delete(u.conns, key)
	u.mu.Unlock()
	if ok {
		c.Close()
	}
}

// parseUDPHeader splits a SOCKS5 UDP datagram into (host, port, payload).
func parseUDPHeader(dgram []byte) (string, int, []byte, error) {
	if len(dgram) < 4 {
		return "", 0, nil, errors.New("datagram too short")
	}
	if dgram[2] != 0 {
		return "", 0, nil, errors.New("fragmented datagrams unsupported")
	}
	atyp := dgram[3]
	var host string
	var off int
	switch atyp {
	case 1: // IPv4
		if len(dgram) < 10 {
			return "", 0, nil, errors.New("bad ipv4 datagram")
		}
		host = net.IP(dgram[4:8]).String()
		off = 8
	case 4: // IPv6
		if len(dgram) < 22 {
			return "", 0, nil, errors.New("bad ipv6 datagram")
		}
		host = net.IP(dgram[4:20]).String()
		off = 20
	case 3: // domain
		if len(dgram) < 5 || len(dgram) < 5+int(dgram[4])+2 {
			return "", 0, nil, errors.New("bad domain datagram")
		}
		host = string(dgram[5 : 5+int(dgram[4])])
		off = 5 + int(dgram[4])
	default:
		return "", 0, nil, fmt.Errorf("bad atyp %d", atyp)
	}
	port := int(binary.BigEndian.Uint16(dgram[off : off+2]))
	return host, port, dgram[off+2:], nil
}

// buildUDPHeader builds the SOCKS5 UDP datagram header for a reply.
func buildUDPHeader(host string, port int) ([]byte, error) {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out := []byte{0, 0, 0, 1}
			out = append(out, v4...)
			return append(out, byte(port>>8), byte(port)), nil
		}
		out := []byte{0, 0, 0, 4}
		out = append(out, ip.To16()...)
		return append(out, byte(port>>8), byte(port)), nil
	}
	// Domain reply (rare — trackers announce by name; replies come from IPs).
	return nil, fmt.Errorf("cannot build UDP header for %q", host)
}
