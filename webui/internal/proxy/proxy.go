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
func HTTP2Dialer(host string, port int, proxyPass string) Dialer {
	transport := &http2.Transport{}
	return func(ctx context.Context, dst string) (net.Conn, error) {
		proxyHost := net.JoinHostPort(host, fmt.Sprint(port))
		dialer := &net.Dialer{Timeout: 15 * time.Second}
		rawConn, err := dialer.DialContext(ctx, "tcp", proxyHost)
		if err != nil {
			return nil, err
		}
		tconn := utls.UClient(rawConn, &utls.Config{
			ServerName: host,
			MinVersion: utls.VersionTLS12,
			NextProtos: []string{"h2"},
		}, utls.HelloFirefox_Auto)
		if err := tconn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, err
		}
		if tconn.ConnectionState().NegotiatedProtocol != "h2" {
			tconn.Close()
			return nil, errors.New("server did not negotiate h2")
		}
		cc, err := transport.NewClientConn(tconn)
		if err != nil {
			tconn.Close()
			return nil, err
		}
		// Bidirectional tunnel: http2 CONNECT reads the request body to send
		// client->upstream data, and returns the upstream->client stream in the
		// response body. Wire them with an io.Pipe.
		pr, pw := io.Pipe()
		req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "http://"+dst, pr)
		if err != nil {
			cc.Close()
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
			cc.Close()
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			resp.Body.Close()
			pw.Close()
			cc.Close()
			return nil, fmt.Errorf("connect refused (HTTP %d)", resp.StatusCode)
		}
		return &http2TunnelConn{reader: resp.Body, writer: pw, cc: cc}, nil
	}
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
func (c *http2TunnelConn) Close() error {
	_ = c.writer.Close()
	_ = c.reader.Close()
	if c.cc != nil {
		_ = c.cc.Close()
	}
	return nil
}
func (c *http2TunnelConn) LocalAddr() net.Addr                { return nil }
func (c *http2TunnelConn) RemoteAddr() net.Addr               { return nil }
func (c *http2TunnelConn) SetDeadline(t time.Time) error      { return nil }
func (c *http2TunnelConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *http2TunnelConn) SetWriteDeadline(t time.Time) error { return nil }

// http2TunnelConn adapts an HTTP/2 CONNECT response body to net.Conn.
