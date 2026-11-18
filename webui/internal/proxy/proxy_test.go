package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestSocks5HTTPTrackerOverTunnel drives the full SOCKS5 path against a mock
// edge: a tracker GET through CONNECT must round-trip.
func TestSocks5HTTPTrackerOverTunnel(t *testing.T) {
	// Mock edge: an HTTP/2 CONNECT-capable server is heavy; instead swap the
	// dialer for a direct dialer to a mock tracker and test the SOCKS5 layer.
	tracker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "d14:failure reason4:ok,e")
	}))
	defer tracker.Close()

	dst := strings.TrimPrefix(tracker.URL, "http://")
	srv := &Server{
		Timeout: 5 * time.Second,
		Dial: func(ctx context.Context, d string) (net.Conn, error) {
			return net.Dial("tcp", d)
		},
	}
	// Bind first, then let ListenAndServe re-bind the SAME address so the
	// dialed port is the accepted one.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenAddr := listener.Addr().String()
	listener.Close()
	srv.Listen = listenAddr
	go func() { _ = srv.ListenAndServe() }()
	// Wait until the listener is accepting.
	for i := 0; i < 50; i++ {
		if d, err := net.DialTimeout("tcp", listenAddr, 100*time.Millisecond); err == nil {
			d.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	c, err := net.Dial("tcp", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Greeting: no-auth.
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0 {
		t.Fatalf("greeting method = %d, want 0 (no-auth)", reply[1])
	}

	// CONNECT to the tracker.
	host, port, _ := net.SplitHostPort(dst)
	var atyp byte
	var addr []byte
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		atyp, addr = 1, ip.To4()
	} else {
		atyp, addr = 3, append([]byte{byte(len(host))}, host...)
	}
	p := uint16(0)
	fmt.Sscanf(port, "%d", &p)
	req := []byte{5, 1, 0, atyp}
	req = append(req, addr...)
	req = append(req, byte(p>>8), byte(p))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0 {
		t.Fatalf("CONNECT reply code = %d, want 0 (success)", rep[1])
	}

	// Speak HTTP/1.1 through the tunnel.
	fmt.Fprintf(c, "GET /announce?info_hash=abc HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", dst)
	r := bufio.NewReader(c)
	status, err := r.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("tracker response = %q", status)
	}

	// UDP ASSOCIATE: rejected when DialUDP is nil.
	c2, err := net.Dial("tcp", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if _, err := c2.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c2, reply); err != nil {
		t.Fatal(err)
	}
	c2.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}) // UDP ASSOCIATE
	if _, err := io.ReadFull(c2, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 7 {
		t.Fatalf("UDP ASSOCIATE (no DialUDP) reply code = %d, want 7 (command not supported)", rep[1])
	}
}

// TestSocks5UDPAssociateRelay drives the full UDP ASSOCIATE path: client
// datagrams go through a CONNECT-UDP session (mock edge echoes payloads)
// and replies come back with a proper SOCKS5 UDP header.
func TestSocks5UDPAssociateRelay(t *testing.T) {
	// Mock CONNECT-UDP "edge": a TCP server that, for each connection,
	// echoes every payload back as an HTTP Datagram capsule.
	mockLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer mockLn.Close()
	go func() {
		for {
			c, err := mockLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 65536)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					// Client sends capsules (00 len payload): unwrap, then
					// re-wrap the raw payload like a CONNECT-UDP gateway.
					b := buf[:n]
					for len(b) >= 2 && b[0] == 0x00 {
						ln := int(b[1])
						if len(b) < 2+ln {
							break
						}
						p := b[2 : 2+ln]
						out := []byte{0x00, byte(len(p))}
						out = append(out, p...)
						if _, err := c.Write(out); err != nil {
							return
						}
						b = b[2+ln:]
					}
				}
			}(c)
		}
	}()

	srv := &Server{
		Timeout: 5 * time.Second,
		Dial: func(ctx context.Context, d string) (net.Conn, error) {
			return net.Dial("tcp", d)
		},
		DialUDP: func(ctx context.Context, host string, port int) (net.Conn, error) {
			// Pretend the edge: connect to the mock and return the raw conn
			// wrapped as a udpSession-like conn (already capsule-wrapping).
			c, err := net.Dial("tcp", mockLn.Addr().String())
			if err != nil {
				return nil, err
			}
			// The client writes raw payloads; the mock wraps them. Our
			// udpSession Read expects capsules — reuse it.
			return &udpSession{tun: &pipeDup{Conn: c}}, nil
		},
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenAddr := listener.Addr().String()
	listener.Close()
	srv.Listen = listenAddr
	go func() { _ = srv.ListenAndServe() }()
	for i := 0; i < 50; i++ {
		if d, err := net.DialTimeout("tcp", listenAddr, 100*time.Millisecond); err == nil {
			d.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Control connection: UDP ASSOCIATE.
	c, err := net.Dial("tcp", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0 {
		t.Fatalf("UDP ASSOCIATE reply code = %d, want 0", rep[1])
	}
	relayPort := binary.BigEndian.Uint16(rep[8:10])

	// Send a datagram to a tracker at 93.184.216.34:6969 via the relay.
	udp, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(relayPort)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	payload := []byte("d1:rd0:...")
	dgram := []byte{0, 0, 0, 1, 93, 184, 216, 34, 0x1b, 0x39} // ipv4, port 6969
	dgram = append(dgram, payload...)
	if _, err := udp.Write(dgram); err != nil {
		t.Fatal(err)
	}
	udp.SetReadDeadline(time.Now().Add(3 * time.Second))
	rbuf := make([]byte, 65536)
	n, _, err := udp.ReadFromUDP(rbuf)
	if err != nil {
		t.Fatalf("no reply datagram: %v", err)
	}
	// Reply header: RSV FRAG 0x00 ATYP=1 ipv4 port — then echoed payload.
	if n < 10 || rbuf[3] != 1 {
		t.Fatalf("bad reply header: % x", rbuf[:min(n, 12)])
	}
	if !strings.Contains(string(rbuf[10:n]), "d1:rd0:") {
		t.Fatalf("echoed payload mismatch: %q", rbuf[10:n])
	}
}

// pipeDup wraps a net.Conn; used by tests where the "tunnel" speaks plain
// capsule framing (the mock edge does the wrapping).
type pipeDup struct{ net.Conn }
