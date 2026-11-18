package proxy

import (
	"bufio"
	"context"
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

	// UDP ASSOCIATE must be rejected with code 7 and a log line.
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
		t.Fatalf("UDP ASSOCIATE reply code = %d, want 7 (command not supported)", rep[1])
	}
}
