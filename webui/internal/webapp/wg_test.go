package webapp

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestGenerateWGKeys(t *testing.T) {
	k, err := GenerateWGKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(k.Private) != 44 || len(k.Public) != 44 { // base64 32 bytes
		t.Fatalf("key lengths: priv=%d pub=%d", len(k.Private), len(k.Public))
	}
	k2, _ := GenerateWGKeys()
	if k.Private == k2.Private {
		t.Fatal("keypairs not random")
	}
}

// TestWGTunnelLocalPair runs two full userspace WireGuard devices against
// each other over UDP localhost and pushes an HTTP request through the
// tunnel — proving the netstack dial path works without any external
// dependency.
func TestWGTunnelLocalPair(t *testing.T) {
	client, _ := GenerateWGKeys()
	server, _ := GenerateWGKeys()

	// "Server" side: a netstack device with a loopback listener.
	srvTun, srvNet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.0.0.1")},
		[]netip.Addr{}, 1420)
	if err != nil {
		t.Fatal(err)
	}
	l, err := srvNet.ListenTCP(&net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 8080})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("hello-via-wg"))
			c.Close()
		}
	}()

	// Server WG device: choose a free UDP port up front so the client's
	// endpoint is deterministic.
	free, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	srvPort := free.LocalAddr().(*net.UDPAddr).Port
	free.Close()

	srvBind := conn.NewDefaultBind()
	srvDev := device.NewDevice(srvTun, srvBind, device.NewLogger(device.LogLevelError, "wg-srv"))
	srvPriv, _ := wgPrivateKeyBytes(server)
	srvDev.IpcSet(fmt.Sprintf("private_key=%x\nlisten_port=%d\n", srvPriv, srvPort))
	srvPubRaw, _ := wgPrivateKeyBytes(server) // decodes base64 → bytes
	_ = srvPubRaw
	srvPubHex := hex.EncodeToString(mustB64(client.Public))
	srvDev.IpcSet(fmt.Sprintf("public_key=%s\nallowed_ip=10.0.0.2/32\n", srvPubHex))
	defer srvDev.Close()

	srvEndpoint := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(srvPort))

	tun, err := DialWGTunnel(context.Background(), WGTunnelConfig{
		PrivateKey:  client.Private,
		AddressIPv4: "10.0.0.2",
		PeerPubKey:  server.Public,
		Endpoint:    srvEndpoint.String(),
		AllowedIPs:  []string{"10.0.0.1/32"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()

	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		c, err := tun.DialContext(ctx, "tcp", "10.0.0.1:8080")
		cancel()
		if err != nil {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}
		buf := make([]byte, 64)
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _ := c.Read(buf)
		c.Close()
		if string(buf[:n]) == "hello-via-wg" {
			return // success
		}
		lastErr = errBadReply(buf[:n])
		break
	}
	t.Fatalf("tunnel round-trip failed: %v", lastErr)
}

func mustB64(b64 string) []byte {
	b, _ := base64.StdEncoding.DecodeString(b64)
	return b
}

func errBadReply(b []byte) error { return context.DeadlineExceeded }
