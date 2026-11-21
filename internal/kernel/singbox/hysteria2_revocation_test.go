//go:build with_quic

package singbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	box "github.com/sagernet/sing-box"
	boxtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	hy2 "github.com/sagernet/sing-quic/hysteria2"
	singJSON "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	metadata "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Use the node's configuration, live inbound manager, hot-update methods and traffic
// tracker. Bind the fixture exclusively to loopback and use an ephemeral certificate.
func localHY2Node(t *testing.T, users []model.UserSpec, tcpPort, udpPort uint16) (*SingBox, func(string) *hy2.Client) {
	t.Helper()
	sock, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := metadata.SocksaddrFromNet(sock.LocalAddr())
	defer sock.Close()
	key, cert, err := boxtls.GenerateCertificate(nil, nil, time.Now, "localhost", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	spec := &model.NodeSpec{Protocol: "hysteria", Version: 2, ServerPort: int(addr.Port), CustomRoutes: []map[string]any{
		{"ip_cidr": "127.0.0.1/32", "port": []uint16{tcpPort, udpPort}, "outbound": "direct"},
		{"network": []string{"tcp", "udp"}, "outbound": "block"},
	}}
	k := New(config.KernelConfig{LogLevel: "error"})
	k.nodeConfig = spec
	k.users = users
	k.tls = kernel.TLSCert{KeyPEM: key, CertPEM: cert}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	k.ctx = include.Context(ctx)
	k.cancel = cancel
	cfg := buildConfig(k.cfg, spec, users, k.tls)
	cfg["inbounds"].([]M)[0]["listen"] = "127.0.0.1"
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	opts, err := singJSON.UnmarshalExtendedContext[option.Options](k.ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	k.box, err = box.New(box.Options{Context: k.ctx, Options: opts})
	if err != nil {
		t.Fatal(err)
	}
	if err := sock.Close(); err != nil {
		t.Fatal(err)
	}
	k.connTracker = NewConnTracker(0)
	k.connTracker.SetUserMap(buildUserMap(users))
	k.registerTracker(k.ctx)
	if err := k.box.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Stop)
	return k, func(password string) *hy2.Client {
		t.Helper()
		cfg, err := boxtls.NewClient(ctx, logger.NOP(), "localhost", option.OutboundTLSOptions{Enabled: true, Certificate: []string{string(cert)}})
		if err != nil {
			t.Fatal(err)
		}
		client, err := hy2.NewClient(hy2.ClientOptions{Context: ctx, Dialer: N.SystemDialer, Logger: logger.NOP(), ServerAddress: addr, Password: password, TLSConfig: cfg})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { client.CloseWithError(net.ErrClosed) })
		return client
	}
}

func localEcho(t *testing.T) (metadata.Socksaddr, net.Addr, *atomic.Int64) {
	t.Helper()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcp.Close() })
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	packets := new(atomic.Int64)
	go func() {
		data := make([]byte, 256)
		for {
			n, from, err := udp.ReadFrom(data)
			if err != nil {
				return
			}
			packets.Add(1)
			udp.WriteTo(append(data[:n], 0), from)
		}
	}()
	return metadata.SocksaddrFromNet(tcp.Addr()), udp.LocalAddr(), packets
}

func openStream(t *testing.T, c *hy2.Client, dst metadata.Socksaddr) net.Conn {
	t.Helper()
	stream, err := c.DialConn(t.Context(), dst)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stream.Close() })
	return stream
}

func echoStream(t *testing.T, stream net.Conn, msg string) {
	t.Helper()
	stream.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(stream, msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(stream, buf); err != nil || string(buf) != msg {
		t.Fatalf("TCP echo = %q, %v", buf, err)
	}
}

func echoPacket(t *testing.T, pkt net.PacketConn, addr net.Addr, msg string) {
	t.Helper()
	pkt.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := pkt.WriteTo([]byte(msg), addr); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	n, _, err := pkt.ReadFrom(buf)
	if err != nil || string(buf[:n]) != msg+"\x00" {
		t.Fatalf("UDP echo = %q, %v", buf[:n], err)
	}
}

func requireClosed(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var b [1]byte
	_, err := c.Read(b[:])
	var timeout net.Error
	if err == nil || errors.As(err, &timeout) && timeout.Timeout() {
		t.Fatalf("expected transport closure, got %v", err)
	}
}

func requireAuthDenied(t *testing.T, c *hy2.Client, dst metadata.Socksaddr) {
	t.Helper()
	conn, err := c.DialConn(t.Context(), dst)
	if err == nil {
		conn.Close()
		t.Fatal("credential was accepted")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("expected authentication rejection, got %v", err)
	}
}

func TestHysteria2Revocation(t *testing.T) {
	first := model.UserSpec{ID: 1, UUID: "fixture-first"}
	other := model.UserSpec{ID: 2, UUID: "fixture-other"}
	tcp, udp, packets := localEcho(t)
	node, client := localHY2Node(t, []model.UserSpec{first, other}, tcp.Port, metadata.SocksaddrFromNet(udp).Port)
	a1, a2, b := client(first.UUID), client(first.UUID), client(other.UUID)
	sa1, sa2, sb := openStream(t, a1, tcp), openStream(t, a2, tcp), openStream(t, b, tcp)
	echoStream(t, sa1, "one")
	echoStream(t, sa2, "two")
	echoStream(t, sb, "b")
	pa, err := a1.ListenPacket(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer pa.Close()
	echoPacket(t, pa, udp, "udp-a")
	pb, err := b.ListenPacket(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer pb.Close()
	echoPacket(t, pb, udp, "udp-b")
	if count, err := node.RemoveUsers([]model.UserSpec{first}); err != nil || count != 1 {
		t.Fatalf("remove = %d, %v", count, err)
	}
	requireClosed(t, sa1)
	requireClosed(t, sa2)
	// A client may accept a UDP write locally after its peer has gone away.
	// Verify delivery at the endpoint and cleanup of the server's routed flows.
	before := packets.Load()
	if _, err := pa.WriteTo([]byte("x"), udp); err == nil {
		pa.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		var b [1]byte
		if _, _, err := pa.ReadFrom(b[:]); err == nil {
			t.Fatal("revoked datagram received a reply")
		}
	}
	if packets.Load() != before {
		t.Fatal("revoked datagram reached the echo endpoint")
	}
	deadline := time.Now().Add(3 * time.Second)
	for node.connTracker.ActiveCount() != 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := node.connTracker.ActiveCount(); got != 2 {
		t.Fatalf("active routes after revocation = %d, want 2", got)
	}
	requireAuthDenied(t, client(first.UUID), tcp)
	echoStream(t, sb, "same")
	echoStream(t, openStream(t, b, tcp), "new")
	echoPacket(t, pb, udp, "live")
	replacement := other
	replacement.UUID = "fixture-rotated"
	if _, _, err := node.UpdateUsers([]model.UserSpec{replacement, first}); err != nil {
		t.Fatal(err)
	}
	requireClosed(t, sb)
	requireAuthDenied(t, client(other.UUID), tcp)
	echoStream(t, openStream(t, client(replacement.UUID), tcp), "rotated")
	echoStream(t, openStream(t, client(first.UUID), tcp), "restored")
	requireClosed(t, sa1)
	kicked := openStream(t, client(first.UUID), tcp)
	echoStream(t, kicked, "before kick")
	if err := node.CloseUserConnections(t.Context(), first.UUID); err != nil {
		t.Fatal(err)
	}
	requireClosed(t, kicked)
	echoStream(t, openStream(t, client(first.UUID), tcp), "fresh login")
	last := openStream(t, client(replacement.UUID), tcp)
	echoStream(t, last, "before reload")
	if err := node.Reload(node.nodeConfig, []model.UserSpec{replacement}, node.tls); err != nil {
		t.Fatal(err)
	}
	echoStream(t, last, "same listener")
	requireAuthDenied(t, client(first.UUID), tcp)
	if _, _, err := node.UpdateUsers(nil); err != nil {
		t.Fatal(err)
	}
	requireAuthDenied(t, client(first.UUID), tcp)
	requireAuthDenied(t, client(replacement.UUID), tcp)
}
