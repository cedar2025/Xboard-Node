package xray

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
)

func startEchoServer(t *testing.T) (int, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("startEchoServer: %v", err)
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, func() { l.Close() }
}

func socks5ConnectAuth(t *testing.T, proxyAddr, targetHost string, targetPort int, user, pass string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("socks5 dial: %v", err)
	}

	conn.Write([]byte{0x05, 0x01, 0x02})
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		t.Fatalf("socks5 greeting: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x02 {
		conn.Close()
		t.Fatalf("socks5 greeting: unexpected %x (want 05 02)", resp)
	}

	var auth bytes.Buffer
	auth.WriteByte(0x01)
	auth.WriteByte(byte(len(user)))
	auth.WriteString(user)
	auth.WriteByte(byte(len(pass)))
	auth.WriteString(pass)
	conn.Write(auth.Bytes())

	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		conn.Close()
		t.Fatalf("socks5 auth: %v", err)
	}
	if authResp[1] != 0x00 {
		conn.Close()
		t.Fatalf("socks5 auth failed: status %d", authResp[1])
	}

	var req bytes.Buffer
	req.Write([]byte{0x05, 0x01, 0x00, 0x03})
	hostBytes := []byte(targetHost)
	req.WriteByte(byte(len(hostBytes)))
	req.Write(hostBytes)
	binary.Write(&req, binary.BigEndian, uint16(targetPort))
	conn.Write(req.Bytes())

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		conn.Close()
		t.Fatalf("socks5 connect: %v", err)
	}
	if header[1] != 0x00 {
		conn.Close()
		t.Fatalf("socks5 connect status: %d", header[1])
	}
	switch header[3] {
	case 0x01:
		io.ReadFull(conn, make([]byte, 6))
	case 0x03:
		dlen := make([]byte, 1)
		io.ReadFull(conn, dlen)
		io.ReadFull(conn, make([]byte, int(dlen[0])+2))
	case 0x04:
		io.ReadFull(conn, make([]byte, 18))
	}
	return conn
}

// testNodeSpecWithLocalRoute creates a NodeSpec that allows localhost traffic
// to pass through the default SSRF block rule, enabling e2e tests against
// local echo servers.
func testNodeSpecWithLocalRoute(nc *model.NodeSpec) *model.NodeSpec {
	nc.CustomRoutes = []map[string]any{
		{"type": "field", "ip": []string{"127.0.0.0/8"}, "outboundTag": "direct"},
	}
	return nc
}

func TestE2E_SOCKS5_ProxyDataFlow(t *testing.T) {
	echoPort, echoStop := startEchoServer(t)
	defer echoStop()

	socksPort := freePort(t)
	nc := testNodeSpecWithLocalRoute(&model.NodeSpec{
		Protocol:   "socks",
		ListenIP:   "127.0.0.1",
		ServerPort: socksPort,
	})

	x := New(config.KernelConfig{Type: "xray", LogLevel: "warn"})
	if err := x.Start(nc, integrationTestUsers, kernel.TLSCert{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer x.Stop()

	proxyAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	if err := waitListening(proxyAddr, 3*time.Second); err != nil {
		t.Fatalf("SOCKS proxy not listening: %v", err)
	}

	u := integrationTestUsers[0]
	conn := socks5ConnectAuth(t, proxyAddr, "127.0.0.1", echoPort, u.UUID, u.UUID)
	defer conn.Close()

	payload := []byte("hello xray e2e proxy test!")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("echo mismatch: got %q want %q", buf, payload)
	}
	t.Logf("✓ SOCKS5 e2e: %d bytes proxied correctly", len(payload))
}

func TestE2E_SOCKS5_MultipleConnections(t *testing.T) {
	echoPort, echoStop := startEchoServer(t)
	defer echoStop()

	socksPort := freePort(t)
	nc := testNodeSpecWithLocalRoute(&model.NodeSpec{
		Protocol:   "socks",
		ListenIP:   "127.0.0.1",
		ServerPort: socksPort,
	})

	x := New(config.KernelConfig{Type: "xray", LogLevel: "warn"})
	if err := x.Start(nc, integrationTestUsers, kernel.TLSCert{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer x.Stop()

	proxyAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	if err := waitListening(proxyAddr, 3*time.Second); err != nil {
		t.Fatalf("SOCKS proxy not listening: %v", err)
	}

	u := integrationTestUsers[0]
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			payload := fmt.Sprintf("connection-%d", id)
			conn := socks5ConnectAuth(t, proxyAddr, "127.0.0.1", echoPort, u.UUID, u.UUID)
			defer conn.Close()

			if _, err := conn.Write([]byte(payload)); err != nil {
				errs <- fmt.Errorf("conn %d write: %w", id, err)
				return
			}
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			buf := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, buf); err != nil {
				errs <- fmt.Errorf("conn %d read: %w", id, err)
				return
			}
			if string(buf) != payload {
				errs <- fmt.Errorf("conn %d: got %q want %q", id, buf, payload)
				return
			}
			errs <- nil
		}(i)
	}
	for i := 0; i < 10; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent: %v", err)
		}
	}
	t.Logf("✓ SOCKS5 e2e: 10 concurrent connections all succeeded")
}

func TestE2E_HTTP_ProxyDataFlow(t *testing.T) {
	echoPort, echoStop := startEchoServer(t)
	defer echoStop()

	httpPort := freePort(t)
	nc := testNodeSpecWithLocalRoute(&model.NodeSpec{
		Protocol:   "http",
		ListenIP:   "127.0.0.1",
		ServerPort: httpPort,
	})

	x := New(config.KernelConfig{Type: "xray", LogLevel: "warn"})
	if err := x.Start(nc, integrationTestUsers, kernel.TLSCert{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer x.Stop()

	proxyAddr := fmt.Sprintf("127.0.0.1:%d", httpPort)
	if err := waitListening(proxyAddr, 3*time.Second); err != nil {
		t.Fatalf("HTTP proxy not listening: %v", err)
	}

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	u := integrationTestUsers[0]
	cred := base64.StdEncoding.EncodeToString([]byte(u.UUID + ":" + u.UUID))
	target := fmt.Sprintf("127.0.0.1:%d", echoPort)
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", target, target, cred)
	conn.Write([]byte(req))

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("CONNECT response: %v", err)
	}
	if !bytes.Contains(buf[:n], []byte("200")) {
		t.Fatalf("CONNECT failed: %s", buf[:n])
	}

	payload := []byte("hello http proxy e2e!")
	conn.Write(payload)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	echoBuf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, echoBuf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(echoBuf, payload) {
		t.Fatalf("echo mismatch: got %q want %q", echoBuf, payload)
	}
	t.Logf("✓ HTTP CONNECT e2e: %d bytes proxied correctly", len(payload))
}
