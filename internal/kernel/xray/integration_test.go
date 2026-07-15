package xray

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/xtls/xray-core/features/routing"
)

func freePort(t *testing.T) int {
	t.Helper()
	// Check both TCP and UDP availability — xray binds both for SOCKS5/HTTP inbounds.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	u, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		// UDP taken (previous test cleanup in progress) — retry with a new port.
		l2, err2 := net.Listen("tcp", "127.0.0.1:0")
		if err2 != nil {
			t.Fatalf("freePort retry: %v", err2)
		}
		port = l2.Addr().(*net.TCPAddr).Port
		l2.Close()
		u2, err3 := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err3 != nil {
			t.Fatalf("freePort: UDP still unavailable after retry: %v", err3)
		}
		u2.Close()
		return port
	}
	u.Close()
	return port
}

func waitListening(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", addr)
}

var integrationTestUsers = []model.UserSpec{
	{ID: 101, UUID: "a0a1a2a3-a4a5-a6a7-a8a9-aaabacadaeaf"},
	{ID: 102, UUID: "b0b1b2b3-b4b5-b6b7-b8b9-babbbcbdbebf"},
}

func testXrayProtocol(t *testing.T, nc *model.NodeSpec, port int) {
	t.Helper()
	x := New(config.KernelConfig{Type: "xray", LogLevel: "warn"})

	err := x.Start(nc, integrationTestUsers, kernel.TLSCert{})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer x.Stop()

	if !x.IsRunning() {
		t.Fatal("expected xray to be running after Start()")
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := waitListening(addr, 5*time.Second); err != nil {
		t.Fatalf("port %d not listening after Start(): %v", port, err)
	}
	t.Logf("✓ %s on port %d: listening", nc.Protocol, port)

	traffic, aliveIPs, connCount, err := x.GetUserTraffic(context.Background())
	if err != nil {
		t.Fatalf("GetUserTraffic() error = %v", err)
	}
	if traffic == nil {
		traffic = make(map[int][2]int64)
	}
	t.Logf("✓ %s: traffic=%v aliveIPs=%v connCount=%d", nc.Protocol, traffic, aliveIPs, connCount)

	newUser := model.UserSpec{ID: 103, UUID: "c0c1c2c3-c4c5-c6c7-c8c9-cacbcdcecfd0"}
	added, err := x.AddUsers([]model.UserSpec{newUser})
	if err != nil {
		t.Fatalf("AddUsers() error = %v", err)
	}
	t.Logf("✓ %s: added %d user(s)", nc.Protocol, added)

	removed, err := x.RemoveUsers([]model.UserSpec{newUser})
	if err != nil {
		t.Fatalf("RemoveUsers() error = %v", err)
	}
	t.Logf("✓ %s: removed %d user(s)", nc.Protocol, removed)

	updated := append([]model.UserSpec{}, integrationTestUsers...)
	updated[0].SpeedLimit = 10
	added, removed, err = x.UpdateUsers(updated)
	if err != nil {
		t.Fatalf("UpdateUsers() error = %v", err)
	}
	t.Logf("✓ %s: UpdateUsers added=%d removed=%d", nc.Protocol, added, removed)

	err = x.Reload(nc, updated, kernel.TLSCert{})
	if err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	t.Logf("✓ %s: Reload succeeded", nc.Protocol)

	if err := waitListening(addr, 2*time.Second); err != nil {
		t.Fatalf("port %d not listening after Reload(): %v", port, err)
	}
	t.Logf("✓ %s: still listening after reload", nc.Protocol)
}

func TestXrayIntegration_VMess_WS(t *testing.T) {
	port := freePort(t)
	nc := &model.NodeSpec{
		Protocol:   "vmess",
		ListenIP:   "127.0.0.1",
		ServerPort: port,
		Network:    "ws",
		NetworkSettings: map[string]interface{}{
			"path": "/vmess",
			"host": "example.com",
		},
	}
	testXrayProtocol(t, nc, port)
}

func TestXrayIntegration_VLess_TCP(t *testing.T) {
	port := freePort(t)
	nc := &model.NodeSpec{
		Protocol:   "vless",
		ListenIP:   "127.0.0.1",
		ServerPort: port,
		Network:    "tcp",
	}
	testXrayProtocol(t, nc, port)
}

func TestXrayIntegration_VLess_WS(t *testing.T) {
	port := freePort(t)
	nc := &model.NodeSpec{
		Protocol:   "vless",
		ListenIP:   "127.0.0.1",
		ServerPort: port,
		Network:    "ws",
		NetworkSettings: map[string]interface{}{
			"path": "/vless",
		},
	}
	testXrayProtocol(t, nc, port)
}

func TestXrayIntegration_VLess_GRPC(t *testing.T) {
	port := freePort(t)
	nc := &model.NodeSpec{
		Protocol:   "vless",
		ListenIP:   "127.0.0.1",
		ServerPort: port,
		Network:    "grpc",
		NetworkSettings: map[string]interface{}{
			"serviceName": "vless-grpc",
		},
	}
	testXrayProtocol(t, nc, port)
}

func TestXrayIntegration_Trojan_TCP(t *testing.T) {
	port := freePort(t)
	nc := &model.NodeSpec{
		Protocol:   "trojan",
		ListenIP:   "127.0.0.1",
		ServerPort: port,
		Network:    "tcp",
	}
	testXrayProtocol(t, nc, port)
}

func TestXrayIntegration_Shadowsocks_AES(t *testing.T) {
	port := freePort(t)
	nc := &model.NodeSpec{
		Protocol:   "shadowsocks",
		ListenIP:   "127.0.0.1",
		ServerPort: port,
		Cipher:     "aes-128-gcm",
	}
	testXrayProtocol(t, nc, port)
}

func TestXrayIntegration_Shadowsocks_2022(t *testing.T) {
	port := freePort(t)
	nc := &model.NodeSpec{
		Protocol:   "shadowsocks",
		ListenIP:   "127.0.0.1",
		ServerPort: port,
		Cipher:     "2022-blake3-aes-128-gcm",
		ServerKey:  "test-server-key-1234",
	}
	testXrayProtocol(t, nc, port)
}

func TestXrayIntegration_Socks(t *testing.T) {
	port := freePort(t)
	nc := &model.NodeSpec{
		Protocol:   "socks",
		ListenIP:   "127.0.0.1",
		ServerPort: port,
	}
	testXrayProtocol(t, nc, port)
}

func TestXrayIntegration_HTTP(t *testing.T) {
	port := freePort(t)
	nc := &model.NodeSpec{
		Protocol:   "http",
		ListenIP:   "127.0.0.1",
		ServerPort: port,
	}
	testXrayProtocol(t, nc, port)
}

func TestXrayIntegration_VLess_XHTTP(t *testing.T) {
	port := freePort(t)
	nc := &model.NodeSpec{
		Protocol:   "vless",
		ListenIP:   "127.0.0.1",
		ServerPort: port,
		Network:    "xhttp",
		NetworkSettings: map[string]interface{}{
			"path": "/xhttp",
			"mode": "auto",
		},
	}
	testXrayProtocol(t, nc, port)
}

func TestXrayIntegration_VLess_HTTPUpgrade(t *testing.T) {
	port := freePort(t)
	nc := &model.NodeSpec{
		Protocol:   "vless",
		ListenIP:   "127.0.0.1",
		ServerPort: port,
		Network:    "httpupgrade",
		NetworkSettings: map[string]interface{}{
			"path": "/upgrade",
			"host": "example.com",
		},
	}
	testXrayProtocol(t, nc, port)
}

func TestXrayIntegration_LimitDispatcher(t *testing.T) {
	port := freePort(t)
	nc := &model.NodeSpec{
		Protocol:   "shadowsocks",
		ListenIP:   "127.0.0.1",
		ServerPort: port,
		Cipher:     "aes-128-gcm",
	}
	x := New(config.KernelConfig{Type: "xray", LogLevel: "debug"})

	err := x.Start(nc, integrationTestUsers, kernel.TLSCert{})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer x.Stop()

	x.mu.Lock()
	ld := x.limitDispatcher
	x.mu.Unlock()

	if ld == nil {
		t.Fatal("LimitDispatcher is nil after Start — dispatcher factory injection failed")
	}
	t.Log("✓ LimitDispatcher installed")

	feat := x.instance.GetFeature(routing.DispatcherType())
	if feat == nil {
		t.Fatal("dispatcher feature is nil in xray instance")
	}
	if feat != ld {
		t.Fatalf("dispatcher feature type=%T, want *LimitDispatcher", feat)
	}
	t.Log("✓ xray instance uses LimitDispatcher as routing.Dispatcher")
}

func TestXrayIntegration_RestartSamePort(t *testing.T) {
	port := freePort(t)
	nc := &model.NodeSpec{
		Protocol:   "shadowsocks",
		ListenIP:   "127.0.0.1",
		ServerPort: port,
		Cipher:     "aes-128-gcm",
	}

	for i := 0; i < 3; i++ {
		x := New(config.KernelConfig{Type: "xray", LogLevel: "warn"})
		err := x.Start(nc, integrationTestUsers, kernel.TLSCert{})
		if err != nil {
			t.Fatalf("iteration %d: Start() error = %v", i, err)
		}
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		if err := waitListening(addr, 3*time.Second); err != nil {
			t.Fatalf("iteration %d: not listening: %v", i, err)
		}
		x.Stop()
		time.Sleep(200 * time.Millisecond)
	}
}
