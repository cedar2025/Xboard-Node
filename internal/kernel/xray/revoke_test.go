package xray

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/model"
	xrayCore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
)

// Removing a user from the inbound only blocks new VLESS handshakes. A user
// removed for exhausted traffic, expiry or a ban must also lose connections
// that already authenticated, including mux sub-streams opened later on an
// authenticated mux connection. Otherwise they keep using the node.

func TestXrayRemovedUserLosesExistingConnection(t *testing.T) {
	removed := model.UserSpec{ID: 1, UUID: rotationOldUUID}
	kept := model.UserSpec{ID: 2, UUID: rotationOtherUUID}
	target := rotationEchoServer(t)
	x, addr := newRotationXray(t, []model.UserSpec{removed, kept})
	removedConn := requireRotationEcho(t, addr, removed.UUID, target)
	keptConn := requireRotationEcho(t, addr, kept.UUID, target)

	if _, err := x.RemoveUsers([]model.UserSpec{{ID: removed.ID}}); err != nil {
		t.Fatalf("RemoveUsers() error = %v", err)
	}

	if connEchoes(removedConn) {
		t.Error("removed user's existing connection still relays traffic")
	}
	if !connEchoes(keptConn) {
		t.Error("remaining user's existing connection was disrupted")
	}
}

func TestXrayRemovedUserLosesMuxSession(t *testing.T) {
	removed := model.UserSpec{ID: 1, UUID: rotationOldUUID}
	kept := model.UserSpec{ID: 2, UUID: rotationOtherUUID}
	target := rotationEchoServer(t)
	x, addr := newRotationXray(t, []model.UserSpec{removed, kept})
	removedMux := startMuxClient(t, addr, removed.UUID, target)
	keptMux := startMuxClient(t, addr, kept.UUID, target)

	existing := dialThrough(t, removedMux)
	keptExisting := dialThrough(t, keptMux)

	if _, err := x.RemoveUsers([]model.UserSpec{{ID: removed.ID}}); err != nil {
		t.Fatalf("RemoveUsers() error = %v", err)
	}

	if connEchoes(existing) {
		t.Error("removed user's existing mux sub-stream still relays traffic")
	}
	if c, err := net.DialTimeout("tcp", removedMux, time.Second); err == nil {
		defer c.Close()
		if connEchoes(c) {
			t.Error("removed user opened a new sub-stream on the authenticated mux connection")
		}
	}

	if !connEchoes(keptExisting) {
		t.Error("remaining user's existing mux sub-stream was disrupted")
	}
	dialThrough(t, keptMux)
}

// startMuxClient runs an Xray client whose local tunnel inbound forwards to
// target through a mux-enabled VLESS outbound, so every local connection is a
// sub-stream of one authenticated VLESS connection. It returns the local
// address.
func startMuxClient(t *testing.T, server, uuid, target string) string {
	t.Helper()
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	local := reservation.Addr().(*net.TCPAddr)
	reservation.Close()
	serverHost, serverPort, _ := net.SplitHostPort(server)
	targetHost, targetPort, _ := net.SplitHostPort(target)

	cfg := fmt.Sprintf(`{
		"log": {"loglevel": "error"},
		"inbounds": [{"listen": "127.0.0.1", "port": %d, "protocol": "dokodemo-door",
			"settings": {"address": %q, "port": %s, "network": "tcp"}}],
		"outbounds": [{"protocol": "vless",
			"settings": {"vnext": [{"address": %q, "port": %s, "users": [{"id": %q, "encryption": "none"}]}]},
			"mux": {"enabled": true, "concurrency": 8}}]
	}`, local.Port, targetHost, targetPort, serverHost, serverPort, uuid)
	pb, err := serial.LoadJSONConfig(strings.NewReader(cfg))
	if err != nil {
		t.Fatalf("parse client config: %v", err)
	}
	// Instance creation swaps the global dispatcher hook; keep it serialised
	// with the kernel's own captures.
	xrayCreationMu.Lock()
	client, err := xrayCore.New(pb)
	xrayCreationMu.Unlock()
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if err := client.Start(); err != nil {
		t.Fatalf("start client: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return local.String()
}

// dialThrough opens a sub-stream through the mux client and requires it to relay.
func dialThrough(t *testing.T, local string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", local, time.Second)
	if err != nil {
		t.Fatalf("dial mux client: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if !connEchoes(c) {
		t.Fatal("sub-stream did not relay traffic")
	}
	return c
}

// connEchoes reports whether a round trip through c reaches the echo server.
func connEchoes(c net.Conn) bool {
	payload := []byte("revoke-probe")
	c.SetDeadline(time.Now().Add(2 * time.Second))
	defer c.SetDeadline(time.Time{})
	if _, err := c.Write(payload); err != nil {
		return false
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		return false
	}
	return bytes.Equal(got, payload)
}
