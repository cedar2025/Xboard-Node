package xray

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vless/encoding"
)

const rotationOldUUID = "11111111-1111-4111-8111-111111111111"
const rotationNewUUID = "33333333-3333-4333-8333-333333333333"
const rotationOtherUUID = "22222222-2222-4222-8222-222222222222"

func newRotationXray(t *testing.T, users []model.UserSpec) (*Xray, string) {
	t.Helper()
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := reservation.Addr().String()
	port := reservation.Addr().(*net.TCPAddr).Port
	reservation.Close()
	x := New(config.KernelConfig{Type: "xray", LogLevel: "error", CustomRoute: []map[string]any{{"type": "field", "ip": []string{"127.0.0.1/32"}, "outboundTag": "direct"}}})
	nc := &model.NodeSpec{Protocol: "vless", ListenIP: "127.0.0.1", ServerPort: port, Network: "tcp"}
	if err := x.Start(nc, users, kernel.TLSCert{}); err != nil {
		t.Fatalf("start VLESS: %v", err)
	}
	t.Cleanup(x.Stop)
	return x, addr
}

func rotationEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); c.SetDeadline(time.Now().Add(5 * time.Second)); io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

func openRotationEcho(addr, credential, target string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) { c.Close(); return nil, err }
	c.SetDeadline(time.Now().Add(2 * time.Second))
	host, portString, err := net.SplitHostPort(target)
	if err != nil {
		return fail(err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		return fail(err)
	}
	u, err := toMemoryUser("vless", &model.NodeSpec{Protocol: "vless"}, model.UserSpec{ID: 1, UUID: credential})
	if err != nil {
		return fail(err)
	}
	request := &protocol.RequestHeader{Version: 0, Command: protocol.RequestCommandTCP, Address: xnet.ParseAddress(host), Port: xnet.Port(port), User: u}
	if err := encoding.EncodeRequestHeader(c, request, &encoding.Addons{}); err != nil {
		return fail(err)
	}
	payload := []byte("uuid-rotation-probe")
	if _, err := c.Write(payload); err != nil {
		return fail(err)
	}
	if _, err := encoding.DecodeResponseHeader(c, request); err != nil {
		return fail(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		return fail(err)
	}
	if !bytes.Equal(got, payload) {
		return fail(fmt.Errorf("unexpected echo %q", got))
	}
	return c, nil
}

func requireRotationEcho(t *testing.T, addr, credential, target string) net.Conn {
	t.Helper()
	c, err := openRotationEcho(addr, credential, target)
	if err != nil {
		t.Fatalf("VLESS credential should work: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestXrayUUIDRotationAcceptsNewRejectsOld(t *testing.T) {
	for _, viaMailbox := range []bool{false, true} {
		t.Run(fmt.Sprintf("machine_mailbox=%v", viaMailbox), func(t *testing.T) {
			old := model.UserSpec{ID: 1, UUID: rotationOldUUID}
			other := model.UserSpec{ID: 2, UUID: rotationOtherUUID}
			users := []model.UserSpec{old, other}
			target := rotationEchoServer(t)
			x, addr := newRotationXray(t, users)
			requireRotationEcho(t, addr, old.UUID, target).Close()
			ongoing := requireRotationEcho(t, addr, other.UUID, target)
			instance := x.instance
			replacement := old
			replacement.UUID = rotationNewUUID
			desired := []model.UserSpec{replacement, other}
			if viaMailbox {
				mailbox := controlplane.NewNodeMailbox()
				mailbox.SeedBaseline(users, x.nodeConfig)
				mailbox.MarkReady()
				mailbox.Apply(controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "add", DeltaUsers: []model.UserSpec{replacement}})
				state := mailbox.DrainIfReady()
				if !state.HasUsers || state.NeedsReconcile {
					t.Fatal("WS delta should yield a complete user snapshot")
				}
				desired = state.Users
			}
			added, removed, err := x.UpdateUsers(desired)
			if err != nil {
				t.Fatalf("replace UUID: %v", err)
			}
			requireRotationEcho(t, addr, replacement.UUID, target).Close()
			if c, err := openRotationEcho(addr, old.UUID, target); err == nil {
				c.Close()
				t.Fatal("old UUID still authenticated after replacement")
			}
			if added != 1 || removed != 1 {
				t.Fatalf("rotation counts = +%d -%d, want +1 -1", added, removed)
			}
			if x.instance != instance {
				t.Fatal("UUID rotation restarted the Xray listener")
			}
			ongoing.SetDeadline(time.Now().Add(time.Second))
			if _, err := ongoing.Write([]byte("still-open")); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len("still-open"))
			if _, err := io.ReadFull(ongoing, got); err != nil {
				t.Fatalf("unaffected user's existing connection broke: %v", err)
			}
			if string(got) != "still-open" {
				t.Fatalf("bad unchanged-user response %q", got)
			}
			requireRotationEcho(t, addr, other.UUID, target).Close()
			added, removed, err = x.UpdateUsers(desired)
			if err != nil || added != 0 || removed != 0 {
				t.Fatalf("replayed snapshot is not idempotent: +%d -%d err=%v", added, removed, err)
			}
		})
	}
}

func TestXrayUUIDRotationValidatesBeforeRemovingOldIdentity(t *testing.T) {
	old := model.UserSpec{ID: 1, UUID: rotationOldUUID}
	x, addr := newRotationXray(t, []model.UserSpec{old})
	target := rotationEchoServer(t)
	invalid := old
	invalid.UUID = ""
	if _, _, err := x.UpdateUsers([]model.UserSpec{invalid}); err == nil {
		t.Fatal("invalid replacement was reported as successfully applied")
	}
	if len(x.users) != 1 || x.users[0] != old {
		t.Fatal("failed replacement advanced the applied user cache")
	}
	requireRotationEcho(t, addr, old.UUID, target).Close()
}

func TestXrayUUIDRotationKeepsTrafficOnSameUser(t *testing.T) {
	old := model.UserSpec{ID: 1, UUID: rotationOldUUID}
	x, addr := newRotationXray(t, []model.UserSpec{old})
	target := rotationEchoServer(t)
	ongoing := requireRotationEcho(t, addr, old.UUID, target)
	before, _, _, err := x.GetUserTraffic(context.Background())
	if err != nil || before[old.ID][0] == 0 {
		t.Fatalf("initial traffic not recorded: %v %v", before, err)
	}
	replacement := old
	replacement.UUID = rotationNewUUID
	if _, _, err := x.UpdateUsers([]model.UserSpec{replacement}); err != nil {
		t.Fatal(err)
	}
	requireRotationEcho(t, addr, replacement.UUID, target).Close()
	payload := []byte("old-session-after-rotation")
	ongoing.SetDeadline(time.Now().Add(time.Second))
	if _, err := ongoing.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(ongoing, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("old session did not echo: %v", err)
	}
	after, _, _, err := x.GetUserTraffic(context.Background())
	if err != nil || len(after) != 1 || after[old.ID][0] <= before[old.ID][0] || after[old.ID][1] <= before[old.ID][1] {
		t.Fatalf("same-ID traffic did not accumulate: before=%v after=%v err=%v", before, after, err)
	}
}

func TestXrayUpdateUsersReturnsActualAddFailure(t *testing.T) {
	old := model.UserSpec{ID: 1, UUID: rotationOldUUID}
	conflicting := model.UserSpec{ID: 2, UUID: rotationOtherUUID}
	x, _ := newRotationXray(t, []model.UserSpec{old})
	um, err := x.getUserManager()
	if err != nil {
		t.Fatal(err)
	}
	mu, err := toMemoryUser("vless", x.nodeConfig, conflicting)
	if err != nil {
		t.Fatal(err)
	}
	if err := um.AddUser(context.Background(), mu); err != nil {
		t.Fatal(err)
	}
	added, removed, err := x.UpdateUsers([]model.UserSpec{old, conflicting})
	if err == nil {
		t.Fatal("real Xray duplicate-user error was swallowed")
	}
	if added != 0 || removed != 0 {
		t.Fatalf("failed addition counted as success: +%d -%d", added, removed)
	}
	if len(x.users) != 1 || x.users[0] != old {
		t.Fatal("failed update advanced the applied user cache")
	}
}

func TestXrayUpdateUsersReturnsActualRemoveFailure(t *testing.T) {
	old := model.UserSpec{ID: 1, UUID: rotationOldUUID}
	other := model.UserSpec{ID: 2, UUID: rotationOtherUUID}
	x, _ := newRotationXray(t, []model.UserSpec{old, other})
	um, err := x.getUserManager()
	if err != nil {
		t.Fatal(err)
	}
	if err := um.RemoveUser(context.Background(), userEmail(old.ID)); err != nil {
		t.Fatal(err)
	}
	added, removed, err := x.UpdateUsers([]model.UserSpec{other})
	if err == nil {
		t.Fatal("real Xray missing-user removal error was swallowed")
	}
	if added != 0 || removed != 0 {
		t.Fatalf("failed removal counted as success: +%d -%d", added, removed)
	}
	if len(x.users) != 2 {
		t.Fatal("failed removal advanced the applied user cache")
	}
}
