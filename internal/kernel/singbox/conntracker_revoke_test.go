package singbox

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	singM "github.com/sagernet/sing/common/metadata"
)

const testManagedInbound = "hysteria-in"

func managedInboundContext(user, ip string) adapter.InboundContext {
	ctx := testInboundContext(user, ip)
	ctx.Inbound = testManagedInbound
	return ctx
}

type testPacketConn struct {
	closed atomic.Bool
}

func (c *testPacketConn) ReadPacket(*buf.Buffer) (singM.Socksaddr, error) {
	return singM.Socksaddr{}, net.ErrClosed
}
func (c *testPacketConn) WritePacket(*buf.Buffer, singM.Socksaddr) error { return nil }
func (c *testPacketConn) Close() error                                   { c.closed.Store(true); return nil }
func (c *testPacketConn) LocalAddr() net.Addr                            { return &net.UDPAddr{} }
func (c *testPacketConn) SetDeadline(time.Time) error                    { return nil }
func (c *testPacketConn) SetReadDeadline(time.Time) error                { return nil }
func (c *testPacketConn) SetWriteDeadline(time.Time) error               { return nil }

// atomicConn is safe to close from another goroutine.
type atomicConn struct {
	testConn
	closedFlag atomic.Bool
}

func (c *atomicConn) Close() error { c.closedFlag.Store(true); return nil }

func TestConnTrackerRejectsUnknownUserOnManagedInbound(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetManagedInbound(testManagedInbound)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})

	// A Hysteria2/TUIC session whose user was removed reports an empty user;
	// a mux/AnyTLS session keeps reporting the old credential.
	for _, user := range []string{"", "uuid-removed"} {
		base := &testConn{}
		got := tracker.RoutedConnection(context.Background(), base, managedInboundContext(user, "1.1.1.1"), nil, nil)
		if got != base || !base.closed {
			t.Fatalf("user %q: connection was admitted, want rejected and closed", user)
		}

		packet := &testPacketConn{}
		gotPacket := tracker.RoutedPacketConnection(context.Background(), packet, managedInboundContext(user, "1.1.1.1"), nil, nil)
		if gotPacket != packet || !packet.closed.Load() {
			t.Fatalf("user %q: packet connection was admitted, want rejected and closed", user)
		}
	}

	if _, _, connCount := tracker.GetUserTraffic(); connCount != 0 {
		t.Fatalf("connCount = %d, want 0", connCount)
	}
}

func TestConnTrackerLeavesUnmanagedInboundAlone(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetManagedInbound(testManagedInbound)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})

	base := &testConn{}
	ctx := testInboundContext("", "1.1.1.1")
	ctx.Inbound = "custom-endpoint"
	if got := tracker.RoutedConnection(context.Background(), base, ctx, nil, nil); got == base {
		t.Fatal("connection from an unmanaged inbound was rejected")
	}

	tracker.SetUserMap(map[string]int{})
	if base.closed {
		t.Fatal("connection from an unmanaged inbound was closed by a user map update")
	}
}

func TestConnTrackerSetUserMapClosesRemovedUsersConnections(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetManagedInbound(testManagedInbound)
	tracker.SetUserMap(map[string]int{"uuid-1": 1, "uuid-2": 2})

	removedTCP := &testConn{}
	tracker.RoutedConnection(context.Background(), removedTCP, managedInboundContext("uuid-1", "1.1.1.1"), nil, nil)
	removedUDP := &testPacketConn{}
	tracker.RoutedPacketConnection(context.Background(), removedUDP, managedInboundContext("uuid-1", "1.1.1.1"), nil, nil)
	keptTCP := &testConn{}
	tracker.RoutedConnection(context.Background(), keptTCP, managedInboundContext("uuid-2", "2.2.2.2"), nil, nil)

	tracker.SetUserMap(map[string]int{"uuid-2": 2})

	if !removedTCP.closed {
		t.Error("removed user's TCP connection is still open")
	}
	if !removedUDP.closed.Load() {
		t.Error("removed user's UDP connection is still open")
	}
	if keptTCP.closed {
		t.Error("remaining user's connection was closed")
	}
	_, aliveIPs, connCount := tracker.GetUserTraffic()
	if aliveIPs[1] != nil {
		t.Errorf("removed user still reported online: %v", aliveIPs[1])
	}
	if connCount != 1 {
		t.Errorf("connCount = %d, want 1", connCount)
	}
}

func TestConnTrackerRevocationRacesWithAdmission(t *testing.T) {
	for i := 0; i < 200; i++ {
		tracker := NewConnTracker(0)
		tracker.SetManagedInbound(testManagedInbound)
		tracker.SetUserMap(map[string]int{"uuid-1": 1})

		conn := &atomicConn{}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			tracker.RoutedConnection(context.Background(), conn, managedInboundContext("uuid-1", "1.1.1.1"), nil, nil)
		}()
		go func() {
			defer wg.Done()
			tracker.SetUserMap(map[string]int{})
		}()
		wg.Wait()

		if !conn.closedFlag.Load() {
			t.Fatalf("iteration %d: connection admitted around revocation stayed open", i)
		}
	}
}

func TestConnTrackerAdmitsNaiveNumericUsername(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetManagedInbound("naive-in")
	tracker.SetUserMap(buildUserMap([]model.UserSpec{{ID: 7, UUID: "uuid-7"}}))

	// The naive inbound authenticates with the numeric user ID as username.
	ctx := adapter.InboundContext{
		Inbound: "naive-in",
		User:    "7",
		Source:  singM.Socksaddr{Addr: netip.MustParseAddr("1.1.1.1")},
	}
	base := &testConn{reads: [][]byte{[]byte("hi")}}
	wrapped := tracker.RoutedConnection(context.Background(), base, ctx, nil, nil)
	if wrapped == base {
		t.Fatal("naive user was rejected")
	}
	if _, err := wrapped.Read(make([]byte, 8)); err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if traffic, _, _ := tracker.GetUserTraffic(); traffic[7][0] != 2 {
		t.Fatalf("traffic[7] = %v, want 2 bytes upload", traffic[7])
	}
}
