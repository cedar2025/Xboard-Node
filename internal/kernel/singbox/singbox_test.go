package singbox

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/sagernet/sing-box/adapter"
	singM "github.com/sagernet/sing/common/metadata"
	"golang.org/x/time/rate"
)

func TestSingBoxCapabilities(t *testing.T) {
	s := New(config.KernelConfig{Type: "sing-box"})
	caps := s.Capabilities()
	if !caps.PerUserSpeedLimit || !caps.DeviceLimit || !caps.AliveIPTracking || !caps.ForceCloseUser {
		t.Fatalf("unexpected sing-box capabilities: %+v", caps)
	}
	if caps.BuiltInTrafficStats || caps.ForceCloseConnection {
		t.Fatalf("unexpected sing-box capabilities: %+v", caps)
	}
	protocols := s.Protocols()
	found := false
	for _, protocol := range protocols {
		if protocol == "hysteria" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Protocols() missing hysteria: %v", protocols)
	}
}

type testConn struct {
	closed bool
	reads  [][]byte
	writes [][]byte
}

func (c *testConn) Read(b []byte) (int, error) {
	if len(c.reads) == 0 {
		return 0, errors.New("eof")
	}
	chunk := c.reads[0]
	c.reads = c.reads[1:]
	n := copy(b, chunk)
	return n, nil
}

func (c *testConn) Write(b []byte) (int, error) {
	cp := append([]byte(nil), b...)
	c.writes = append(c.writes, cp)
	return len(b), nil
}

func (c *testConn) Close() error                     { c.closed = true; return nil }
func (c *testConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *testConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *testConn) SetDeadline(time.Time) error      { return nil }
func (c *testConn) SetReadDeadline(time.Time) error  { return nil }
func (c *testConn) SetWriteDeadline(time.Time) error { return nil }

func testInboundContext(uuid, ip string) adapter.InboundContext {
	return adapter.InboundContext{
		User:   uuid,
		Source: singM.Socksaddr{Addr: netip.MustParseAddr(ip)},
	}
}

func TestConnTrackerRoutedConnectionTracksTrafficAndAliveIPs(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	base := &testConn{reads: [][]byte{[]byte("hello")}}

	wrapped := tracker.RoutedConnection(context.Background(), base, testInboundContext("uuid-1", "1.1.1.1"), nil, nil)

	buf := make([]byte, 16)
	n, err := wrapped.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if n != 5 {
		t.Fatalf("Read() bytes = %d, want 5", n)
	}
	if _, err := wrapped.Write([]byte("bye")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	traffic, aliveIPs, connCount := tracker.GetUserTraffic()
	if got := traffic[1]; got != [2]int64{5, 3} {
		t.Fatalf("traffic[1] = %v, want [5 3]", got)
	}
	if !aliveIPs[1]["1.1.1.1"] {
		t.Fatal("expected alive IP to include source address")
	}
	if connCount != 1 {
		t.Fatalf("connCount = %d, want 1", connCount)
	}

	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	_, aliveIPs, connCount = tracker.GetUserTraffic()
	if aliveIPs[1] != nil {
		t.Fatalf("aliveIPs after close = %v, want nil", aliveIPs[1])
	}
	if connCount != 0 {
		t.Fatalf("connCount after close = %d, want 0", connCount)
	}
}

func TestConnTrackerRoutedConnectionRejectsWhenDeviceLimitExceeded(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	tracker.SetDeviceLimitFunc(func(uuid string) (int, bool) {
		if uuid != "uuid-1" {
			return 0, false
		}
		return 1, true
	})

	first := &testConn{}
	wrapped1 := tracker.RoutedConnection(context.Background(), first, testInboundContext("uuid-1", "1.1.1.1"), nil, nil)
	if wrapped1 == first {
		t.Fatal("expected first connection to be wrapped")
	}

	second := &testConn{}
	wrapped2 := tracker.RoutedConnection(context.Background(), second, testInboundContext("uuid-1", "2.2.2.2"), nil, nil)
	if wrapped2 != second {
		t.Fatal("expected rejected connection to be returned unwrapped")
	}
	if !second.closed {
		t.Fatal("expected rejected connection to be closed")
	}
}

func TestConnTrackerCheckDeviceGateMergesFreshGlobalDevices(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	us := tracker.users[1]
	us.addConn("1.1.1.1")
	tracker.UpdateGlobalDevices(map[int][]string{1: {"9.9.9.9"}})

	for _, ip := range []string{"2.2.2.2", "99.99.99.99"} {
		if !tracker.checkDeviceGate(us, 1, ip, 2) {
			t.Fatalf("expected merged local+global device state to reject third device %s", ip)
		}
	}
	if tracker.checkDeviceGate(us, 1, "1.1.1.1", 2) {
		t.Fatal("existing local IP should still be allowed")
	}
	if tracker.checkDeviceGate(us, 1, "9.9.9.9", 2) {
		t.Fatal("existing global IP should still be allowed")
	}
}

func TestConnTrackerCloseByIDClosesTrackedConnection(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	base := &testConn{}
	wrapped := tracker.RoutedConnection(context.Background(), base, testInboundContext("uuid-1", "1.1.1.1"), nil, nil)
	tracked, ok := wrapped.(*trackedConn)
	if !ok {
		t.Fatalf("wrapped type = %T, want *trackedConn", wrapped)
	}
	if !tracker.CloseByID(tracked.connID) {
		t.Fatal("CloseByID() = false, want true")
	}
	if !base.closed {
		t.Fatal("expected underlying connection to be closed")
	}
}

func TestConnTrackerRateLimitHonorsContextCancellation(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	oneBytePerSecond := func(uuid string) *rate.Limiter {
		if uuid != "uuid-1" {
			return nil
		}
		return rate.NewLimiter(rate.Limit(1), 1)
	}
	tracker.SetSpeedLimitFunc(oneBytePerSecond)
	tracker.SetUploadLimitFunc(oneBytePerSecond)

	readCtx, cancelRead := context.WithCancel(context.Background())
	readBase := &testConn{reads: [][]byte{[]byte("a"), []byte("a")}}
	readTracked := tracker.RoutedConnection(readCtx, readBase, testInboundContext("uuid-1", "1.1.1.1"), nil, nil).(*trackedConn)
	buf := make([]byte, 8)
	if n, err := readTracked.Read(buf); err != nil || n != 1 {
		t.Fatalf("first Read() = (%d, %v), want (1, nil)", n, err)
	}
	cancelRead()
	if n, err := readTracked.Read(buf); !errors.Is(err, context.Canceled) || n != 1 {
		t.Fatalf("second Read() = (%d, %v), want (1, context canceled)", n, err)
	}

	writeCtx, cancelWrite := context.WithCancel(context.Background())
	writeBase := &testConn{}
	writeTracked := tracker.RoutedConnection(writeCtx, writeBase, testInboundContext("uuid-1", "1.1.1.2"), nil, nil).(*trackedConn)
	if n, err := writeTracked.Write([]byte("a")); err != nil || n != 1 {
		t.Fatalf("first Write() = (%d, %v), want (1, nil)", n, err)
	}
	cancelWrite()
	if n, err := writeTracked.Write([]byte("a")); !errors.Is(err, context.Canceled) || n != 0 {
		t.Fatalf("second Write() = (%d, %v), want (0, context canceled)", n, err)
	}
}

func limitedTracker(limit int) *ConnTracker {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	tracker.SetDeviceLimitFunc(func(string) (int, bool) { return limit, true })
	return tracker
}

func admitted(tracker *ConnTracker, ip string) (net.Conn, bool) {
	base := &testConn{}
	wrapped := tracker.RoutedConnection(context.Background(), base, testInboundContext("uuid-1", ip), nil, nil)
	return wrapped, wrapped != net.Conn(base)
}

// Device slots are first come, first served: once the limit is reached a new
// IP is rejected whatever its sort order.
func TestConnTrackerFullLimitRejectsLowerSortingIP(t *testing.T) {
	tracker := limitedTracker(1)
	if _, ok := admitted(tracker, "9.9.9.9"); !ok {
		t.Fatal("first device rejected")
	}
	if _, ok := admitted(tracker, "1.1.1.1"); ok {
		t.Error("a second device was admitted over the limit")
	}
}

// The panel's global state includes the devices this node reported itself,
// and trails them: a device that just left this node must not hold its slot
// against the same user's next IP (Wi-Fi to cellular).
func TestConnTrackerIgnoresGlobalEchoOfDepartedDevice(t *testing.T) {
	tracker := limitedTracker(1)
	old, _ := admitted(tracker, "1.1.1.1")
	tracker.UpdateGlobalDevices(map[int][]string{1: {"1.1.1.1"}})
	old.Close()

	if _, ok := admitted(tracker, "2.2.2.2"); !ok {
		t.Error("new IP rejected because of this node's own stale report")
	}
}

// Global state received well after the device left here no longer echoes
// this node's report: the device is online on another node.
func TestConnTrackerCountsDepartedDeviceStillOnlineElsewhere(t *testing.T) {
	tracker := limitedTracker(1)
	old, _ := admitted(tracker, "1.1.1.1")
	old.Close()
	tracker.users[1].departed["1.1.1.1"] = time.Now().Add(-2 * kernel.DeviceEchoWindow)
	tracker.UpdateGlobalDevices(map[int][]string{1: {"1.1.1.1"}})

	if _, ok := admitted(tracker, "2.2.2.2"); ok {
		t.Error("a second device was admitted while the first is online on another node")
	}
}

// Two nodes can each admit a device before the panel tells them about the
// other. Once global state shows the user over the limit, every node keeps
// the same lowest-sorting IPs and disconnects its other devices.
func TestConnTrackerGlobalStateDisconnectsDeviceOverLimit(t *testing.T) {
	tracker := limitedTracker(1)
	base := &testConn{}
	tracker.RoutedConnection(context.Background(), base, testInboundContext("uuid-1", "9.9.9.9"), nil, nil)
	tracker.UpdateGlobalDevices(map[int][]string{1: {"1.1.1.1", "9.9.9.9"}})

	if !base.closed {
		t.Fatal("device over the limit stayed connected")
	}
	if _, alive, _ := tracker.GetUserTraffic(); len(alive[1]) != 0 {
		t.Errorf("disconnected device still reported online: %v", alive[1])
	}
	if _, ok := admitted(tracker, "9.9.9.9"); ok {
		t.Error("disconnected device was admitted again while the slot is used on another node")
	}
}

func TestConnTrackerGlobalStateKeepsDevicesWithinLimit(t *testing.T) {
	for name, tc := range map[string]struct {
		limit  int
		local  string
		global []string
	}{
		"survivor on this node":  {1, "1.1.1.1", []string{"1.1.1.1", "9.9.9.9"}},
		"total within the limit": {2, "9.9.9.9", []string{"1.1.1.1", "9.9.9.9"}},
		"only this node":         {1, "9.9.9.9", []string{"9.9.9.9"}},
	} {
		t.Run(name, func(t *testing.T) {
			tracker := limitedTracker(tc.limit)
			base := &testConn{}
			tracker.RoutedConnection(context.Background(), base, testInboundContext("uuid-1", tc.local), nil, nil)
			tracker.UpdateGlobalDevices(map[int][]string{1: tc.global})
			if base.closed {
				t.Error("device within the limit was disconnected")
			}
		})
	}
}

// The echo of a device that just left this node is not a second device.
func TestConnTrackerGlobalEchoDoesNotDisconnectNextDevice(t *testing.T) {
	tracker := limitedTracker(1)
	old, _ := admitted(tracker, "1.1.1.1")
	old.Close()
	base := &testConn{}
	tracker.RoutedConnection(context.Background(), base, testInboundContext("uuid-1", "9.9.9.9"), nil, nil)
	tracker.UpdateGlobalDevices(map[int][]string{1: {"1.1.1.1", "9.9.9.9"}})

	if base.closed {
		t.Error("device disconnected because of this node's own stale report")
	}
}

func TestConnTrackerLimitsUploadAndDownloadSeparately(t *testing.T) {
	tracker := NewConnTracker(0)
	tracker.SetUserMap(map[string]int{"uuid-1": 1})
	down := rate.NewLimiter(rate.Limit(1), 1000)
	up := rate.NewLimiter(rate.Limit(1), 1000)
	tracker.SetSpeedLimitFunc(func(string) *rate.Limiter { return down })
	tracker.SetUploadLimitFunc(func(string) *rate.Limiter { return up })

	base := &testConn{reads: [][]byte{make([]byte, 300)}}
	tracked := tracker.RoutedConnection(context.Background(), base, testInboundContext("uuid-1", "1.1.1.1"), nil, nil).(*trackedConn)
	if _, err := tracked.Read(make([]byte, 300)); err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if _, err := tracked.Write(make([]byte, 200)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	if got := up.Tokens(); got > 701 || got < 699 {
		t.Errorf("upload tokens = %.0f, want 700: reads (uploads) must draw from the upload bucket only", got)
	}
	if got := down.Tokens(); got > 801 || got < 799 {
		t.Errorf("download tokens = %.0f, want 800: writes (downloads) must draw from the download bucket only", got)
	}
}
