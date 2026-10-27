package xray

import (
	"context"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
)

var udpDest = net.UDPDestination(net.ParseAddress("9.9.9.9"), 53)

func userContextFrom(email, ip string) context.Context {
	return session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress(ip), 40000),
		User:   &protocol.MemoryUser{Email: email},
	})
}

func limitedDispatcher(limit int) (*LimitDispatcher, string) {
	ld, _ := newRevocationDispatcher()
	email := userEmail(1)
	ld.UpdateLimits(map[string]int{email: 1}, map[string]int{email: limit}, nil)
	return ld, email
}

// The panel pushes the IPs a user has online on every node; the device limit
// is per user, not per node.
func TestLimitDispatcher_GlobalDevicesCountTowardLimit(t *testing.T) {
	ld, email := limitedDispatcher(2)
	ld.UpdateGlobalDevices(map[int][]string{1: {"5.5.5.5", "6.6.6.6"}})

	if err := ld.DispatchLink(userContextFrom(email, "7.7.7.7"), tcpDest, newTestLink().link); err == nil {
		t.Error("a third device was admitted while two are online on other nodes")
	}
	if err := ld.DispatchLink(userContextFrom(email, "5.5.5.5"), tcpDest, newTestLink().link); err != nil {
		t.Errorf("a device already online on another node was rejected: %v", err)
	}
}

func TestLimitDispatcher_IgnoresStaleOrClearedGlobalDevices(t *testing.T) {
	ld, email := limitedDispatcher(1)
	ld.UpdateGlobalDevices(map[int][]string{1: {"5.5.5.5"}})
	ld.globalLastUpdate = time.Now().Add(-2 * globalDevicesTTL)
	if err := ld.DispatchLink(userContextFrom(email, "7.7.7.7"), tcpDest, newTestLink().link); err != nil {
		t.Errorf("stale global devices still counted: %v", err)
	}

	ld, email = limitedDispatcher(1)
	ld.UpdateGlobalDevices(map[int][]string{1: {"5.5.5.5"}})
	ld.ClearGlobalDevices()
	if err := ld.DispatchLink(userContextFrom(email, "7.7.7.7"), tcpDest, newTestLink().link); err != nil {
		t.Errorf("cleared global devices still counted: %v", err)
	}
}

// A device that only sends UDP (XUDP, Shadowsocks UDP) is still a device.
func TestLimitDispatcher_UDPDevicesCountTowardLimit(t *testing.T) {
	ld, email := limitedDispatcher(1)
	udp := newTestLink()
	if err := ld.DispatchLink(userContextFrom(email, "1.1.1.1"), udpDest, udp.link); err != nil {
		t.Fatalf("UDP device rejected: %v", err)
	}

	if err := ld.DispatchLink(userContextFrom(email, "2.2.2.2"), tcpDest, newTestLink().link); err == nil {
		t.Error("a second device was admitted while a UDP-only device holds the only slot")
	}
	if alive, _ := ld.GetConnectionState(); !alive[1]["1.1.1.1"] {
		t.Error("UDP-only device is not reported online")
	}

	udp.link.Writer.(interface{ Close() error }).Close()
	if err := ld.DispatchLink(userContextFrom(email, "2.2.2.2"), tcpDest, newTestLink().link); err != nil {
		t.Errorf("slot not released after the UDP device disconnected: %v", err)
	}
}

func TestXrayGlobalDevicesLimitNewDevices(t *testing.T) {
	user := model.UserSpec{ID: 1, UUID: rotationOldUUID, DeviceLimit: 1}
	target := rotationEchoServer(t)
	x, addr := newRotationXray(t, []model.UserSpec{user})

	// The only device slot is taken on another node by an IP that sorts
	// before this client's 127.0.0.1.
	x.UpdateGlobalDevices(map[int][]string{1: {"1.1.1.1"}})
	if c, err := openRotationEcho(addr, user.UUID, target); err == nil {
		c.Close()
		t.Fatal("connection admitted although the user's device limit is used on another node")
	}

	x.ClearGlobalDevices()
	requireRotationEcho(t, addr, user.UUID, target).Close()
}

func dispatchFrom(ld *LimitDispatcher, email, ip string) (*testLink, error) {
	l := newTestLink()
	return l, ld.DispatchLink(userContextFrom(email, ip), tcpDest, l.link)
}

func (l *testLink) close() { l.link.Writer.(interface{ Close() error }).Close() }

// A user first seen without a device limit keeps an entry in the unlimited
// table; connections admitted after a limit is set must still be released.
func TestLimitDispatcher_ReleasesDevicesOfUserWhoGainedLimit(t *testing.T) {
	ld, _ := newRevocationDispatcher()
	email := userEmail(1)
	ld.UpdateLimits(map[string]int{email: 1}, map[string]int{}, nil)
	unlimited, _ := dispatchFrom(ld, email, "1.1.1.1")
	unlimited.close()

	ld.UpdateLimits(map[string]int{email: 1}, map[string]int{email: 1}, nil)
	limited, err := dispatchFrom(ld, email, "1.1.1.1")
	if err != nil {
		t.Fatalf("first device rejected: %v", err)
	}
	limited.close()

	if alive, _ := ld.GetConnectionState(); len(alive[1]) != 0 {
		t.Errorf("devices still reported online after every connection closed: %v", alive[1])
	}
	if _, err := dispatchFrom(ld, email, "2.2.2.2"); err != nil {
		t.Errorf("new device rejected although none is online: %v", err)
	}
}

func TestLimitDispatcher_ReleasesDevicesOfUserWhoLostLimit(t *testing.T) {
	ld, email := limitedDispatcher(1)
	limited, _ := dispatchFrom(ld, email, "1.1.1.1")

	ld.UpdateLimits(map[string]int{email: 1}, map[string]int{}, nil)
	unlimited, _ := dispatchFrom(ld, email, "3.3.3.3")
	limited.close()
	unlimited.close()

	if alive, _ := ld.GetConnectionState(); len(alive[1]) != 0 {
		t.Errorf("devices still reported online after every connection closed: %v", alive[1])
	}
}

// Device slots are first come, first served: once the limit is reached a new
// IP is rejected whatever its sort order.
func TestLimitDispatcher_FullLimitRejectsLowerSortingIP(t *testing.T) {
	ld, email := limitedDispatcher(1)
	if _, err := dispatchFrom(ld, email, "9.9.9.9"); err != nil {
		t.Fatalf("first device rejected: %v", err)
	}
	if _, err := dispatchFrom(ld, email, "1.1.1.1"); err == nil {
		t.Error("a second device was admitted over the limit")
	}

	ld, email = limitedDispatcher(1)
	ld.UpdateGlobalDevices(map[int][]string{1: {"5.5.5.5"}})
	if _, err := dispatchFrom(ld, email, "1.1.1.1"); err == nil {
		t.Error("a second device was admitted while the slot is used on another node")
	}
}

// The panel's global state includes the devices this node reported itself,
// and trails them: a device that just left this node must not hold its slot
// against the same user's next IP (Wi-Fi to cellular).
func TestLimitDispatcher_IgnoresGlobalEchoOfDepartedDevice(t *testing.T) {
	ld, email := limitedDispatcher(1)
	old, _ := dispatchFrom(ld, email, "1.1.1.1")
	ld.UpdateGlobalDevices(map[int][]string{1: {"1.1.1.1"}})
	old.close()

	if _, err := dispatchFrom(ld, email, "2.2.2.2"); err != nil {
		t.Errorf("new IP rejected because of this node's own stale report: %v", err)
	}
}

// Global state received well after the device left here no longer echoes
// this node's report: the device is online on another node.
func TestLimitDispatcher_CountsDepartedDeviceStillOnlineElsewhere(t *testing.T) {
	ld, email := limitedDispatcher(1)
	old, _ := dispatchFrom(ld, email, "1.1.1.1")
	old.close()
	ld.departed[email]["1.1.1.1"] = time.Now().Add(-2 * kernel.DeviceEchoWindow)
	ld.UpdateGlobalDevices(map[int][]string{1: {"1.1.1.1"}})

	if _, err := dispatchFrom(ld, email, "2.2.2.2"); err == nil {
		t.Error("a second device was admitted while the first is online on another node")
	}
}

// Two nodes can each admit a device before the panel tells them about the
// other. Once global state shows the user over the limit, every node keeps
// the same lowest-sorting IPs and disconnects its other devices.
func TestLimitDispatcher_GlobalStateDisconnectsDeviceOverLimit(t *testing.T) {
	ld, email := limitedDispatcher(1)
	local, err := dispatchFrom(ld, email, "9.9.9.9")
	if err != nil {
		t.Fatalf("first device rejected: %v", err)
	}
	ld.UpdateGlobalDevices(map[int][]string{1: {"1.1.1.1", "9.9.9.9"}})

	if !local.interrupted() {
		t.Fatal("device over the limit stayed connected")
	}
	if alive, _ := ld.GetConnectionState(); len(alive[1]) != 0 {
		t.Errorf("disconnected device still reported online: %v", alive[1])
	}
	if _, err := dispatchFrom(ld, email, "9.9.9.9"); err == nil {
		t.Error("disconnected device was admitted again while the slot is used on another node")
	}
}

func TestLimitDispatcher_GlobalStateKeepsDevicesWithinLimit(t *testing.T) {
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
			ld, email := limitedDispatcher(tc.limit)
			local, _ := dispatchFrom(ld, email, tc.local)
			ld.UpdateGlobalDevices(map[int][]string{1: tc.global})
			if local.interrupted() {
				t.Error("device within the limit was disconnected")
			}
		})
	}
}

// The echo of a device that just left this node is not a second device.
func TestLimitDispatcher_GlobalEchoDoesNotDisconnectNextDevice(t *testing.T) {
	ld, email := limitedDispatcher(1)
	old, _ := dispatchFrom(ld, email, "1.1.1.1")
	old.close()
	next, _ := dispatchFrom(ld, email, "9.9.9.9")
	ld.UpdateGlobalDevices(map[int][]string{1: {"1.1.1.1", "9.9.9.9"}})

	if next.interrupted() {
		t.Error("device disconnected because of this node's own stale report")
	}
}
