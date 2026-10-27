package xray

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport"
)

func newTestDispatcher() *LimitDispatcher {
	return &LimitDispatcher{
		limitedIPs: make(map[string]map[string]int),
	}
}

// rejects reports whether the dispatcher refuses a connection from sourceIP.
func rejects(ld *LimitDispatcher, email, sourceIP string) bool {
	rejected, _ := ld.checkDeviceLimit(email, sourceIP)
	return rejected
}

type nopReader struct{}

func (nopReader) ReadMultiBuffer() (buf.MultiBuffer, error) { return nil, nil }

func TestLimitDispatcher_DeviceLimitCheck(t *testing.T) {
	ld := newTestDispatcher()

	users := []model.UserSpec{
		{ID: 1, UUID: "uuid-1", DeviceLimit: 2, SpeedLimit: 0},
		{ID: 2, UUID: "uuid-2", DeviceLimit: 0, SpeedLimit: 10},
	}

	emailToUID := make(map[string]int)
	deviceLimits := make(map[string]int)
	speedLimits := make(map[string]int)
	for _, u := range users {
		email := userEmail(u.ID)
		emailToUID[email] = u.ID
		if u.DeviceLimit > 0 {
			deviceLimits[email] = u.DeviceLimit
		}
		if u.SpeedLimit > 0 {
			speedLimits[email] = u.SpeedLimit
		}
	}
	ld.UpdateLimits(emailToUID, deviceLimits, speedLimits)

	email1 := userEmail(1)

	// First IP should be allowed
	if rejects(ld, email1, "1.1.1.1") {
		t.Error("first IP should be allowed")
	}

	// Second IP should be allowed (limit=2)
	if rejects(ld, email1, "2.2.2.2") {
		t.Error("second IP should be allowed")
	}

	// Third unique IP should be rejected
	if !rejects(ld, email1, "3.3.3.3") {
		t.Error("third IP should be rejected (limit=2)")
	}

	// Same IP as first should be allowed (already connected)
	if rejects(ld, email1, "1.1.1.1") {
		t.Error("same IP should always be allowed")
	}

	// User 2 has no device limit — should always be allowed
	email2 := userEmail(2)
	for i := 0; i < 10; i++ {
		ip := "10.0.0." + string(rune('0'+i))
		if rejects(ld, email2, ip) {
			t.Errorf("user with no device limit should always be allowed (ip=%s)", ip)
		}
	}
}

func TestLimitDispatcher_DelConn(t *testing.T) {
	ld := newTestDispatcher()

	email := userEmail(1)
	deviceLimits := map[string]int{email: 2}
	ld.UpdateLimits(map[string]int{email: 1}, deviceLimits, nil)

	// Add 2 IPs
	rejects(ld, email, "1.1.1.1")
	rejects(ld, email, "2.2.2.2")

	// Third should be rejected
	if !rejects(ld, email, "3.3.3.3") {
		t.Error("third IP should be rejected")
	}

	// Remove first IP
	ld.delConn(email, "1.1.1.1", true)

	// Now third IP should be allowed
	if rejects(ld, email, "3.3.3.3") {
		t.Error("after deleting one IP, new IP should be allowed")
	}
}

func TestLimitDispatcher_ConcurrentLimitedConnections(t *testing.T) {
	ld := newTestDispatcher()
	email := userEmail(1)
	const sourceIP = "1.1.1.1"
	ld.UpdateLimits(map[string]int{email: 1}, map[string]int{email: 1}, nil)

	// Repeatedly race a new connection against the last connection closing.
	// Both operations must agree on the lifetime of the user's IP map.
	const workers, iterations = 8, 10000
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range iterations {
				if rejects(ld, email, sourceIP) {
					t.Error("connections from the same IP must remain allowed")
					return
				}
				ld.delConn(email, sourceIP, true)
			}
		}()
	}
	close(start)
	wg.Wait()

	ld.mu.RLock()
	remaining := len(ld.limitedIPs[email])
	ld.mu.RUnlock()
	if remaining != 0 {
		t.Fatalf("all connections closed, but %d IPs are still tracked", remaining)
	}
	if rejects(ld, email, "2.2.2.2") {
		t.Fatal("a new IP should be admitted after the previous connections close")
	}
	if !rejects(ld, email, "3.3.3.3") {
		t.Fatal("the device limit must still reject an additional higher-sorting IP")
	}
	ld.delConn(email, "2.2.2.2", true)
}

func TestLimitDispatcher_GetConnectionState(t *testing.T) {
	ld := newTestDispatcher()

	email1 := userEmail(1)
	email2 := userEmail(2)
	ld.UpdateLimits(map[string]int{email1: 1, email2: 2}, nil, nil)

	ic1 := &ipCounter{}
	r1 := &atomic.Int64{}
	r1.Store(1)
	ic1.ips.Store("1.1.1.1", r1)
	r2 := &atomic.Int64{}
	r2.Store(1)
	ic1.ips.Store("2.2.2.2", r2)
	ld.unlimitedIPs.Store(email1, ic1)

	ic2 := &ipCounter{}
	r3 := &atomic.Int64{}
	r3.Store(1)
	ic2.ips.Store("3.3.3.3", r3)
	ld.unlimitedIPs.Store(email2, ic2)

	ld.connCount.Store(5)

	aliveIPs, connCount := ld.GetConnectionState()

	if connCount != 5 {
		t.Errorf("expected connCount=5, got %d", connCount)
	}
	if len(aliveIPs[1]) != 2 {
		t.Errorf("user 1 IPs: got %d, want 2", len(aliveIPs[1]))
	}
	if len(aliveIPs[2]) != 1 {
		t.Errorf("user 2 IPs: got %d, want 1", len(aliveIPs[2]))
	}
}

func TestLimitDispatcher_ConcurrentConnectionStateSnapshot(t *testing.T) {
	ld := newTestDispatcher()
	email := userEmail(1)
	ld.UpdateLimits(map[string]int{email: 1}, map[string]int{email: 8}, nil)

	const writers, readers, iterations = 4, 4, 20000
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}
	start := make(chan struct{})
	var wg sync.WaitGroup
	var unexpectedlyRejected atomic.Bool

	for worker := range writers {
		wg.Add(1)
		go func(sourceIP string) {
			defer wg.Done()
			<-start
			for range iterations {
				if rejects(ld, email, sourceIP) {
					unexpectedlyRejected.Store(true)
					return
				}
				ld.delConn(email, sourceIP, true)
			}
		}(ips[worker])
	}
	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range iterations {
				aliveIPs, _ := ld.GetConnectionState()
				for range aliveIPs[1] {
				}
			}
		}()
	}

	close(start)
	wg.Wait()
	if unexpectedlyRejected.Load() {
		t.Fatal("connections below the configured device limit must remain allowed")
	}
}

func TestLimitDispatcher_ResetConns(t *testing.T) {
	ld := newTestDispatcher()

	ld.mu.Lock()
	ld.limitedIPs["user@1"] = map[string]int{"1.1.1.1": 1}
	ld.mu.Unlock()
	ld.connCount.Store(3)

	ld.ResetConns()

	ld.mu.RLock()
	ipCount := len(ld.limitedIPs)
	ld.mu.RUnlock()
	if ipCount != 0 {
		t.Error("limitedIPs should be empty after reset")
	}

	if ld.connCount.Load() != 0 {
		t.Error("connCount should be 0 after reset")
	}
}

func TestLimitDispatcher_UnlimitedUserFastPath(t *testing.T) {
	ld := newTestDispatcher()

	email := userEmail(1)
	// No device limit set for this user
	ld.UpdateLimits(map[string]int{email: 1}, nil, nil)

	// Should use fast path (sync.Map), no lock needed
	for i := 0; i < 100; i++ {
		ip := "10.0.0." + string(rune('0'+i%10))
		if rejects(ld, email, ip) {
			t.Errorf("unlimited user should always be allowed (ip=%s)", ip)
		}
	}

	// Verify IPs are tracked in unlimitedIPs
	v, ok := ld.unlimitedIPs.Load(email)
	if !ok {
		t.Error("unlimited user should have entry in unlimitedIPs")
	}
	ic := v.(*ipCounter)
	ips := ic.aliveIPs()
	if len(ips) == 0 {
		t.Error("should have tracked some IPs")
	}
}

func TestLimitDispatcher_TrackLinkPreservesReader(t *testing.T) {
	ld := newTestDispatcher()
	email := userEmail(1)
	ld.UpdateLimits(map[string]int{email: 1}, map[string]int{email: 1}, nil)

	origReader := nopReader{}
	origWriter := &closeTrackingWriter{Writer: buf.Discard, onClose: func() {}}
	link := &transport.Link{Reader: origReader, Writer: origWriter}

	ld.trackLink(context.Background(), link, email, "1.1.1.1", true)

	if link.Reader != origReader {
		t.Fatal("trackLink must not replace link.Reader")
	}
	if link.Writer == origWriter {
		t.Fatal("trackLink should wrap link.Writer for lifecycle callbacks")
	}
}

func TestLimitDispatcher_CloseTrackingWriterReleasesConn(t *testing.T) {
	ld := newTestDispatcher()
	email := userEmail(1)
	ld.UpdateLimits(map[string]int{email: 1}, map[string]int{email: 1}, nil)
	if rejects(ld, email, "1.1.1.1") {
		t.Fatal("first connection should be allowed")
	}

	link := &transport.Link{Reader: nopReader{}, Writer: buf.Discard}
	ld.trackLink(context.Background(), link, email, "1.1.1.1", true)

	if got := ld.connCount.Load(); got != 1 {
		t.Fatalf("expected connCount=1 after tracking, got %d", got)
	}
	cw, ok := link.Writer.(*closeTrackingWriter)
	if !ok {
		t.Fatal("expected closeTrackingWriter wrapper")
	}
	if err := cw.Close(); err != nil {
		t.Fatalf("closeTrackingWriter.Close() error = %v", err)
	}
	if got := ld.connCount.Load(); got != 0 {
		t.Fatalf("expected connCount=0 after close, got %d", got)
	}
	if rejects(ld, email, "2.2.2.2") {
		t.Fatal("device slot should be released after writer close")
	}
}
