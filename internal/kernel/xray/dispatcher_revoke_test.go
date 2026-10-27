package xray

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

type countingInner struct {
	dispatched atomic.Int32
}

func (*countingInner) Type() interface{} { return nil }
func (*countingInner) Start() error      { return nil }
func (*countingInner) Close() error      { return nil }
func (*countingInner) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	return nil, nil
}
func (c *countingInner) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	c.dispatched.Add(1)
	return nil
}

type interruptibleReader struct {
	nopReader
	interrupted atomic.Bool
}

func (r *interruptibleReader) Interrupt() { r.interrupted.Store(true) }

type interruptibleWriter struct {
	interrupted atomic.Bool
}

func (*interruptibleWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return nil
}
func (w *interruptibleWriter) Interrupt() { w.interrupted.Store(true) }

type testLink struct {
	reader *interruptibleReader
	writer *interruptibleWriter
	link   *transport.Link
}

func newTestLink() *testLink {
	l := &testLink{reader: &interruptibleReader{}, writer: &interruptibleWriter{}}
	l.link = &transport.Link{Reader: l.reader, Writer: l.writer}
	return l
}

func (l *testLink) interrupted() bool {
	return l.reader.interrupted.Load() && l.writer.interrupted.Load()
}

func userContext(email string) context.Context {
	return session.ContextWithInbound(context.Background(), &session.Inbound{
		Source: net.TCPDestination(net.ParseAddress("1.1.1.1"), 40000),
		User:   &protocol.MemoryUser{Email: email},
	})
}

func newRevocationDispatcher() (*LimitDispatcher, *countingInner) {
	inner := &countingInner{}
	ld := newTestDispatcher()
	ld.inner = inner
	ld.innerDisp = inner
	return ld, inner
}

var tcpDest = net.TCPDestination(net.ParseAddress("9.9.9.9"), 443)

func TestLimitDispatcher_AdmitsEveryoneBeforeUsersAreKnown(t *testing.T) {
	ld, inner := newRevocationDispatcher()
	if err := ld.DispatchLink(userContext(userEmail(1)), tcpDest, newTestLink().link); err != nil {
		t.Fatalf("DispatchLink() before UpdateLimits error = %v", err)
	}
	if inner.dispatched.Load() != 1 {
		t.Fatal("connection was not dispatched")
	}
}

func TestLimitDispatcher_RejectsRemovedUser(t *testing.T) {
	ld, inner := newRevocationDispatcher()
	ld.UpdateLimits(map[string]int{userEmail(1): 1}, map[string]int{}, nil)

	if err := ld.DispatchLink(userContext(userEmail(2)), tcpDest, newTestLink().link); err == nil {
		t.Fatal("removed user's connection was admitted")
	}
	if err := ld.DispatchLink(userContext(userEmail(1)), tcpDest, newTestLink().link); err != nil {
		t.Fatalf("current user's connection was rejected: %v", err)
	}
	if got := inner.dispatched.Load(); got != 1 {
		t.Fatalf("dispatched = %d, want 1", got)
	}
}

func TestLimitDispatcher_UpdateLimitsInterruptsRemovedUsersLinks(t *testing.T) {
	ld, _ := newRevocationDispatcher()
	ld.UpdateLimits(map[string]int{userEmail(1): 1, userEmail(2): 2}, map[string]int{}, nil)
	removed := newTestLink()
	kept := newTestLink()
	if err := ld.DispatchLink(userContext(userEmail(1)), tcpDest, removed.link); err != nil {
		t.Fatal(err)
	}
	if err := ld.DispatchLink(userContext(userEmail(2)), tcpDest, kept.link); err != nil {
		t.Fatal(err)
	}

	ld.UpdateLimits(map[string]int{userEmail(2): 2}, map[string]int{}, nil)

	if !removed.interrupted() {
		t.Error("removed user's link was not interrupted")
	}
	if kept.reader.interrupted.Load() || kept.writer.interrupted.Load() {
		t.Error("remaining user's link was interrupted")
	}
	if _, connCount := ld.GetConnectionState(); connCount != 1 {
		t.Errorf("connCount = %d, want 1", connCount)
	}
}

func TestLimitDispatcher_RevocationRacesWithAdmission(t *testing.T) {
	for i := 0; i < 200; i++ {
		ld, _ := newRevocationDispatcher()
		ld.UpdateLimits(map[string]int{userEmail(1): 1}, map[string]int{}, nil)
		l := newTestLink()
		var admitted atomic.Bool

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			admitted.Store(ld.DispatchLink(userContext(userEmail(1)), tcpDest, l.link) == nil)
		}()
		go func() {
			defer wg.Done()
			ld.UpdateLimits(map[string]int{}, map[string]int{}, nil)
		}()
		wg.Wait()

		if admitted.Load() && !l.interrupted() {
			t.Fatalf("iteration %d: link admitted around revocation stayed open", i)
		}
	}
}
