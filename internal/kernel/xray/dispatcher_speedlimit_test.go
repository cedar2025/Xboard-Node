package xray

import (
	"context"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"golang.org/x/time/rate"
)

// spliceCandidateContext is a session whose inbound may still switch to
// splice copy, the state a VLESS Vision inbound dispatches with.
func spliceCandidateContext(email string) (context.Context, *session.Inbound) {
	inbound := &session.Inbound{
		Source:        net.TCPDestination(net.ParseAddress("1.1.1.1"), 40000),
		User:          &protocol.MemoryUser{Email: email},
		CanSpliceCopy: 2,
	}
	return session.ContextWithInbound(context.Background(), inbound), inbound
}

func TestLimitDispatcher_DispatchLinkDisablesSpliceForSpeedLimitedUser(t *testing.T) {
	ld, _ := newRevocationDispatcher()
	email := userEmail(1)
	ld.UpdateLimits(map[string]int{email: 1}, nil, map[string]int{email: 10})

	ctx, inbound := spliceCandidateContext(email)
	if err := ld.DispatchLink(ctx, tcpDest, newTestLink().link); err != nil {
		t.Fatalf("DispatchLink() error = %v", err)
	}

	if inbound.CanSpliceCopy != 3 {
		t.Fatalf("CanSpliceCopy = %d, want 3: splice copy bypasses the rate limiter and the user traffic counter", inbound.CanSpliceCopy)
	}
}

func TestLimitDispatcher_DispatchLinkKeepsSpliceForUnlimitedUser(t *testing.T) {
	ld, _ := newRevocationDispatcher()
	limited, unlimited := userEmail(1), userEmail(2)
	ld.UpdateLimits(map[string]int{limited: 1, unlimited: 2}, nil, map[string]int{limited: 10})

	ctx, inbound := spliceCandidateContext(unlimited)
	if err := ld.DispatchLink(ctx, tcpDest, newTestLink().link); err != nil {
		t.Fatalf("DispatchLink() error = %v", err)
	}

	if inbound.CanSpliceCopy != 2 {
		t.Fatalf("CanSpliceCopy = %d, want 2: users without a speed limit keep splice copy", inbound.CanSpliceCopy)
	}
}

func TestXrayUpdateDispatcherLimitsDisablesSpliceForSpeedLimitedUsers(t *testing.T) {
	ld, _ := newRevocationDispatcher()
	x := New(config.KernelConfig{Type: "xray"})
	x.limitDispatcher = ld

	x.updateDispatcherLimits([]model.UserSpec{
		{ID: 1, UUID: "uuid-1", SpeedLimit: 10},
		{ID: 2, UUID: "uuid-2"},
	})

	for _, tc := range []struct {
		userID int
		want   int
	}{
		{userID: 1, want: 3},
		{userID: 2, want: 2},
	} {
		ctx, inbound := spliceCandidateContext(userEmail(tc.userID))
		if err := ld.DispatchLink(ctx, tcpDest, newTestLink().link); err != nil {
			t.Fatalf("DispatchLink(user %d) error = %v", tc.userID, err)
		}
		if inbound.CanSpliceCopy != tc.want {
			t.Errorf("user %d: CanSpliceCopy = %d, want %d", tc.userID, inbound.CanSpliceCopy, tc.want)
		}
	}
}

// linkCapturingInner records the link it is handed, as xray's DefaultDispatcher
// would go on to read the uplink from it.
type linkCapturingInner struct {
	countingInner
	link *transport.Link
}

func (c *linkCapturingInner) DispatchLink(_ context.Context, _ net.Destination, link *transport.Link) error {
	c.link = link
	return nil
}

// chunkReader yields one n-byte buffer per read, like a client sending data.
type chunkReader struct{ n int }

func (r chunkReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	b.Extend(int32(r.n))
	return buf.MultiBuffer{b}, nil
}

func TestLimitDispatcher_DispatchLinkLimitsUplinkOfSpeedLimitedUser(t *testing.T) {
	ld, _ := newRevocationDispatcher()
	inner := &linkCapturingInner{}
	ld.inner, ld.innerDisp = inner, inner
	email := userEmail(1)
	lim := rate.NewLimiter(rate.Limit(1000), 64*1024)
	ld.UpdateLimits(map[string]int{email: 1}, nil, map[string]int{email: 10})
	ld.SetUploadLimiters(map[string]*rate.Limiter{email: lim})

	ctx, _ := spliceCandidateContext(email)
	if err := ld.DispatchLink(ctx, tcpDest, &transport.Link{Reader: chunkReader{n: 8000}, Writer: &interruptibleWriter{}}); err != nil {
		t.Fatalf("DispatchLink() error = %v", err)
	}
	mb, err := inner.link.Reader.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("ReadMultiBuffer() error = %v", err)
	}
	buf.ReleaseMulti(mb)

	// xray-core's WrapLink limits only the downlink writer of a DispatchLink
	// link, so the uplink must draw from the user's upload limiter here.
	if got := lim.Tokens(); got > 64*1024-8000+100 {
		t.Fatalf("limiter tokens = %.0f after an 8000-byte upload, want about %d: uplink bypasses the speed limit", got, 64*1024-8000)
	}
}

func TestLimitDispatcher_DispatchLinkLeavesUplinkOfUnlimitedUserAlone(t *testing.T) {
	ld, _ := newRevocationDispatcher()
	inner := &linkCapturingInner{}
	ld.inner, ld.innerDisp = inner, inner
	limited, unlimited := userEmail(1), userEmail(2)
	ld.UpdateLimits(map[string]int{limited: 1, unlimited: 2}, nil, map[string]int{limited: 10})
	ld.SetUploadLimiters(map[string]*rate.Limiter{limited: rate.NewLimiter(1000, 64*1024)})

	reader := chunkReader{n: 10}
	ctx, _ := spliceCandidateContext(unlimited)
	if err := ld.DispatchLink(ctx, tcpDest, &transport.Link{Reader: reader, Writer: &interruptibleWriter{}}); err != nil {
		t.Fatalf("DispatchLink() error = %v", err)
	}
	if inner.link.Reader != buf.Reader(reader) {
		t.Fatalf("uplink reader = %T, want the inbound's own reader", inner.link.Reader)
	}
}

func TestXrayUpdateDispatcherLimitsUsesUploadBuckets(t *testing.T) {
	ld, _ := newRevocationDispatcher()
	inner := &linkCapturingInner{}
	ld.inner, ld.innerDisp = inner, inner
	x := New(config.KernelConfig{Type: "xray"})
	x.limitDispatcher = ld
	up := rate.NewLimiter(rate.Limit(1000), 64*1024)
	x.uploadLimitFunc = func(uuid string) *rate.Limiter {
		if uuid == "uuid-1" {
			return up
		}
		return nil
	}

	x.updateDispatcherLimits([]model.UserSpec{{ID: 1, UUID: "uuid-1", SpeedLimit: 10}})

	ctx, _ := spliceCandidateContext(userEmail(1))
	if err := ld.DispatchLink(ctx, tcpDest, &transport.Link{Reader: chunkReader{n: 8000}, Writer: &interruptibleWriter{}}); err != nil {
		t.Fatalf("DispatchLink() error = %v", err)
	}
	mb, _ := inner.link.Reader.ReadMultiBuffer()
	buf.ReleaseMulti(mb)
	if got := up.Tokens(); got > 64*1024-8000+100 {
		t.Fatalf("upload bucket tokens = %.0f, want about %d: the uplink must use the upload bucket", got, 64*1024-8000)
	}
}
