//go:build linux

package xray

import (
	"context"
	"io"
	gonet "net"
	"testing"
	"time"

	xrayDispatcher "github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"golang.org/x/time/rate"
)

// tcpPair returns both ends of a loopback TCP connection.
func tcpPair(t *testing.T) (client, server *gonet.TCPConn) {
	t.Helper()
	ln, err := gonet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()
	accepted := make(chan gonet.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	c, err := gonet.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	s := <-accepted
	if s == nil {
		t.Fatal("Accept() failed")
	}
	t.Cleanup(func() { c.Close(); s.Close() })
	return c.(*gonet.TCPConn), s.(*gonet.TCPConn)
}

// A speed-limited user's download must reach the user traffic counter even
// when the inbound and outbound would otherwise switch to splice copy, which
// moves bytes in the kernel past both the rate limiter and the counter.
func TestSpeedLimitedDownloadIsCountedOnSpliceCapableConnection(t *testing.T) {
	const payload = 256 * 1024

	// remote → node (outbound connection) and node → client (inbound connection).
	remote, fromRemote := tcpPair(t)
	toClient, client := tcpPair(t)

	go func() {
		remote.Write(make([]byte, payload))
		remote.Close()
	}()
	received := make(chan int64, 1)
	go func() {
		n, _ := io.Copy(io.Discard, client)
		received <- n
	}()

	ld, _ := newRevocationDispatcher()
	email := userEmail(1)
	ld.UpdateLimits(map[string]int{email: 1}, nil, map[string]int{email: 100})

	ctx, inbound := spliceCandidateContext(email)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{CanSpliceCopy: 1}})
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// The writer chain xray-core builds for a user with a speed limit.
	counter := mustRegisterCounter(t, newStatsManager(t), counterName(1, "downlink"))
	link := &transport.Link{
		Reader: nopReader{},
		Writer: &xrayDispatcher.RateLimitWriter{
			Writer:  &xrayDispatcher.SizeStatWriter{Counter: counter, Writer: buf.NewWriter(toClient)},
			Limiter: rate.NewLimiter(rate.Inf, 0),
			Context: ctx,
		},
	}
	downlink := link.Writer
	if err := ld.DispatchLink(ctx, tcpDest, link); err != nil {
		t.Fatalf("DispatchLink() error = %v", err)
	}

	// VLESS Vision promotes the inbound to splice once it sees TLS 1.3
	// application data, unless splice was ruled out for the connection.
	if inbound.CanSpliceCopy == 2 {
		inbound.CanSpliceCopy = 1
	}

	timer := signal.CancelAfterInactivity(ctx, cancel, time.Minute)
	if err := proxy.CopyRawConnIfExist(ctx, fromRemote, toClient, downlink, timer, nil); err != nil {
		t.Fatalf("CopyRawConnIfExist() error = %v", err)
	}
	toClient.Close()

	if got := <-received; got != payload {
		t.Fatalf("client received %d bytes, want %d", got, payload)
	}
	if got := counter.Value(); got != payload {
		t.Fatalf("user downlink counter = %d, want %d", got, payload)
	}
}
