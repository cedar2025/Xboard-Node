//go:build with_quic && with_utls

package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/model"
)

func TestHysteriaConcurrentAuthenticationAndUserRefresh(t *testing.T) {
	s := newRealService(t)
	_, target := localHTTPSTarget(t)
	port := freePort(t)
	spec := realHysteria2Spec(port)
	a := model.UserSpec{ID: 1, UUID: testUUID}
	b := model.UserSpec{ID: 2, UUID: testOtherUUID}
	s.setDesiredConfig(spec, computeConfigHash(spec))
	s.setDesiredUsers([]model.UserSpec{a, b})
	s.reconcile(context.Background())
	applied(t, s, "hysteria")
	ca := autoCertPEM(t, s)
	start := make(chan struct{})
	results := make(chan int, 4)
	for w := 0; w < 4; w++ {
		go func() {
			<-start
			succeeded := 0
			for i := 0; i < 16; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				_, closeFn, err := hysteria2Dial(ctx, fmt.Sprintf("127.0.0.1:%d", port), testUUID, ca, target)
				if err == nil {
					closeFn()
					succeeded++
				}
				cancel()
			}
			results <- succeeded
		}()
	}
	close(start)
	for i := 0; i < 80; i++ {
		users := []model.UserSpec{a}
		if i%2 == 0 {
			users = append(users, b)
		}
		s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUsers, Users: users})
		time.Sleep(time.Millisecond)
	}
	total := 0
	for i := 0; i < 4; i++ {
		total += <-results
	}
	t.Logf("%d/64 authentication attempts completed during listener replacement", total)
	// Replacement may interrupt a concurrent connection, but must never race
	// authentication state and must serve the final authorized snapshot.
	assertHysteria2Works(t, s, port, target)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, closeFn, err := hysteria2Dial(ctx, fmt.Sprintf("127.0.0.1:%d", port), testOtherUUID, ca, target); err == nil {
		closeFn()
		t.Fatal("final revoked user still authenticates")
	}
}
