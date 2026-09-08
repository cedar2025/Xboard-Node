//go:build with_quic && with_utls

package service

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/model"
)

// Real xray kernel: user-set changes on the hitless UserManager path, a
// native failure inside that path, and the service recovery around it, all
// verified with real VLESS clients against the listener.

const (
	testThirdUUID = "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d"
	// invalidCredential is longer than a UUID and longer than the 30
	// characters xray maps to a UUIDv5, so xray cannot build an account from
	// it: a real native failure on the user path.
	invalidCredential = "this-credential-is-not-a-valid-uuid-at-all"
)

func newRealXrayService(t *testing.T) *Service {
	t.Helper()
	s := newRealService(t)
	s.preferredKernel = model.KernelXray
	return s
}

func vlessWorks(t *testing.T, addr, uuid, target string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := plainVLESSDial(ctx, addr, uuid, target)
	if err != nil {
		t.Fatalf("vless handshake for %s: %v", uuid, err)
	}
	defer conn.Close()
	if body := httpsGetThrough(t, conn, target); !strings.HasPrefix(body, "hello from") {
		t.Fatalf("unexpected body for %s: %q", uuid, body)
	}
}

// vlessRejected asserts that uuid cannot proxy an HTTPS request through addr:
// xray must drop the request of an unknown credential instead of serving it.
func vlessRejected(t *testing.T, addr, uuid, target string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	conn, err := plainVLESSDial(ctx, addr, uuid, target)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	originTLS := tls.Client(conn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // local httptest origin
	if err := originTLS.HandshakeContext(ctx); err != nil {
		return
	}
	req, _ := http.NewRequest(http.MethodGet, "https://"+target+"/probe", nil)
	if err := req.Write(originTLS); err != nil {
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(originTLS), req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK && strings.HasPrefix(string(body), "hello from") {
		t.Fatalf("credential %s still proxies HTTPS through %s", uuid, addr)
	}
}

// A WS full sync that rotates one credential and keeps another: the new
// credential authenticates, the old one is refused, and a limit-only change
// afterwards keeps the node applied.
func TestRealXrayCredentialRotationInvalidatesTheOldCredential(t *testing.T) {
	s := newRealXrayService(t)
	_, target := localHTTPSTarget(t)
	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: realPlainVLESSSpec(port), Users: []model.UserSpec{{ID: 1, UUID: testUUID}, {ID: 2, UUID: testOtherUUID}}})
	applied(t, s, "vless")
	if s.appliedState.Kernel != model.KernelXray {
		t.Fatalf("expected xray, got %s", s.appliedState.Kernel)
	}
	vlessWorks(t, addr, testUUID, target)
	vlessWorks(t, addr, testOtherUUID, target)

	rotated := []model.UserSpec{{ID: 1, UUID: testThirdUUID}, {ID: 2, UUID: testOtherUUID}}
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUsers, Users: rotated})
	if s.appliedState.UserHash != s.lastUserHash || s.retryPending {
		t.Fatalf("rotation not applied: applied=%+v err=%v", s.appliedState, s.lastApplyErr)
	}
	vlessWorks(t, addr, testThirdUUID, target)
	vlessWorks(t, addr, testOtherUUID, target)
	vlessRejected(t, addr, testUUID, target)

	limited := []model.UserSpec{{ID: 1, UUID: testThirdUUID, SpeedLimit: 8}, {ID: 2, UUID: testOtherUUID, DeviceLimit: 2}}
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUsers, Users: limited})
	if s.appliedState.UserHash != s.lastUserHash || s.retryPending {
		t.Fatalf("limit-only change not applied: applied=%+v err=%v", s.appliedState, s.lastApplyErr)
	}
	vlessWorks(t, addr, testThirdUUID, target)
	vlessRejected(t, addr, testUUID, target)
}

// A native failure on the xray user path must not become a false success. The
// panel revokes user 1 and adds a user whose credential xray cannot build.
// The listener must stop rather than keep serving the revoked credential, the
// desired set is kept for the retry, and the node comes back with exactly the
// corrected set.
func TestRealXrayNativeUserFailureStopsListenerUntilTheDesiredUsersApply(t *testing.T) {
	s := newRealXrayService(t)
	_, target := localHTTPSTarget(t)
	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: realPlainVLESSSpec(port), Users: []model.UserSpec{{ID: 1, UUID: testUUID}, {ID: 2, UUID: testOtherUUID}}})
	applied(t, s, "vless")
	vlessWorks(t, addr, testUUID, target)

	broken := []model.UserSpec{{ID: 2, UUID: testOtherUUID}, {ID: 3, UUID: invalidCredential}}
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUsers, Users: broken})
	if s.appliedState.Running || s.appliedState.UserHash != "" || len(s.appliedState.Users) != 0 {
		t.Fatalf("a failed native user update advanced the applied state: %+v", s.appliedState)
	}
	if !s.retryPending || s.lastApplyStage != "users" || s.lastApplyErr == nil {
		t.Fatalf("expected a retried user failure: pending=%v stage=%s err=%v", s.retryPending, s.lastApplyStage, s.lastApplyErr)
	}
	if computeUserHash(s.lastUsers) != computeUserHash(broken) {
		t.Fatalf("desired users must be kept for the retry, got %v", s.lastUsers)
	}
	tcpRefused(t, addr)

	// The retry cannot apply the broken set either: the node stays down and
	// keeps retrying, it never brings the revoked credential back.
	s.reconcile(context.Background())
	if s.appliedState.Running || !s.retryPending || s.lastApplyStage != "prepare" {
		t.Fatalf("retry with the broken set: applied=%+v pending=%v stage=%s err=%v", s.appliedState, s.retryPending, s.lastApplyStage, s.lastApplyErr)
	}
	tcpRefused(t, addr)

	// The panel corrects the credential through REST.
	fixed := []model.UserSpec{{ID: 2, UUID: testOtherUUID}, {ID: 3, UUID: testThirdUUID}}
	s.applyPullResult(context.Background(), pullResult{users: fixed, userHash: computeUserHash(fixed), gen: s.desiredGen})
	applied(t, s, "vless")
	if s.appliedState.UserHash != s.lastUserHash || s.retryPending {
		t.Fatalf("corrected users not applied: applied=%+v err=%v", s.appliedState, s.lastApplyErr)
	}
	vlessWorks(t, addr, testOtherUUID, target)
	vlessWorks(t, addr, testThirdUUID, target)
	vlessRejected(t, addr, testUUID, target)
}
