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

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/model"
)

// Independent review: requested TLS must not expose the VLESS authentication
// protocol on a plaintext socket merely because certificates were omitted.
func TestRequestedTLSRejectsPlaintextVLESS(t *testing.T) {
	for _, explicitNone := range []bool{false, true} {
		name := "certificate_omitted"
		if explicitNone {
			name = "explicit_none"
		}
		t.Run(name, func(t *testing.T) {
			s := newRealService(t)
			_, target := localHTTPSTarget(t)
			port := freePort(t)
			spec := realPlainVLESSSpec(port)
			spec.TLS = 1
			spec.ServerName = "tls.review.test"
			if explicitNone {
				spec.CertConfig = &config.CertConfig{CertMode: "none"}
			}
			s.setDesiredConfig(spec, computeConfigHash(spec))
			s.setDesiredUsers([]model.UserSpec{{ID: 1, UUID: testUUID}})
			s.reconcile(context.Background())
			if !s.appliedState.Running {
				if explicitNone && s.lastApplyErr != nil {
					return
				}
				t.Fatalf("omitted cert should prepare TLS in managed mode: %v", s.lastApplyErr)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			conn, err := plainVLESSDial(ctx, fmt.Sprintf("127.0.0.1:%d", port), testUUID, target)
			if err != nil {
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(4 * time.Second))
			originTLS := tls.Client(conn, &tls.Config{InsecureSkipVerify: true}) // local test origin only
			if err := originTLS.HandshakeContext(ctx); err != nil {
				return
			}
			req, _ := http.NewRequest(http.MethodGet, "https://"+target+"/review", nil)
			if err := req.Write(originTLS); err != nil {
				return
			}
			resp, err := http.ReadResponse(bufio.NewReader(originTLS), req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode == 200 && strings.HasPrefix(string(body), "hello from") {
				t.Fatalf("TLS=1 accepted plaintext VLESS authentication and proxied HTTPS; cert=%s/%s, material=%v", s.appliedState.CertSource, s.appliedState.CertMode, s.appliedState.TLS.HasCert())
			}
		})
	}
}

func TestRevocationDuringFailedProtocolSwitch(t *testing.T) {
	for _, path := range []string{"ws_delta", "ws_full", "rest"} {
		t.Run(path, func(t *testing.T) {
			s := newRealService(t)
			_, target := localHTTPSTarget(t)
			port := freePort(t)
			spec := realHysteria2Spec(port)
			users := []model.UserSpec{{ID: 1, UUID: testUUID}, {ID: 2, UUID: testOtherUUID}}
			s.setDesiredConfig(spec, computeConfigHash(spec))
			s.setDesiredUsers(users)
			s.reconcile(context.Background())
			applied(t, s, "hysteria")
			ca := autoCertPEM(t, s)

			// xhttp needs xray, whereas this mux requires sing-box: neither
			// kernel accepts this requested target, so the old service stays up.
			bad := &model.NodeSpec{Protocol: "vmess", ServerPort: port, Network: "xhttp", Multiplex: &model.MultiplexConfig{Enabled: true}}
			s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: bad})
			if s.lastApplyStage != "prepare" || s.lastApplyErr == nil {
				t.Fatal("invalid target was not rejected")
			}
			remaining := users[1:]
			switch path {
			case "ws_delta":
				s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "remove", DeltaUsers: users[:1]})
			case "ws_full":
				s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUsers, Users: remaining})
			case "rest":
				s.applyPullResult(context.Background(), pullResult{users: remaining, userHash: computeUserHash(remaining), gen: s.desiredGen})
			}
			if len(s.lastUsers) != 1 || s.lastUsers[0].ID != 2 {
				t.Fatal("revocation never reached desired state")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			conn, closeFn, err := hysteria2Dial(ctx, fmt.Sprintf("127.0.0.1:%d", port), testUUID, ca, target)
			if err == nil {
				defer closeFn()
				body := httpsGetThrough(t, conn, target)
				t.Fatalf("revoked user opened a NEW authenticated QUIC connection and read HTTPS via retained old kernel: %q", body)
			}
		})
	}
}

func TestStaleRESTUsersCannotRestoreRevokedCredential(t *testing.T) {
	s := newRealService(t)
	_, target := localHTTPSTarget(t)
	port := freePort(t)
	spec := realHysteria2Spec(port)
	oldUsers := []model.UserSpec{{ID: 1, UUID: testUUID}, {ID: 2, UUID: testOtherUUID}}
	s.setDesiredConfig(spec, computeConfigHash(spec))
	s.setDesiredUsers(oldUsers)
	s.reconcile(context.Background())
	applied(t, s, "hysteria")
	ca := autoCertPEM(t, s)
	pollGeneration := s.desiredGen

	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "remove", DeltaUsers: oldUsers[:1]})
	if len(s.lastUsers) != 1 || s.desiredGen == pollGeneration {
		t.Fatal("WS revocation was not processed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_, closeFn, err := hysteria2Dial(ctx, fmt.Sprintf("127.0.0.1:%d", port), testUUID, ca, target)
	if err == nil {
		closeFn()
		cancel()
		t.Fatal("setup: WS revocation did not initially block the credential")
	}
	cancel()

	// An older poll can have a 304 config response (nil config) together with
	// the full user response that was read before the concurrent WS revocation.
	s.applyPullResult(context.Background(), pullResult{users: oldUsers, userHash: computeUserHash(oldUsers), gen: pollGeneration})
	ctx, cancel = context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	conn, closeFn, err := hysteria2Dial(ctx, fmt.Sprintf("127.0.0.1:%d", port), testUUID, ca, target)
	if err == nil {
		defer closeFn()
		body := httpsGetThrough(t, conn, target)
		t.Fatalf("stale REST user response restored a revoked credential: NEW QUIC authentication and HTTPS succeeded: %q", body)
	}
}
