//go:build with_quic && with_utls

package service

// Real-kernel regression tests. They run the production sing-box and xray
// kernels in-process, obtain certificates through the real certificate
// manager and talk to the listeners with real protocol clients (a Hysteria2
// QUIC client, a REALITY+VLESS client, plain VLESS), never with a TCP ping.
//
// The file needs the with_quic and with_utls build tags, which are part of the
// production build; `make test` passes them, so a build without them is a
// build that cannot run Hysteria or REALITY in production either.

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	singtls "github.com/sagernet/sing-box/common/tls"
	singlog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing-vmess/vless"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/cedar2025/xboard-node/internal/cert"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/limiter"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/tracker"
)

const (
	testUUID      = "8f1e9c1a-2b3c-4d5e-8f9a-0b1c2d3e4f5a"
	testOtherUUID = "1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e"
	realitySNI    = "www.example.com"
	hysteriaSNI   = "hy.local.test"
)

func newRealService(t *testing.T) *Service {
	t.Helper()
	cfg := testConfig(t)
	src := &fakeSource{}
	sharedLimiter := limiter.New()
	s := &Service{
		cfg:             cfg,
		source:          src,
		sink:            src,
		preferredKernel: model.KernelSingbox,
		newKernel:       defaultKernelFactory,
		kernels:         make(map[string]kernel.Kernel),
		tracker:         tracker.New(),
		limiter:         sharedLimiter,
		speedTracker:    limiter.NewSpeedTracker(sharedLimiter),
		cert:            cert.NewManager(cfg.Cert),
		retryDelayFn:    func(int) time.Duration { return time.Millisecond },
		wsEvents:        make(chan controlplane.Event, 16),
		wsStatusCh:      make(chan controlplane.StatusChange, 4),
		pullResults:     make(chan pullResult, 1),
	}
	t.Cleanup(s.stopKernels)
	t.Cleanup(s.stopRetryTimer)
	return s
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// loopbackDirect lets the kernel reach the test target on loopback; the
// default private-range block would otherwise swallow it. It is a structured
// panel rule, so it compiles for both kernels.
func loopbackDirect() []model.CustomRouteRule {
	return []model.CustomRouteRule{{
		Name:   "test-loopback",
		Match:  model.RouteMatch{IPCIDRs: []string{"127.0.0.0/8", "::1/128"}},
		Action: model.RouteAction{Type: "direct"},
	}}
}

func realHysteria2Spec(port int) *model.NodeSpec {
	return &model.NodeSpec{
		Protocol: "hysteria", Version: 2, ServerPort: port,
		Host: hysteriaSNI, ServerName: hysteriaSNI,
		TLSSettings:      map[string]any{"server_name": hysteriaSNI},
		CustomRouteRules: loopbackDirect(),
	}
}

type realityKeys struct{ private, public string }

func newRealityKeys(t *testing.T) realityKeys {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return realityKeys{
		private: base64.RawURLEncoding.EncodeToString(priv.Bytes()),
		public:  base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()),
	}
}

func realRealitySpec(port int, keys realityKeys, dest string) *model.NodeSpec {
	return &model.NodeSpec{
		Protocol: "vless", ServerPort: port, Network: "tcp", TLS: 2,
		TLSSettings: map[string]any{
			"private_key": keys.private,
			"server_name": realitySNI,
			"short_id":    "0123456789abcdef",
			"dest":        dest,
		},
		CustomRouteRules: loopbackDirect(),
	}
}

func realPlainVLESSSpec(port int) *model.NodeSpec {
	return &model.NodeSpec{Protocol: "vless", ServerPort: port, Network: "tcp", CustomRouteRules: loopbackDirect()}
}

func realXHTTPSpec(port int) *model.NodeSpec {
	return &model.NodeSpec{
		Protocol: "vless", ServerPort: port, Network: "xhttp",
		NetworkSettings:  map[string]any{"path": "/xhttp-test", "mode": "auto"},
		CustomRouteRules: loopbackDirect(),
	}
}

func nopLogger() singlog.ContextLogger { return singlog.NewNOPFactory().NewLogger("test") }

// localHTTPSTarget is the origin every proxied request is sent to.
func localHTTPSTarget(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello from "+r.Host)
	}))
	t.Cleanup(srv.Close)
	return srv, strings.TrimPrefix(srv.URL, "https://")
}

// httpsGetThrough performs one HTTPS request to target over an already
// proxied connection and returns the body.
func httpsGetThrough(t *testing.T, conn net.Conn, targetHostPort string) string {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // local httptest origin
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("origin TLS handshake through proxy: %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://"+targetHostPort+"/probe", nil)
	req.Host = targetHostPort
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	return string(body)
}

// hysteria2Dial completes a real Hysteria2 (QUIC + HTTP/3 auth) handshake
// against serverAddr, verifying the server certificate with caPEM, and opens
// a proxied TCP stream to dest.
func hysteria2Dial(ctx context.Context, serverAddr, password string, caPEM []byte, dest string) (net.Conn, func(), error) {
	tlsCfg, err := singtls.NewClient(ctx, nopLogger(), hysteriaSNI, option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  hysteriaSNI,
		Certificate: []string{string(caPEM)},
		ALPN:        []string{"h3"},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("tls client: %w", err)
	}
	client, err := hysteria2.NewClient(hysteria2.ClientOptions{
		Context:       ctx,
		Dialer:        N.SystemDialer,
		Logger:        nopLogger(),
		ServerAddress: M.ParseSocksaddr(serverAddr),
		Password:      password,
		TLSConfig:     tlsCfg,
		UDPDisabled:   true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("hysteria2 client: %w", err)
	}
	conn, err := client.DialConn(ctx, M.ParseSocksaddr(dest))
	if err != nil {
		_ = client.CloseWithError(err)
		return nil, nil, err
	}
	return conn, func() { conn.Close(); _ = client.CloseWithError(nil) }, nil
}

// realityDial completes a real REALITY handshake (uTLS client hello with the
// server's public key and short id) and a VLESS request over it.
func realityDial(ctx context.Context, serverAddr string, keys realityKeys, uuid, dest string) (net.Conn, error) {
	tcp, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := singtls.NewClient(ctx, nopLogger(), realitySNI, option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: realitySNI,
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		Reality:    &option.OutboundRealityOptions{Enabled: true, PublicKey: keys.public, ShortID: "0123456789abcdef"},
	})
	if err != nil {
		tcp.Close()
		return nil, fmt.Errorf("reality client config: %w", err)
	}
	tlsConn, err := singtls.ClientHandshake(ctx, tcp, tlsCfg)
	if err != nil {
		tcp.Close()
		return nil, fmt.Errorf("reality handshake: %w", err)
	}
	client, err := vless.NewClient(uuid, "", nopLogger())
	if err != nil {
		tlsConn.Close()
		return nil, err
	}
	conn, err := client.DialConn(tlsConn, M.ParseSocksaddr(dest))
	if err != nil {
		tlsConn.Close()
		return nil, err
	}
	return conn, nil
}

// plainVLESSDial performs a VLESS request over plain TCP.
func plainVLESSDial(ctx context.Context, serverAddr, uuid, dest string) (net.Conn, error) {
	tcp, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, err
	}
	client, err := vless.NewClient(uuid, "", nopLogger())
	if err != nil {
		tcp.Close()
		return nil, err
	}
	conn, err := client.DialConn(tcp, M.ParseSocksaddr(dest))
	if err != nil {
		tcp.Close()
		return nil, err
	}
	return conn, nil
}

func tcpRefused(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err == nil {
		conn.Close()
		t.Fatalf("%s still accepts TCP connections", addr)
	}
}

func autoCertPEM(t *testing.T, s *Service) []byte {
	t.Helper()
	pemBytes, err := os.ReadFile(filepath.Join(autoCertificateDir(s.cfg), "self-signed", "cert.pem"))
	if err != nil {
		t.Fatalf("automatic certificate not persisted: %v", err)
	}
	return pemBytes
}

func applied(t *testing.T, s *Service, protocol string) {
	t.Helper()
	if !s.appliedState.Running || s.appliedState.Config == nil || s.appliedState.Config.Protocol != protocol || s.appliedState.ConfigHash != s.lastConfigHash {
		t.Fatalf("target %s not applied: applied=%+v stage=%s err=%v", protocol, s.appliedState, s.lastApplyStage, s.lastApplyErr)
	}
}

func assertHysteria2Works(t *testing.T, s *Service, port int, targetHostPort string) {
	t.Helper()
	caPEM := autoCertPEM(t, s)
	for _, host := range []string{"127.0.0.1", "[::1]"} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, closeFn, err := hysteria2Dial(ctx, fmt.Sprintf("%s:%d", host, port), testUUID, caPEM, targetHostPort)
		if err != nil {
			cancel()
			if host == "[::1]" && strings.Contains(err.Error(), "cannot assign requested address") {
				t.Logf("IPv6 loopback unavailable in this environment: %v", err)
				continue
			}
			t.Fatalf("hysteria2 handshake via %s failed: %v", host, err)
		}
		body := httpsGetThrough(t, conn, targetHostPort)
		closeFn()
		cancel()
		if !strings.HasPrefix(body, "hello from") {
			t.Fatalf("unexpected body via %s: %q", host, body)
		}
	}
}

func assertHysteria2Down(t *testing.T, port int, caPEM []byte, targetHostPort string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, closeFn, err := hysteria2Dial(ctx, fmt.Sprintf("127.0.0.1:%d", port), testUUID, caPEM, targetHostPort)
	if err == nil {
		closeFn()
		_ = conn
		t.Fatalf("hysteria2 on port %d still answers", port)
	}
}

func assertRealityWorks(t *testing.T, port int, keys realityKeys, targetHostPort string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := realityDial(ctx, fmt.Sprintf("127.0.0.1:%d", port), keys, testUUID, targetHostPort)
	if err != nil {
		t.Fatalf("reality handshake failed: %v", err)
	}
	defer conn.Close()
	if body := httpsGetThrough(t, conn, targetHostPort); !strings.HasPrefix(body, "hello from") {
		t.Fatalf("unexpected body: %q", body)
	}
}

// ─── Scenarios ──────────────────────────────────────────────────────────────

// Incident replay: a Hysteria2 node with no certificate configuration. The
// node must come up on its own with an automatic self-signed certificate,
// listen on UDP only, and complete a real QUIC handshake on both loopback
// families for an authorised user.
func TestRealHysteria2StartsWithAutomaticCertificate(t *testing.T) {
	s := newRealService(t)
	_, target := localHTTPSTarget(t)
	port := freePort(t)

	spec := realHysteria2Spec(port)
	s.setDesiredConfig(spec, computeConfigHash(spec))
	s.setDesiredUsers([]model.UserSpec{{ID: 1, UUID: testUUID}})
	s.reconcile(context.Background())
	applied(t, s, "hysteria")
	if s.appliedState.CertSource != certSourceAuto || s.appliedState.Kernel != model.KernelSingbox {
		t.Fatalf("applied = %+v", s.appliedState)
	}

	assertHysteria2Works(t, s, port, target)
	tcpRefused(t, fmt.Sprintf("127.0.0.1:%d", port))

	// A credential the panel never issued must be refused by the server.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if conn, closeFn, err := hysteria2Dial(ctx, fmt.Sprintf("127.0.0.1:%d", port), testOtherUUID, autoCertPEM(t, s), target); err == nil {
		closeFn()
		_ = conn
		t.Fatal("unauthorised password completed a hysteria2 handshake")
	}

	// A restart-like second apply reuses the same certificate.
	before := string(autoCertPEM(t, s))
	s.appliedState.Running = false
	s.activeKernel().Stop()
	s.reconcile(context.Background())
	applied(t, s, "hysteria")
	if string(autoCertPEM(t, s)) != before {
		t.Fatal("restart rotated the automatic certificate")
	}
	assertHysteria2Works(t, s, port, target)
}

// The incident's rebinding on one node id: VLESS REALITY → Hysteria2 through
// the WS path, then back to REALITY through the REST path, on the same port
// number. Each step is verified with a real client and the old listener must
// be gone.
func TestRealRealityAndHysteria2SwitchBothWaysOnSameNode(t *testing.T) {
	s := newRealService(t)
	targetSrv, target := localHTTPSTarget(t)
	keys := newRealityKeys(t)
	port := freePort(t)
	users := []model.UserSpec{{ID: 1, UUID: testUUID}}

	reality := realRealitySpec(port, keys, strings.TrimPrefix(targetSrv.URL, "https://"))
	s.setDesiredConfig(reality, computeConfigHash(reality))
	s.setDesiredUsers(users)
	s.reconcile(context.Background())
	applied(t, s, "vless")
	if s.appliedState.CertMode != "reality" || s.appliedState.TLS.HasCert() {
		t.Fatalf("reality must not carry a certificate: %+v", s.appliedState)
	}
	assertRealityWorks(t, port, keys, target)

	// WS push: same node id, protocol switch to Hysteria2 on the same port.
	hy := realHysteria2Spec(port)
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: hy})
	applied(t, s, "hysteria")
	assertHysteria2Works(t, s, port, target)
	tcpRefused(t, fmt.Sprintf("127.0.0.1:%d", port))

	// REST result: back to REALITY on the same port; the QUIC listener must
	// stop answering and the certificate flow must not block the switch.
	caPEM := autoCertPEM(t, s)
	s.applyPullResult(context.Background(), pullResult{config: reality, configHash: computeConfigHash(reality), users: users, userHash: computeUserHash(users), gen: s.desiredGen})
	applied(t, s, "vless")
	assertRealityWorks(t, port, keys, target)
	assertHysteria2Down(t, port, caPEM, target)
}

// Cross-kernel switch: a plain VLESS node on sing-box moves to xhttp, which
// only xray serves, and back. The previous kernel's listener must be closed
// before the next one binds the same port, and the return trip must land on
// the preferred kernel again.
func TestRealCrossKernelSwitchToXHTTPAndBack(t *testing.T) {
	s := newRealService(t)
	_, target := localHTTPSTarget(t)
	port := freePort(t)
	users := []model.UserSpec{{ID: 1, UUID: testUUID}}
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	plain := realPlainVLESSSpec(port)
	s.setDesiredConfig(plain, computeConfigHash(plain))
	s.setDesiredUsers(users)
	s.reconcile(context.Background())
	applied(t, s, "vless")
	if s.appliedState.Kernel != model.KernelSingbox {
		t.Fatalf("expected sing-box, got %s", s.appliedState.Kernel)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	conn, err := plainVLESSDial(ctx, addr, testUUID, target)
	if err != nil {
		t.Fatalf("plain vless handshake: %v", err)
	}
	httpsGetThrough(t, conn, target)
	conn.Close()
	cancel()

	xhttp := realXHTTPSpec(port)
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: xhttp})
	applied(t, s, "vless")
	if s.appliedState.Kernel != model.KernelXray {
		t.Fatalf("xhttp must run on xray, got %s (err %v)", s.appliedState.Kernel, s.lastApplyErr)
	}
	if k := s.kernels[model.KernelSingbox]; k != nil && k.IsRunning() {
		t.Fatal("sing-box still running after the switch to xray")
	}
	// xray's xhttp handler owns the port now: a request outside the
	// configured path is answered with 404 by xray itself. Every probe uses
	// a fresh TCP connection so a pooled keep-alive connection can never
	// stand in for a listener.
	httpClient := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := httpClient.Get("http://" + addr + "/not-the-path")
	if err != nil {
		t.Fatalf("xhttp listener probe: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("xhttp probe status = %d, want 404", resp.StatusCode)
	}

	// Back to a target the preferred kernel can serve.
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: realPlainVLESSSpec(port)})
	applied(t, s, "vless")
	if s.appliedState.Kernel != model.KernelSingbox {
		t.Fatalf("return trip must use the preferred kernel, got %s", s.appliedState.Kernel)
	}
	if k := s.kernels[model.KernelXray]; k != nil && k.IsRunning() {
		t.Fatal("xray still running after switching back")
	}
	if resp, err := httpClient.Get("http://" + addr + "/not-the-path"); err == nil {
		resp.Body.Close()
		t.Fatalf("xray's HTTP handler still answers after the switch back (status %d)", resp.StatusCode)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err = plainVLESSDial(ctx, addr, testUUID, target)
	if err != nil {
		t.Fatalf("plain vless handshake after return: %v", err)
	}
	httpsGetThrough(t, conn, target)
	conn.Close()
}

// A target no kernel can run is rejected before anything is touched: the
// running Hysteria2 node keeps answering, the error is recorded, and the next
// valid target applies without a manual restart.
func TestRealUnsupportedTargetKeepsPreviousNodeServing(t *testing.T) {
	s := newRealService(t)
	_, target := localHTTPSTarget(t)
	port := freePort(t)

	hy := realHysteria2Spec(port)
	s.setDesiredConfig(hy, computeConfigHash(hy))
	s.setDesiredUsers([]model.UserSpec{{ID: 1, UUID: testUUID}})
	s.reconcile(context.Background())
	applied(t, s, "hysteria")

	bad := &model.NodeSpec{Protocol: "vmess", ServerPort: port, Network: "xhttp", Multiplex: &model.MultiplexConfig{Enabled: true}}
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: bad})
	if s.lastApplyStage != "prepare" || s.lastApplyErr == nil || !strings.Contains(s.lastApplyErr.Error(), "no kernel can run") {
		t.Fatalf("stage=%s err=%v", s.lastApplyStage, s.lastApplyErr)
	}
	assertHysteria2Works(t, s, port, target)

	next := freePort(t)
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: realHysteria2Spec(next)})
	applied(t, s, "hysteria")
	assertHysteria2Works(t, s, next, target)
}

// A transient bind failure (the port is held by someone else) is retried and
// recovers on its own once the port is free.
func TestRealPortBusyRecoversWithoutManualRestart(t *testing.T) {
	s := newRealService(t)
	_, target := localHTTPSTarget(t)
	port := freePort(t)
	// Hold the wildcard address: the kernel listens on "::".
	holder, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatal(err)
	}

	plain := realPlainVLESSSpec(port)
	s.setDesiredConfig(plain, computeConfigHash(plain))
	s.setDesiredUsers([]model.UserSpec{{ID: 1, UUID: testUUID}})
	s.reconcile(context.Background())
	if s.appliedState.Running || s.lastApplyStage != "apply" || !s.retryPending {
		t.Fatalf("expected a retried apply failure: applied=%+v stage=%s err=%v", s.appliedState, s.lastApplyStage, s.lastApplyErr)
	}
	holder.Close()

	s.reconcile(context.Background())
	applied(t, s, "vless")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := plainVLESSDial(ctx, fmt.Sprintf("127.0.0.1:%d", port), testUUID, target)
	if err != nil {
		t.Fatalf("handshake after recovery: %v", err)
	}
	httpsGetThrough(t, conn, target)
	conn.Close()
}

// The user hot path on a real Hysteria2 node: a user added by delta can
// connect and a revoked user cannot; Hysteria2 replaces its inbound safely.
func TestRealHysteria2UserDeltaHotSwap(t *testing.T) {
	s := newRealService(t)
	_, target := localHTTPSTarget(t)
	port := freePort(t)
	hy := realHysteria2Spec(port)
	s.setDesiredConfig(hy, computeConfigHash(hy))
	s.setDesiredUsers([]model.UserSpec{{ID: 1, UUID: testUUID}})
	s.reconcile(context.Background())
	applied(t, s, "hysteria")
	caPEM := autoCertPEM(t, s)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "add", DeltaUsers: []model.UserSpec{{ID: 2, UUID: testOtherUUID}}})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	conn, closeFn, err := hysteria2Dial(ctx, addr, testOtherUUID, caPEM, target)
	if err != nil {
		t.Fatalf("added user cannot connect: %v", err)
	}
	httpsGetThrough(t, conn, target)
	closeFn()
	cancel()

	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "remove", DeltaUsers: []model.UserSpec{{ID: 1, UUID: testUUID}}})
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if conn, closeFn, err := hysteria2Dial(ctx, addr, testUUID, caPEM, target); err == nil {
		closeFn()
		_ = conn
		t.Fatal("revoked user still connects")
	}
	if s.appliedState.UserHash != s.lastUserHash {
		t.Fatal("applied users must follow the delta")
	}
}
