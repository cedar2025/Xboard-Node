package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/cert"
	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/limiter"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/tracker"
	"golang.org/x/time/rate"
)

// fakeKernel is a controllable kernel. It records every lifecycle call so a
// test can assert what the service did, and lets a test inject failures at
// each stage.
type fakeKernel struct {
	mu      sync.Mutex
	name    string
	running bool

	validateErr error
	startErr    error
	reloadErr   error
	updateErr   error
	addErr      error
	removeErr   error

	startCalls    int
	reloadCalls   int
	stopCalls     int
	validateCalls int
	updateCalls   int
	addCalls      int
	removeCalls   int

	// startFailures fails the first N Start calls, then succeeds.
	startFailures int

	lastStart  *model.NodeSpec
	lastReload *model.NodeSpec
	lastUsers  []model.UserSpec
	lastTLS    kernel.TLSCert

	onUpdateUsers func([]model.UserSpec)
	onAddUsers    func([]model.UserSpec)
	onRemoveUsers func([]model.UserSpec)
	onStart       func(*model.NodeSpec, []model.UserSpec)

	speedLimitFunc  func(string) *rate.Limiter
	deviceLimitFunc func(string) (int, bool)
}

func (f *fakeKernel) Name() string { return f.name }
func (f *fakeKernel) Protocols() []string {
	return []string{"vmess", "vless", "trojan", "shadowsocks", "hysteria", "tuic", "naive", "socks", "http", "anytls", "mieru"}
}
func (f *fakeKernel) Capabilities() kernel.Capabilities { return kernel.Capabilities{} }
func (f *fakeKernel) Validate(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.validateCalls++
	return f.validateErr
}
func (f *fakeKernel) Start(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	f.mu.Lock()
	f.startCalls++
	f.lastStart = nodeConfig
	f.lastUsers = model.CloneUserSpecs(users)
	f.lastTLS = tls
	onStart := f.onStart
	if f.startFailures > 0 {
		f.startFailures--
		f.mu.Unlock()
		return errors.New("simulated start failure")
	}
	if f.startErr != nil {
		err := f.startErr
		f.mu.Unlock()
		return err
	}
	f.running = true
	f.mu.Unlock()
	if onStart != nil {
		onStart(nodeConfig, users)
	}
	return nil
}
func (f *fakeKernel) Stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopCalls++
	f.running = false
}
func (f *fakeKernel) IsRunning() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running
}
func (f *fakeKernel) Reload(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reloadCalls++
	if f.reloadErr != nil {
		return f.reloadErr
	}
	f.lastReload = nodeConfig
	f.lastUsers = model.CloneUserSpecs(users)
	f.lastTLS = tls
	return nil
}
func (f *fakeKernel) AddUsers(users []model.UserSpec) (int, error) {
	f.mu.Lock()
	f.addCalls++
	cb := f.onAddUsers
	f.mu.Unlock()
	if cb != nil {
		cb(users)
	}
	if f.addErr != nil {
		return 0, f.addErr
	}
	return len(users), nil
}
func (f *fakeKernel) RemoveUsers(users []model.UserSpec) (int, error) {
	f.mu.Lock()
	f.removeCalls++
	cb := f.onRemoveUsers
	f.mu.Unlock()
	if cb != nil {
		cb(users)
	}
	if f.removeErr != nil {
		return 0, f.removeErr
	}
	return len(users), nil
}
func (f *fakeKernel) UpdateUsers(users []model.UserSpec) (int, int, error) {
	f.mu.Lock()
	f.updateCalls++
	cb := f.onUpdateUsers
	f.mu.Unlock()
	if cb != nil {
		cb(users)
	}
	if f.updateErr != nil {
		return 0, 0, f.updateErr
	}
	f.mu.Lock()
	f.lastUsers = model.CloneUserSpecs(users)
	f.mu.Unlock()
	return len(users), 0, nil
}
func (f *fakeKernel) GetUserTraffic(ctx context.Context) (map[int][2]int64, map[int]map[string]bool, int, error) {
	return nil, nil, 0, nil
}
func (f *fakeKernel) CloseConnection(ctx context.Context, connID string) error    { return nil }
func (f *fakeKernel) CloseUserConnections(ctx context.Context, uuid string) error { return nil }
func (f *fakeKernel) SetSpeedLimitFunc(fn func(uuid string) *rate.Limiter)        { f.speedLimitFunc = fn }
func (f *fakeKernel) SetDeviceLimitFunc(fn func(uuid string) (int, bool))         { f.deviceLimitFunc = fn }
func (f *fakeKernel) UpdateGlobalDevices(users map[int][]string)                  {}
func (f *fakeKernel) ClearGlobalDevices()                                         {}

func (f *fakeKernel) counts() (start, reload, stop int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.startCalls, f.reloadCalls, f.stopCalls
}

func (f *fakeKernel) startedWith() (*model.NodeSpec, []model.UserSpec) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastStart, model.CloneUserSpecs(f.lastUsers)
}

// fakeSource is an in-memory control plane.
type fakeSource struct {
	mu          sync.Mutex
	initialErrs int
	bootstrap   controlplane.Bootstrap
	snapshot    controlplane.Snapshot
	pollErr     error
	polls       int
	resets      int
	initials    int
}

func (f *fakeSource) Initial(ctx context.Context, _ func() map[string]interface{}, _ chan<- controlplane.Event, _ chan<- controlplane.StatusChange) (controlplane.Bootstrap, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.initials++
	if f.initialErrs > 0 {
		f.initialErrs--
		return controlplane.Bootstrap{}, errors.New("panel unavailable (502)")
	}
	return f.bootstrap, nil
}
func (f *fakeSource) Poll(ctx context.Context) (controlplane.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.polls++
	if f.pollErr != nil {
		return controlplane.Snapshot{}, f.pollErr
	}
	return f.snapshot, nil
}
func (f *fakeSource) Discover(ctx context.Context, _ func() map[string]interface{}, _ chan<- controlplane.Event, _ chan<- controlplane.StatusChange) (controlplane.PushClient, error) {
	return nil, nil
}
func (f *fakeSource) Metrics() controlplane.APIMetrics { return controlplane.APIMetrics{} }
func (f *fakeSource) SupportsPolling() bool            { return true }
func (f *fakeSource) SupportsDiscovery() bool          { return false }
func (f *fakeSource) ResetCache() {
	f.mu.Lock()
	f.resets++
	f.mu.Unlock()
}
func (f *fakeSource) Report(payload controlplane.ReportPayload) error                      { return nil }
func (f *fakeSource) ReportDevices(push controlplane.PushClient, devices map[int][]string) {}
func (f *fakeSource) SupportsReporting() bool                                              { return false }
func (f *fakeSource) SupportsDeviceReports() bool                                          { return false }

// testKernels wires one fake kernel per kernel type into a service.
type testKernels struct {
	singbox *fakeKernel
	xray    *fakeKernel
}

func newTestKernels() *testKernels {
	return &testKernels{
		singbox: &fakeKernel{name: model.KernelSingbox},
		xray:    &fakeKernel{name: model.KernelXray},
	}
}

func (tk *testKernels) factory(kcfg config.KernelConfig) kernel.Kernel {
	switch kcfg.Type {
	case model.KernelXray:
		return tk.xray
	default:
		return tk.singbox
	}
}

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	return &config.Config{
		InstanceID: "svc-test",
		Panel:      config.PanelConfig{URL: "https://panel.test", NodeID: 5, Token: "t"},
		Kernel:     config.KernelConfig{Type: model.KernelSingbox, ConfigDir: dir, LogLevel: "warn"},
		Cert:       config.CertConfig{CertDir: dir + "/certs", HTTPPort: 80},
		Node:       config.NodeConfig{TrackInterval: 60, DeviceReportInterval: 60, PushInterval: 60, PullInterval: 60},
		WS:         config.WSConfig{DiscoveryInterval: 300},
	}
}

func newTestService(t *testing.T, tk *testKernels) *Service {
	t.Helper()
	cfg := testConfig(t)
	src := &fakeSource{}
	sharedLimiter := limiter.New()
	s := &Service{
		cfg:             cfg,
		source:          src,
		sink:            src,
		preferredKernel: model.KernelSingbox,
		newKernel:       tk.factory,
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

func vlessSpec(port int) *model.NodeSpec {
	return &model.NodeSpec{Protocol: "vless", ServerPort: port, Network: "tcp"}
}

func hysteria2Spec(port int) *model.NodeSpec {
	return &model.NodeSpec{Protocol: "hysteria", Version: 2, ServerPort: port, Host: "hy.example.test", ServerName: "hy.example.test"}
}

func realitySpec(port int) *model.NodeSpec {
	return &model.NodeSpec{Protocol: "vless", ServerPort: port, Network: "tcp", TLS: 2, Flow: "xtls-rprx-vision",
		TLSSettings: map[string]any{"private_key": "priv", "server_name": "www.example.com", "short_id": "ab"}}
}

var (
	userA = model.UserSpec{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444", SpeedLimit: 4}
	userB = model.UserSpec{ID: 2, UUID: "bbbbbbbb-5555-6666-7777-888888888888", SpeedLimit: 8}
)

// seed puts the service in the state "the panel authorised spec/users and the
// kernel is serving them".
func seed(t *testing.T, s *Service, spec *model.NodeSpec, users []model.UserSpec) {
	t.Helper()
	s.setDesiredConfig(spec, computeConfigHash(spec))
	s.setDesiredUsers(users)
	s.reconcile(context.Background())
	if !s.appliedState.Running || s.appliedState.ConfigHash != s.lastConfigHash {
		t.Fatalf("seed failed: applied=%+v err=%v", s.appliedState, s.lastApplyErr)
	}
}

func TestApplyUserUpdatePreparesLimiterBeforeKernelUpdate(t *testing.T) {
	tk := newTestKernels()
	s := newTestService(t, tk)
	seed(t, s, vlessSpec(443), []model.UserSpec{userA})

	newUsers := []model.UserSpec{userB}
	tk.singbox.onUpdateUsers = func(users []model.UserSpec) {
		if len(users) != 1 || users[0].UUID != userB.UUID {
			t.Fatalf("unexpected users passed to UpdateUsers: %#v", users)
		}
		if got := tk.singbox.speedLimitFunc(userB.UUID); got == nil {
			t.Fatal("expected new user's limiter to be visible before kernel UpdateUsers")
		}
	}

	s.applyUserUpdate(context.Background(), newUsers, computeUserHash(newUsers))

	if got := tk.singbox.updateCalls; got != 1 {
		t.Fatalf("UpdateUsers call count = %d, want 1", got)
	}
	if len(s.lastUsers) != 1 || s.lastUsers[0].UUID != userB.UUID {
		t.Fatalf("lastUsers = %#v, want new users", s.lastUsers)
	}
	if s.appliedState.UserHash != s.lastUserHash {
		t.Fatal("applied user hash must follow a successful hot update")
	}
	if s.speedTracker.GetLimiter(userB.UUID) == nil {
		t.Fatal("expected limiter for new user after successful update")
	}
	if start, _, _ := tk.singbox.counts(); start != 1 {
		t.Fatalf("a user-only change must not restart the kernel, starts = %d", start)
	}
}

// A failed authorization update stops the unsafe listener and retains the
// desired user set for a bounded retry.
func TestApplyUserUpdateKeepsDesiredAndRetriesWhenKernelFails(t *testing.T) {
	tk := newTestKernels()
	s := newTestService(t, tk)
	seed(t, s, vlessSpec(443), []model.UserSpec{userA})

	tk.singbox.updateErr = errors.New("update failed")
	tk.singbox.reloadErr = errors.New("reload failed")
	tk.singbox.startErr = errors.New("restart failed")
	newUsers := []model.UserSpec{userB}
	s.applyUserUpdate(context.Background(), newUsers, computeUserHash(newUsers))

	if start, _, _ := tk.singbox.counts(); start != 1 {
		t.Fatalf("unexpected start before the retry: %d", start)
	}
	if len(s.lastUsers) != 1 || s.lastUsers[0].UUID != userB.UUID {
		t.Fatalf("desired users must stay the new set, got %#v", s.lastUsers)
	}
	if s.kernelRunning() || s.appliedState.Running || len(s.appliedState.Users) != 0 {
		t.Fatal("failed authorization update must stop serving the revoked user")
	}
	if !s.retryPending {
		t.Fatal("a retry must be pending after a failed user update")
	}
	if s.speedTracker.GetLimiter(userA.UUID) != nil {
		t.Fatal("revoked user's limiter must not be restored")
	}
	if s.speedTracker.GetLimiter(userB.UUID) != nil {
		t.Fatal("expected the unapplied user's limiter to be removed")
	}

	// The kernel recovers: the pending retry applies the desired users.
	tk.singbox.updateErr = nil
	tk.singbox.reloadErr = nil
	tk.singbox.startErr = nil
	s.reconcile(context.Background())
	if s.appliedState.UserHash != s.lastUserHash || s.retryPending {
		t.Fatalf("retry did not apply the desired users: applied=%+v pending=%v", s.appliedState, s.retryPending)
	}
	if s.speedTracker.GetLimiter(userB.UUID) == nil {
		t.Fatal("expected limiter for the newly applied user")
	}
}

func TestApplyUserDeltaAddPreparesLimiterBeforeKernelUpdate(t *testing.T) {
	tk := newTestKernels()
	s := newTestService(t, tk)
	seed(t, s, vlessSpec(443), []model.UserSpec{userA})

	tk.singbox.onAddUsers = func(users []model.UserSpec) {
		if len(users) != 1 || users[0].UUID != userB.UUID {
			t.Fatalf("unexpected users passed to AddUsers: %#v", users)
		}
		if got := tk.singbox.speedLimitFunc(userB.UUID); got == nil {
			t.Fatal("expected delta user's limiter to be visible before kernel AddUsers")
		}
	}

	s.applyUserDelta(context.Background(), "add", []model.UserSpec{userB})

	if got := tk.singbox.addCalls; got != 1 {
		t.Fatalf("AddUsers call count = %d, want 1", got)
	}
	if len(s.lastUsers) != 2 || len(s.appliedState.Users) != 2 {
		t.Fatalf("desired=%d applied=%d users, want 2/2", len(s.lastUsers), len(s.appliedState.Users))
	}
	if s.speedTracker.GetLimiter(userB.UUID) == nil {
		t.Fatal("expected limiter for delta-added user after successful update")
	}
}

func TestApplyUserDeltaRotatedUUIDRemovesStaleCredentialFirst(t *testing.T) {
	tk := newTestKernels()
	s := newTestService(t, tk)
	seed(t, s, vlessSpec(443), []model.UserSpec{userA})

	var removed []model.UserSpec
	tk.singbox.onRemoveUsers = func(users []model.UserSpec) { removed = append(removed, users...) }
	rotated := model.UserSpec{ID: userA.ID, UUID: "cccccccc-0000-0000-0000-000000000000"}
	s.applyUserDelta(context.Background(), "add", []model.UserSpec{rotated})
	if len(removed) != 1 || removed[0].UUID != userA.UUID {
		t.Fatalf("stale credential must be removed before the rotated one is added, removed=%v", removed)
	}
	if len(s.appliedState.Users) != 1 || s.appliedState.Users[0].UUID != rotated.UUID {
		t.Fatalf("applied users = %v", s.appliedState.Users)
	}
}

// Zero users at bootstrap must not wedge the node: the first user set that
// arrives on any path starts the kernel.
func TestZeroUsersThenUsersStartsKernelOnEveryPath(t *testing.T) {
	paths := map[string]func(s *Service){
		"full sync": func(s *Service) {
			s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUsers, Users: []model.UserSpec{userA}})
		},
		"delta add": func(s *Service) {
			s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "add", DeltaUsers: []model.UserSpec{userA}})
		},
		"rest poll": func(s *Service) {
			s.applyPullResult(context.Background(), pullResult{users: []model.UserSpec{userA}, userHash: computeUserHash([]model.UserSpec{userA}), gen: s.desiredGen})
		},
	}
	for name, deliver := range paths {
		t.Run(name, func(t *testing.T) {
			tk := newTestKernels()
			s := newTestService(t, tk)
			spec := vlessSpec(443)
			s.setDesiredConfig(spec, computeConfigHash(spec))
			s.setDesiredUsers(nil)
			s.reconcile(context.Background())
			if tk.singbox.IsRunning() {
				t.Fatal("kernel must not start without users")
			}

			deliver(s)

			if !tk.singbox.IsRunning() || !s.appliedState.Running {
				t.Fatalf("kernel must start when the first user arrives (applied=%+v, err=%v)", s.appliedState, s.lastApplyErr)
			}
			if _, users := tk.singbox.startedWith(); len(users) != 1 || users[0].UUID != userA.UUID {
				t.Fatalf("kernel started with %v", users)
			}
		})
	}
}

func TestUsersRevokedToZeroStopsKernelAndKeepsSyncing(t *testing.T) {
	tk := newTestKernels()
	s := newTestService(t, tk)
	seed(t, s, vlessSpec(443), []model.UserSpec{userA})

	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUserDelta, DeltaAction: "remove", DeltaUsers: []model.UserSpec{userA}})
	if tk.singbox.IsRunning() || s.appliedState.Running {
		t.Fatal("kernel must stop when the last user is revoked")
	}
	if s.speedTracker.GetLimiter(userA.UUID) != nil {
		t.Fatal("revoked user's limiter must be gone")
	}

	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUsers, Users: []model.UserSpec{userB}})
	if !tk.singbox.IsRunning() {
		t.Fatal("kernel must come back with the next user set")
	}
}

func TestSameKernelProtocolSwitchReloadsInPlace(t *testing.T) {
	tk := newTestKernels()
	s := newTestService(t, tk)
	seed(t, s, realitySpec(443), []model.UserSpec{userA})

	target := hysteria2Spec(54433)
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: target})

	start, reload, _ := tk.singbox.counts()
	if start != 1 || reload != 1 {
		t.Fatalf("starts=%d reloads=%d, want 1/1 (in-place rebuild)", start, reload)
	}
	if s.appliedState.Config.Protocol != "hysteria" || s.appliedState.ConfigHash != computeConfigHash(target) {
		t.Fatalf("applied = %+v", s.appliedState)
	}
	if s.appliedState.CertSource != certSourceAuto || !s.appliedState.TLS.HasCert() {
		t.Fatalf("hysteria without cert config must get an automatic self-signed certificate, got %+v", s.appliedState)
	}
	if !tk.singbox.lastTLS.HasCert() {
		t.Fatal("the kernel must have received the certificate")
	}
}

func TestTLSToNoTLSSwitchDoesNotPrepareCertificate(t *testing.T) {
	tk := newTestKernels()
	s := newTestService(t, tk)
	seed(t, s, hysteria2Spec(54433), []model.UserSpec{userA})
	if s.appliedState.CertSource != certSourceAuto {
		t.Fatalf("expected auto-self, got %+v", s.appliedState)
	}

	target := realitySpec(443)
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: target})
	if s.appliedState.Config.Protocol != "vless" || s.appliedState.CertMode != "reality" {
		t.Fatalf("applied = %+v err=%v", s.appliedState, s.lastApplyErr)
	}
	if tk.singbox.lastTLS.HasCert() {
		t.Fatal("a REALITY target must not carry certificate material")
	}
	if s.cert.HasCert() || s.cert.Config().CertMode != "none" {
		t.Fatal("REALITY must deactivate the previous certificate manager")
	}
}

func TestCrossKernelSwitchStopsOldKernelBeforeStartingNew(t *testing.T) {
	tk := newTestKernels()
	s := newTestService(t, tk)
	seed(t, s, vlessSpec(443), []model.UserSpec{userA})

	var singboxRunningAtXrayStart bool
	tk.xray.onStart = func(*model.NodeSpec, []model.UserSpec) { singboxRunningAtXrayStart = tk.singbox.IsRunning() }

	xhttp := &model.NodeSpec{Protocol: "vless", ServerPort: 443, Network: "xhttp", NetworkSettings: map[string]any{"path": "/x"}}
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: xhttp})

	if s.appliedState.Kernel != model.KernelXray || !tk.xray.IsRunning() || tk.singbox.IsRunning() {
		t.Fatalf("expected xray serving and sing-box stopped: applied=%+v singbox=%v xray=%v err=%v", s.appliedState, tk.singbox.IsRunning(), tk.xray.IsRunning(), s.lastApplyErr)
	}
	if singboxRunningAtXrayStart {
		t.Fatal("the previous kernel must be stopped before the next one binds the port")
	}

	// Back to a target the preferred kernel can run: sing-box again.
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: vlessSpec(443)})
	if s.appliedState.Kernel != model.KernelSingbox || tk.xray.IsRunning() || !tk.singbox.IsRunning() {
		t.Fatalf("expected sing-box again: applied=%+v", s.appliedState)
	}
}

func TestCrossKernelSwitchFailureRollsBackWithLatestUsers(t *testing.T) {
	tk := newTestKernels()
	s := newTestService(t, tk)
	seed(t, s, vlessSpec(443), []model.UserSpec{userA})

	// Users change before the switch: userA is revoked, userB authorised.
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncUsers, Users: []model.UserSpec{userB}})

	tk.xray.startErr = errors.New("bind: address already in use")
	xhttp := &model.NodeSpec{Protocol: "vless", ServerPort: 443, Network: "xhttp"}
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: xhttp})

	if tk.xray.IsRunning() {
		t.Fatal("xray must not be running after a failed start")
	}
	if !tk.singbox.IsRunning() || !s.appliedState.Running || s.appliedState.Kernel != model.KernelSingbox {
		t.Fatalf("the previous kernel must be restored: applied=%+v", s.appliedState)
	}
	_, users := tk.singbox.startedWith()
	if len(users) != 1 || users[0].UUID != userB.UUID {
		t.Fatalf("rollback must use the latest authorised users, got %v", users)
	}
	if s.lastConfigHash != computeConfigHash(xhttp) || s.appliedState.ConfigHash == s.lastConfigHash {
		t.Fatal("desired must stay the new target while applied stays the old one")
	}
	if !s.retryPending {
		t.Fatal("a retry must be pending")
	}

	// The port frees up: the retry completes the switch.
	tk.xray.startErr = nil
	s.reconcile(context.Background())
	if s.appliedState.Kernel != model.KernelXray || !tk.xray.IsRunning() || tk.singbox.IsRunning() {
		t.Fatalf("retry did not complete the switch: applied=%+v err=%v", s.appliedState, s.lastApplyErr)
	}
}

func TestApplyFailureDoesNotAdvanceAppliedHashAndDuplicatePushKeepsRetry(t *testing.T) {
	tk := newTestKernels()
	s := newTestService(t, tk)
	tk.singbox.startFailures = 2

	spec := hysteria2Spec(54433)
	s.setDesiredConfig(spec, computeConfigHash(spec))
	s.setDesiredUsers([]model.UserSpec{userA})
	s.reconcile(context.Background())

	if s.appliedState.Running || s.appliedState.ConfigHash != "" {
		t.Fatalf("applied state advanced despite the failure: %+v", s.appliedState)
	}
	if s.lastApplyStage != "apply" || s.lastApplyErr == nil {
		t.Fatalf("failure must be recorded, stage=%q err=%v", s.lastApplyStage, s.lastApplyErr)
	}
	if !s.retryPending || s.retryAttempts != 1 {
		t.Fatalf("retry pending=%v attempts=%d", s.retryPending, s.retryAttempts)
	}

	// The same config pushed again (or served again by REST) is a no-op that
	// leaves the recovery in place.
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: hysteria2Spec(54433)})
	if !s.retryPending || s.retryAttempts != 1 {
		t.Fatalf("duplicate push disturbed the retry: pending=%v attempts=%d", s.retryPending, s.retryAttempts)
	}
	// A 304 answers with nothing at all.
	s.applyPullResult(context.Background(), pullResult{gen: s.desiredGen})
	if s.appliedState.Running {
		t.Fatal("second attempt should still fail")
	}
	if s.retryAttempts != 2 {
		t.Fatalf("attempts = %d, want 2", s.retryAttempts)
	}

	// Third attempt succeeds.
	s.reconcile(context.Background())
	if !s.appliedState.Running || s.appliedState.ConfigHash != s.lastConfigHash || s.retryPending {
		t.Fatalf("recovery failed: applied=%+v pending=%v err=%v", s.appliedState, s.retryPending, s.lastApplyErr)
	}
}

func TestPrepareFailureKeepsPreviousInstanceServing(t *testing.T) {
	tk := newTestKernels()
	s := newTestService(t, tk)
	seed(t, s, vlessSpec(443), []model.UserSpec{userA})

	// xhttp with multiplex: no kernel can run it.
	bad := &model.NodeSpec{Protocol: "vmess", ServerPort: 443, Network: "xhttp", Multiplex: &model.MultiplexConfig{Enabled: true}}
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: bad})

	if !tk.singbox.IsRunning() || !s.appliedState.Running || s.appliedState.Config.Protocol != "vless" {
		t.Fatalf("previous instance must keep serving: applied=%+v", s.appliedState)
	}
	if _, reload, _ := tk.singbox.counts(); reload != 0 {
		t.Fatal("a target rejected before apply must not touch the kernel")
	}
	if s.lastApplyStage != "prepare" || !s.retryPending {
		t.Fatalf("stage=%q pending=%v", s.lastApplyStage, s.retryPending)
	}

	// A corrected config applies without any manual restart.
	good := hysteria2Spec(8443)
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: good})
	if s.appliedState.Config.Protocol != "hysteria" || s.retryPending {
		t.Fatalf("corrected config not applied: applied=%+v err=%v", s.appliedState, s.lastApplyErr)
	}
}

func TestRapidSwitchesLeaveOnlyTheLatestTarget(t *testing.T) {
	tk := newTestKernels()
	s := newTestService(t, tk)
	seed(t, s, vlessSpec(443), []model.UserSpec{userA})

	a := hysteria2Spec(1001)
	b := realitySpec(1002)
	c := &model.NodeSpec{Protocol: "trojan", ServerPort: 1003, TLS: 1, ServerName: "t.example.test"}
	for _, spec := range []*model.NodeSpec{a, b, c, c, b, c} {
		s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: spec})
	}
	if s.appliedState.Config.ServerPort != 1003 || s.appliedState.ConfigHash != computeConfigHash(c) {
		t.Fatalf("applied = %+v", s.appliedState)
	}
	if tk.singbox.lastReload == nil || tk.singbox.lastReload.ServerPort != 1003 {
		t.Fatalf("kernel last reloaded with %+v", tk.singbox.lastReload)
	}
}

func TestStalePollResultDoesNotOverwriteNewerPush(t *testing.T) {
	tk := newTestKernels()
	s := newTestService(t, tk)
	seed(t, s, vlessSpec(443), []model.UserSpec{userA})
	src := s.source.(*fakeSource)

	// A poll started at generation g; while in flight the panel pushed a
	// newer config.
	staleGen := s.desiredGen
	newer := vlessSpec(444)
	s.handleWSEvent(context.Background(), controlplane.Event{Type: controlplane.EventSyncConfig, Config: newer})

	older := vlessSpec(443)
	s.applyPullResult(context.Background(), pullResult{config: older, configHash: computeConfigHash(older), gen: staleGen})

	if s.lastConfigHash != computeConfigHash(newer) || s.appliedState.Config.ServerPort != 444 {
		t.Fatalf("stale poll overwrote the push: desired port %d", s.lastConfig.ServerPort)
	}
	if src.resets != 1 {
		t.Fatalf("a superseded poll must reset the conditional cache and re-poll, resets=%d", src.resets)
	}
}

func TestCertificateRenewalTriggersReapply(t *testing.T) {
	tk := newTestKernels()
	s := newTestService(t, tk)
	seed(t, s, hysteria2Spec(54433), []model.UserSpec{userA})

	s.applyPullResult(context.Background(), pullResult{certChanged: true, gen: s.desiredGen})
	if _, reload, _ := tk.singbox.counts(); reload != 1 {
		t.Fatalf("renewed certificate must re-apply the node, reloads=%d", reload)
	}
	if s.certRenewed {
		t.Fatal("renewal flag must clear after a successful apply")
	}
}

func TestServiceRunRecoversFromTransientStartFailureWithoutRestart(t *testing.T) {
	tk := newTestKernels()
	s := newTestService(t, tk)
	src := s.source.(*fakeSource)
	src.bootstrap = controlplane.Bootstrap{Config: hysteria2Spec(54433), Users: []model.UserSpec{userA}}
	tk.singbox.startFailures = 3

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	waitFor(t, 5*time.Second, func() bool { return tk.singbox.IsRunning() })
	if start, _, _ := tk.singbox.counts(); start != 4 {
		t.Fatalf("starts = %d, want 4 (3 failures + 1 success)", start)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if tk.singbox.IsRunning() {
		t.Fatal("kernel must stop when the service stops")
	}
}

func TestServiceRunRetriesBootstrapAfterPanelErrors(t *testing.T) {
	tk := newTestKernels()
	s := newTestService(t, tk)
	src := s.source.(*fakeSource)
	src.initialErrs = 2
	src.bootstrap = controlplane.Bootstrap{Config: vlessSpec(443), Users: []model.UserSpec{userA}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	waitFor(t, 5*time.Second, func() bool { return tk.singbox.IsRunning() })
	src.mu.Lock()
	initials := src.initials
	src.mu.Unlock()
	if initials != 3 {
		t.Fatalf("Initial calls = %d, want 3", initials)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestUnboundDuringRetryNeverStartsKernel(t *testing.T) {
	tk := newTestKernels()
	s := newTestService(t, tk)
	src := s.source.(*fakeSource)
	src.bootstrap = controlplane.Bootstrap{Config: vlessSpec(443), Users: []model.UserSpec{userA}}
	tk.singbox.startFailures = 1000

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	waitFor(t, 5*time.Second, func() bool { start, _, _ := tk.singbox.counts(); return start >= 2 })
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	startsAtExit, _, _ := tk.singbox.counts()
	time.Sleep(20 * time.Millisecond)
	if start, _, _ := tk.singbox.counts(); start != startsAtExit {
		t.Fatal("a cancelled node kept retrying after exit")
	}
	if tk.singbox.IsRunning() {
		t.Fatal("an unbound node must never come back")
	}
}

func TestRetryDelayIsBoundedExponential(t *testing.T) {
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second, 160 * time.Second, 5 * time.Minute, 5 * time.Minute}
	for i, w := range want {
		if got := retryDelay(i + 1); got != w {
			t.Fatalf("retryDelay(%d) = %v, want %v", i+1, got, w)
		}
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %v", timeout)
}

var _ = fmt.Sprintf
