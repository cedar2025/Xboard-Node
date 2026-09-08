package service

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cedar2025/xboard-node/internal/cert"
	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/kernel/singbox"
	"github.com/cedar2025/xboard-node/internal/kernel/xray"
	"github.com/cedar2025/xboard-node/internal/limiter"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/monitor"
	"github.com/cedar2025/xboard-node/internal/nlog"
	"github.com/cedar2025/xboard-node/internal/tracker"
)

// Service runs one panel node (or one standalone node).
//
// It keeps two states apart:
//
//   - the desired state: the latest configuration and user set the control
//     plane authorised for this node (lastConfig / lastUsers). Every input —
//     bootstrap, WebSocket push, REST poll, machine mailbox — only updates the
//     desired state and then asks reconcile to act on it;
//   - the applied state: what the kernel is actually serving. It advances only
//     when an apply succeeded, so a failure can never be mistaken for a running
//     node and a later "not modified" answer from the panel never stalls the
//     recovery of a target that was received but not applied.
//
// reconcile runs on the main goroutine only, so applies are serial per node.
type Service struct {
	cfg          *config.Config
	source       controlplane.Source
	sink         controlplane.Sink
	tracker      *tracker.Tracker
	limiter      *limiter.Limiter
	speedTracker *limiter.SpeedTracker
	cert         *cert.Manager

	// preferredKernel is the operator's configured kernel. The kernel actually
	// used for a target is chosen per target from this preference and the
	// target itself, never from a previous automatic choice.
	preferredKernel string
	newKernel       func(config.KernelConfig) kernel.Kernel
	kernels         map[string]kernel.Kernel
	// kernel is the active kernel: the one serving the applied state or the
	// one the apply in progress targets. Guarded by metricsMu for readers on
	// other goroutines (WS ping metrics).
	kernel           kernel.Kernel
	activeKernelType string

	// Desired state.
	lastConfig     *model.NodeSpec
	lastUsers      []model.UserSpec
	lastConfigHash string
	lastUserHash   string
	// desiredGen increases on every desired-state change; async pulls carry
	// the generation they started under so a stale answer cannot overwrite a
	// newer push.
	desiredGen uint64

	// appliedState tracks the configuration and users that are currently
	// successfully running in the kernel.
	appliedState appliedState
	// certRenewed is set when the ACME manager renewed material behind the
	// applied state; the next reconcile re-applies with the new certificate.
	certRenewed bool

	// Recovery of a target that failed to apply: bounded exponential backoff,
	// reset whenever a new desired state arrives.
	retryAttempts  int
	retryTimer     *time.Timer
	retryPending   bool
	retryDelayFn   func(attempt int) time.Duration
	lastApplyErr   error
	lastApplyStage string

	// nodeLog is the logger with node context for this service instance.
	nodeLog *nlog.NodeLog

	pushInterval int // seconds
	pullInterval int // seconds

	pullBackoff apiBackoff // backoff for panel pull failures
	pushBackoff apiBackoff // backoff for panel push failures

	// pushActive prevents overlapping push/pull goroutines.
	pushActive atomic.Bool
	pullActive atomic.Bool
	// pullResults delivers async pullViaAPI results back to the main goroutine.
	pullResults chan pullResult

	wsClient         controlplane.PushClient        // Push client (nil if push is not enabled)
	wsEvents         chan controlplane.Event        // receives data events from push transport
	wsStatusCh       chan controlplane.StatusChange // receives push connectivity notifications
	wsCancel         context.CancelFunc             // cancels the WS client goroutine
	wsDisconnectAt   time.Time                      // when WS last disconnected (zero if connected)
	wsResyncPending  atomic.Bool
	machineMailbox   *controlplane.NodeMailbox
	machineMailboxCh <-chan struct{}

	// metricsMu: lastUsers, lastConfig, wsClient, wsDisconnectAt, kernel
	// (buildMetrics / wsMetrics vs main loop).
	metricsMu sync.RWMutex
}

// appliedState is what the kernel is serving.
type appliedState struct {
	Config     *model.NodeSpec
	Users      []model.UserSpec
	ConfigHash string
	UserHash   string
	Kernel     string
	TLS        kernel.TLSCert
	CertMode   string
	CertSource certSource
	// Running is true while the kernel serves Config; it is cleared when the
	// kernel is stopped (no users, kernel switch) or an apply failed after
	// the previous instance was torn down.
	Running bool
}

// pullResult carries the outcome of an async pullViaAPI back to the main goroutine.
type pullResult struct {
	config      *model.NodeSpec
	users       []model.UserSpec
	configHash  string
	userHash    string
	certChanged bool
	// gen is the desired-state generation the pull started under.
	gen uint64
}

// apiBackoff implements simple exponential backoff for API failures.
type apiBackoff struct {
	mu            sync.Mutex
	skipRemaining int
}

func (b *apiBackoff) shouldSkip() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.skipRemaining > 0 {
		b.skipRemaining--
		return true
	}
	return false
}

func (b *apiBackoff) onSuccess() {
	b.mu.Lock()
	b.skipRemaining = 0
	b.mu.Unlock()
}

func (b *apiBackoff) onFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.skipRemaining <= 0 {
		b.skipRemaining = 1
	} else if b.skipRemaining < 8 {
		b.skipRemaining *= 2
	}
}

// Retry schedule for a target that failed to apply.
const (
	retryBaseDelay = 5 * time.Second
	retryMaxDelay  = 5 * time.Minute
)

// retryDelay returns the bounded exponential delay before attempt n (1-based).
func retryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := retryBaseDelay
	for i := 1; i < attempt; i++ {
		delay *= 2
		if delay >= retryMaxDelay {
			return retryMaxDelay
		}
	}
	if delay > retryMaxDelay {
		return retryMaxDelay
	}
	return delay
}

func New(cfg *config.Config) *Service {
	var cp controlplane.ControlPlane
	if cfg.IsStandalone() {
		cp = controlplane.NewLocalControlPlane(cfg)
	} else {
		cp = controlplane.NewPanelControlPlane(cfg.Panel, cfg.WS, cfg.Kernel)
	}
	return newService(cfg, cp)
}

// NewWithControlPlane creates a Service with an externally-provided
// ControlPlane. Used by the machine orchestrator to inject a
// MachinePanelControlPlane with WS mux routing.
func NewWithControlPlane(cfg *config.Config, cp controlplane.ControlPlane) *Service {
	return newService(cfg, cp)
}

// defaultKernelFactory builds the kernel for a kernel type.
func defaultKernelFactory(kcfg config.KernelConfig) kernel.Kernel {
	switch kcfg.Type {
	case model.KernelXray:
		return xray.New(kcfg)
	default:
		return singbox.New(kcfg)
	}
}

func newService(cfg *config.Config, cp controlplane.ControlPlane) *Service {
	certMgr := cert.NewManager(cfg.Cert)

	preferred := cfg.Kernel.Type
	switch preferred {
	case model.KernelSingbox, model.KernelXray:
	default:
		nlog.Core().Warn("unsupported kernel type, defaulting to sing-box", "type", cfg.Kernel.Type)
		preferred = model.KernelSingbox
	}

	l := limiter.New()
	st := limiter.NewSpeedTracker(l)

	return &Service{
		cfg:             cfg,
		source:          cp,
		sink:            cp,
		preferredKernel: preferred,
		newKernel:       defaultKernelFactory,
		kernels:         make(map[string]kernel.Kernel),
		tracker:         tracker.New(),
		limiter:         l,
		speedTracker:    st,
		cert:            certMgr,
		retryDelayFn:    retryDelay,
		wsEvents:        make(chan controlplane.Event, 16),
		wsStatusCh:      make(chan controlplane.StatusChange, 4),
		pullResults:     make(chan pullResult, 1),
	}
}

func (s *Service) Run(ctx context.Context) error {
	defer s.cert.Stop()

	// Handshake: get WS config + initial data in one call. A control-plane
	// failure is retried in process; a target that cannot be applied does not
	// stop the loop (see reconcile).
	if err := s.bootstrap(ctx); err != nil {
		return fmt.Errorf("initial setup: %w", err)
	}
	defer s.stopKernels()

	// Set up tickers
	trackTicker := time.NewTicker(time.Duration(s.cfg.Node.TrackInterval) * time.Second)
	pushInterval := time.Duration(math.Max(float64(s.pushInterval), 5)) * time.Second
	pullInterval := time.Duration(s.pullInterval) * time.Second
	reportTicker := time.NewTicker(pushInterval)
	pullTicker := time.NewTicker(pullInterval)
	deviceReportTicker := time.NewTicker(time.Duration(s.cfg.Node.DeviceReportInterval) * time.Second)

	// WS discovery: when in REST-only mode, periodically re-handshake to check
	// if WS has been enabled. When WS is disconnected for too long, re-check
	// if it's still available.
	wsDiscoveryTicker := time.NewTicker(time.Duration(s.cfg.WS.DiscoveryInterval) * time.Second)

	defer trackTicker.Stop()
	defer reportTicker.Stop()
	defer pullTicker.Stop()
	defer deviceReportTicker.Stop()
	defer wsDiscoveryTicker.Stop()
	defer s.stopRetryTimer()

	s.startWSClient(ctx)

	for {
		select {
		case <-ctx.Done():
			s.pushReportSync()
			return nil

		case <-trackTicker.C:
			s.trackAndEnforce(ctx)

		case <-reportTicker.C:
			s.pushReportAsync()

		case <-deviceReportTicker.C:
			s.reportDevices()

		case <-pullTicker.C:
			// A renewed ACME certificate is picked up on the poll cadence
			// whether or not the WS transport is connected.
			if s.cert.CertRenewed() {
				s.certRenewed = true
				s.reconcile(ctx)
			}
			// When WebSocket is connected, skip REST polling entirely.
			// Config/user updates arrive via WS push.
			if s.wsClient != nil && s.wsClient.IsConnected() {
				continue
			}
			nlog.Core().Debug("polling from API (ws not connected)")
			s.pullViaAPIAsync(ctx)

		case result := <-s.pullResults:
			s.applyPullResult(ctx, result)

		case <-s.retryC():
			s.retryPending = false
			s.reconcile(ctx)

		case <-wsDiscoveryTicker.C:
			s.wsDiscovery(ctx)

		case status := <-s.wsStatusCh:
			s.handleWSStatus(ctx, status)

		case <-s.machineMailboxCh:
			s.drainMachineMailbox(ctx)

		case event := <-s.wsEvents:
			s.handleWSEvent(ctx, event)
		}
	}
}

// bootstrap runs initialSetup, retrying control-plane failures with the same
// bounded backoff used for apply failures. A standalone node has nothing to
// wait for, so its errors are returned at once.
func (s *Service) bootstrap(ctx context.Context) error {
	attempt := 0
	for {
		// An earlier attempt may have fetched users before rejecting the
		// config. There is no applied snapshot to pair with a 304 yet.
		s.source.ResetCache()
		err := s.initialSetup(ctx)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !s.source.SupportsPolling() {
			return err
		}
		attempt++
		delay := s.retryDelayFn(attempt)
		s.logf("error", "initial setup failed, retrying", "attempt", attempt, "retry_in", delay, "error", err)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *Service) initialSetup(ctx context.Context) error {
	bootstrap, err := s.source.Initial(ctx, s.wsMetrics, s.wsEvents, s.wsStatusCh)
	if err != nil {
		return err
	}

	if s.cfg.Node.PushInterval == 0 && bootstrap.PushInterval > 0 {
		s.pushInterval = bootstrap.PushInterval
	} else {
		s.pushInterval = s.cfg.Node.PushInterval
	}
	if s.pushInterval == 0 {
		s.pushInterval = 60
	}

	if s.cfg.Node.PullInterval == 0 && bootstrap.PullInterval > 0 {
		s.pullInterval = bootstrap.PullInterval
	} else {
		s.pullInterval = s.cfg.Node.PullInterval
	}
	if s.pullInterval == 0 {
		s.pullInterval = 60
	}

	if bootstrap.Push != nil {
		s.wsClient = bootstrap.Push
	}
	s.machineMailbox = bootstrap.Mailbox
	if s.machineMailbox != nil {
		s.machineMailboxCh = s.machineMailbox.NotifyCh()
	}
	if bootstrap.Config == nil {
		if bootstrap.Push != nil {
			// In machine mode a shared WS client may be available before the first
			// per-node snapshot arrives. In that case we wait for subsequent WS/REST
			// updates instead of failing startup.
			return nil
		}
		return fmt.Errorf("initial config is nil")
	}

	users := bootstrap.Users
	if users == nil {
		users = []model.UserSpec{}
	}
	s.setDesiredConfig(bootstrap.Config)
	s.setDesiredUsers(users)

	s.logf("info", "initial snapshot ready",
		"protocol", bootstrap.Config.Protocol,
		"port", bootstrap.Config.ServerPort,
		"users", len(users),
	)

	// The first apply goes through the same pipeline as every later one; a
	// failure is logged, retried with backoff and never ends the service.
	s.reconcile(ctx)
	s.markMailboxReadyAndDrain(ctx)
	return nil
}

// ─── Desired state ──────────────────────────────────────────────────────────

// setDesiredConfig records spec as the desired configuration. The service
// takes its own deep copy and hashes that copy, so the recorded snapshot and
// its hash always describe the same content whatever the caller does with its
// object afterwards. prepareTarget copies and hashes this snapshot again, so
// a successful apply leaves the desired and applied hashes equal.
func (s *Service) setDesiredConfig(spec *model.NodeSpec) {
	snapshot := model.CloneNodeSpec(spec)
	s.metricsMu.Lock()
	s.lastConfig = snapshot
	s.metricsMu.Unlock()
	s.lastConfigHash = computeConfigHash(snapshot)
	s.desiredGen++
	s.retryAttempts = 0
	if snapshot != nil && s.nodeLog == nil {
		s.nodeLog = nlog.ForNode(snapshot.Protocol, snapshot.ServerPort)
	}
}

func (s *Service) setDesiredUsers(users []model.UserSpec) {
	if users == nil {
		users = []model.UserSpec{}
	}
	s.metricsMu.Lock()
	s.lastUsers = model.CloneUserSpecs(users)
	s.metricsMu.Unlock()
	s.lastUserHash = computeUserHash(users)
	s.desiredGen++
	s.retryAttempts = 0
}

// updateUserState records a user set as desired. Kept for callers and tests
// that seed state before driving the kernel.
func (s *Service) updateUserState(users []model.UserSpec) {
	s.setDesiredUsers(users)
}

// setLimiterUsers points the device / speed limiters at users. It runs before
// a kernel update so credentials the kernel is about to accept already have
// their limits, and again after a failed update so the limiters describe the
// users the kernel still serves.
func (s *Service) setLimiterUsers(users []model.UserSpec) {
	if users == nil {
		users = []model.UserSpec{}
	}
	s.limiter.UpdateUsers(users)
	s.speedTracker.UpdateBuckets()
}

// ─── Kernel management ──────────────────────────────────────────────────────

// kernelFor returns the kernel instance for a kernel type, creating it on
// first use and wiring the shared limiters into it.
func (s *Service) kernelFor(kernelType string) kernel.Kernel {
	if k, ok := s.kernels[kernelType]; ok {
		return k
	}
	kcfg := s.cfg.Kernel
	kcfg.Type = kernelType
	if s.lastConfig != nil && s.lastConfig.KernelLogLevel != "" {
		kcfg.LogLevel = s.lastConfig.KernelLogLevel
	}
	k := s.newKernel(kcfg)
	k.SetSpeedLimitFunc(s.speedTracker.GetLimiter)
	k.SetDeviceLimitFunc(s.limiter.GetDeviceLimitByUUID)
	s.kernels[kernelType] = k
	return k
}

func (s *Service) setActiveKernel(k kernel.Kernel, kernelType string) {
	s.metricsMu.Lock()
	s.kernel = k
	s.activeKernelType = kernelType
	s.metricsMu.Unlock()
}

// activeKernel returns the active kernel for readers on other goroutines.
func (s *Service) activeKernel() kernel.Kernel {
	s.metricsMu.RLock()
	defer s.metricsMu.RUnlock()
	return s.kernel
}

func (s *Service) kernelRunning() bool {
	k := s.activeKernel()
	return k != nil && k.IsRunning()
}

func (s *Service) stopKernels() {
	for _, k := range s.kernels {
		if k.IsRunning() {
			k.Stop()
		}
	}
	s.appliedState.Running = false
}

// ─── Reconcile: desired → applied ───────────────────────────────────────────

// servingDesiredConfig reports whether the running kernel serves the desired
// configuration, so that only the user set may still differ.
func (s *Service) servingDesiredConfig() bool {
	return s.appliedState.Running && s.kernelRunning() && s.appliedState.ConfigHash == s.lastConfigHash && !s.certRenewed
}

// reconcile drives the kernel towards the desired state. It is the only path
// that starts, reloads or stops a kernel for configuration reasons; every
// input funnels into it. It never returns an error: a failed apply is
// recorded, the previous instance (if any) keeps serving, and a retry is
// scheduled with bounded backoff until a new desired state arrives.
func (s *Service) reconcile(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	if s.lastConfig == nil {
		return
	}
	if len(s.lastUsers) == 0 {
		s.stopForNoUsers()
		return
	}
	// Enforce permissions on the listener actually serving, independently
	// of whether the desired protocol/configuration can be prepared.
	if s.kernelRunning() && s.appliedState.UserHash != s.lastUserHash {
		s.applyUsersHot(ctx)
		if s.appliedState.UserHash != s.lastUserHash {
			return
		}
	}
	if s.servingDesiredConfig() {
		s.clearRetry()
		return
	}
	s.applyTarget(ctx)
}

// stopForNoUsers takes the listener down while the panel authorises nobody.
// The desired configuration is kept so the node starts as soon as users
// arrive on any path (full sync, delta, REST).
func (s *Service) stopForNoUsers() {
	if s.kernelRunning() {
		s.logf("warn", "no users authorised, stopping kernel", "protocol", s.lastConfig.Protocol, "port", s.lastConfig.ServerPort)
		s.activeKernel().Stop()
	} else if !s.appliedState.Running {
		s.logf("warn", "no users, kernel will not start until users are available", "protocol", s.lastConfig.Protocol, "port", s.lastConfig.ServerPort)
	}
	s.appliedState.Running = false
	s.appliedState.Users = nil
	s.appliedState.UserHash = ""
	s.setLimiterUsers(nil)
	s.clearRetry()
}

// applyUsersHot updates the user set of a kernel that already serves the
// desired configuration. A kernel that cannot hot-swap falls back to the full
// apply path.
func (s *Service) applyUsersHot(ctx context.Context) {
	k := s.activeKernel()
	users := model.CloneUserSpecs(s.lastUsers)
	s.setLimiterUsers(users)
	added, removed, err := k.UpdateUsers(users)
	if err != nil {
		s.failUserUpdate(err)
		return
	}
	s.appliedState.Users = users
	s.appliedState.UserHash = s.lastUserHash
	s.clearRetry()
	if added > 0 || removed > 0 {
		s.logf("info", fmt.Sprintf("users updated: +%d -%d", added, removed))
	}
}

// failUserUpdate stops a listener that cannot enforce the current user set.
// Retrying a different target must never retain revoked credentials.
func (s *Service) failUserUpdate(err error) {
	if k := s.activeKernel(); k != nil && k.IsRunning() {
		k.Stop()
	}
	s.appliedState.Running = false
	s.appliedState.Users = nil
	s.appliedState.UserHash = ""
	s.setLimiterUsers(nil)
	s.failApply("users", s.lastConfig, s.appliedState.Kernel, err)
}

// applyTarget runs the full pipeline for the desired configuration:
// prepare (kernel selection, policy, certificate, config validation) and then
// the controlled rebuild of the node.
func (s *Service) applyTarget(ctx context.Context) {
	spec := s.lastConfig
	users := model.CloneUserSpecs(s.lastUsers)
	if spec == nil || len(users) == 0 || ctx.Err() != nil {
		return
	}

	prepared, err := s.prepareTarget(ctx, spec, users)
	if err != nil {
		s.failApply("prepare", spec, "", err)
		return
	}
	if ctx.Err() != nil {
		s.cert.Discard(prepared.cert)
		return
	}
	for _, warning := range prepared.warnings {
		s.logf("warn", warning, "protocol", spec.Protocol, "port", spec.ServerPort)
	}

	s.setLimiterUsers(users)
	if err := s.activate(ctx, prepared); err != nil {
		s.cert.Discard(prepared.cert)
		// The limiters must describe the users the kernel actually serves.
		if s.appliedState.Running {
			s.setLimiterUsers(s.appliedState.Users)
		} else {
			s.setLimiterUsers(nil)
		}
		s.failApply("apply", spec, prepared.kernelType, err)
		return
	}
	if ctx.Err() != nil {
		s.stopKernels()
		s.cert.Discard(prepared.cert)
		return
	}
	s.cert.Commit(prepared.cert)
	s.markApplied(prepared)
}

// activate makes the kernel serve a prepared target.
//
//   - A different kernel than the active one: the active kernel is stopped
//     first (the target may reuse its port), then the new kernel starts. If
//     the new kernel fails, the previous kernel is restarted with the previous
//     configuration and the latest authorised user set.
//   - The same kernel already running: an in-place reload; a kernel that
//     cannot reload in place restarts itself.
//   - No running kernel: a plain start.
func (s *Service) activate(ctx context.Context, p *preparedTarget) error {
	k := s.kernelFor(p.kernelType)
	current := s.activeKernel()

	switch {
	case current != nil && current != k && current.IsRunning():
		previous := s.appliedState
		s.logf("info", "switching kernel", "from", previous.Kernel, "to", p.kernelType, "protocol", p.spec.Protocol, "port", p.spec.ServerPort)
		current.Stop()
		s.appliedState.Running = false
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := k.Start(p.spec, p.users, p.tls); err != nil {
			s.rollbackPrevious(ctx, current, previous, p.users)
			return err
		}
		s.setActiveKernel(k, p.kernelType)
		return nil

	case current == k && k.IsRunning():
		if err := k.Reload(p.spec, p.users, p.tls); err != nil {
			s.logf("warn", "in-place reload failed, restarting kernel", "error", err)
			if err2 := k.Start(p.spec, p.users, p.tls); err2 != nil {
				return fmt.Errorf("reload: %v; restart: %w", err, err2)
			}
		}
		return nil

	default:
		if err := k.Start(p.spec, p.users, p.tls); err != nil {
			return err
		}
		s.setActiveKernel(k, p.kernelType)
		return nil
	}
}

// rollbackPrevious restores the previously applied instance of this node
// after a kernel switch failed. It only ever restores the configuration this
// node had successfully applied and always uses the latest authorised users,
// so a revoked credential is never brought back.
func (s *Service) rollbackPrevious(ctx context.Context, old kernel.Kernel, previous appliedState, users []model.UserSpec) {
	if ctx.Err() != nil || !previous.Running || previous.Config == nil || len(users) == 0 {
		return
	}
	if err := old.Start(previous.Config, users, previous.TLS); err != nil {
		s.logf("error", "rollback to previous kernel failed", "kernel", previous.Kernel, "protocol", previous.Config.Protocol, "error", err)
		s.appliedState.Running = false
		return
	}
	s.appliedState = previous
	s.appliedState.Users = model.CloneUserSpecs(users)
	s.appliedState.UserHash = computeUserHash(users)
	s.appliedState.Running = true
	s.setActiveKernel(old, previous.Kernel)
	s.logf("warn", "restored previous node after failed switch", "kernel", previous.Kernel, "protocol", previous.Config.Protocol, "port", previous.Config.ServerPort)
}

func (s *Service) markApplied(p *preparedTarget) {
	s.appliedState = appliedState{
		Config:     p.spec,
		Users:      p.users,
		ConfigHash: p.configHash,
		UserHash:   computeUserHash(p.users),
		Kernel:     p.kernelType,
		TLS:        p.tls,
		CertMode:   p.plan.Mode,
		CertSource: p.plan.Source,
		Running:    true,
	}
	s.certRenewed = false
	s.lastApplyErr = nil
	s.lastApplyStage = ""
	s.clearRetry()

	s.nodeLog = nlog.ForNode(p.spec.Protocol, p.spec.ServerPort)
	s.speedTracker.SetLogCallback(func(msg string) {
		fullMsg := fmt.Sprintf("speedtracker: %s active_limiters=%d", msg, s.speedTracker.LimitedUserCount())
		s.nodeLog.Info(fullMsg)
	})
	s.logf("info", "node applied",
		"protocol", p.spec.Protocol,
		"port", p.spec.ServerPort,
		"kernel", p.kernelType,
		"tls", string(p.plan.Requirement),
		"cert", fmt.Sprintf("%s/%s", p.plan.Source, p.plan.Mode),
		"users", len(p.users),
	)
}

// failApply records a failed apply and schedules the next attempt.
func (s *Service) failApply(stage string, spec *model.NodeSpec, kernelType string, err error) {
	s.lastApplyErr = err
	s.lastApplyStage = stage
	if !s.kernelRunning() {
		s.appliedState.Running = false
	}
	s.retryAttempts++
	delay := s.retryDelayFn(s.retryAttempts)
	s.scheduleRetry(delay)
	fields := []any{
		"stage", stage,
		"protocol", spec.Protocol,
		"port", spec.ServerPort,
		"attempt", s.retryAttempts,
		"retry_in", delay,
		"error", err,
	}
	if kernelType != "" {
		fields = append(fields, "kernel", kernelType)
	}
	if s.appliedState.Running && s.appliedState.Config != nil {
		fields = append(fields, "serving", fmt.Sprintf("%s:%d", s.appliedState.Config.Protocol, s.appliedState.Config.ServerPort))
	}
	s.logf("error", "node apply failed", fields...)
}

// ─── Retry timer ────────────────────────────────────────────────────────────

func (s *Service) scheduleRetry(delay time.Duration) {
	if s.retryTimer == nil {
		s.retryTimer = time.NewTimer(delay)
	} else {
		s.drainRetryTimer()
		s.retryTimer.Reset(delay)
	}
	s.retryPending = true
}

func (s *Service) drainRetryTimer() {
	if s.retryTimer == nil {
		return
	}
	if !s.retryTimer.Stop() {
		select {
		case <-s.retryTimer.C:
		default:
		}
	}
}

func (s *Service) clearRetry() {
	s.retryAttempts = 0
	if s.retryPending {
		s.drainRetryTimer()
	}
	s.retryPending = false
}

func (s *Service) stopRetryTimer() {
	s.drainRetryTimer()
	s.retryPending = false
}

// retryC returns the timer channel while a retry is pending; a nil channel
// blocks forever in select, which is the idle state.
func (s *Service) retryC() <-chan time.Time {
	if !s.retryPending || s.retryTimer == nil {
		return nil
	}
	return s.retryTimer.C
}

// ─── Logging ────────────────────────────────────────────────────────────────

// logf writes to the node logger when one exists, tagging every line with the
// panel node id so a multi-node process stays readable.
func (s *Service) logf(level, msg string, fields ...any) {
	if s.cfg != nil && s.cfg.Panel.NodeID > 0 {
		fields = append([]any{"node_id", s.cfg.Panel.NodeID}, fields...)
	}
	logger := s.nodeLog
	if logger == nil {
		logger = nlog.Core()
	}
	switch level {
	case "debug":
		logger.Debug(msg, fields...)
	case "warn":
		logger.Warn(msg, fields...)
	case "error":
		logger.Error(msg, fields...)
	default:
		logger.Info(msg, fields...)
	}
}

// startWSClient starts the push client goroutine if a client is configured.
func (s *Service) startWSClient(ctx context.Context) {
	if s.wsClient == nil {
		return
	}
	wsCtx, wsCancel := context.WithCancel(ctx)
	s.wsCancel = wsCancel
	go s.wsClient.Run(wsCtx)
}

func (s *Service) markMailboxReadyAndDrain(ctx context.Context) {
	if s.machineMailbox == nil {
		return
	}
	// Seed mailbox with bootstrap state so delta events can be applied
	// incrementally instead of always triggering REST reconciliation.
	s.metricsMu.RLock()
	users := s.lastUsers
	config := s.lastConfig
	s.metricsMu.RUnlock()
	s.machineMailbox.SeedBaseline(users, config)
	s.machineMailbox.MarkReady()
	s.drainMachineMailbox(ctx)
}

func (s *Service) drainMachineMailbox(ctx context.Context) {
	if s.machineMailbox == nil {
		return
	}
	state := s.machineMailbox.DrainIfReady()
	if state.HasConfig {
		s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncConfig, Config: state.Config})
	}
	if state.HasUsers {
		s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncUsers, Users: state.Users})
	}
	if state.HasDevices {
		s.handleWSEvent(ctx, controlplane.Event{Type: controlplane.EventSyncDevices, DeviceUsers: state.DeviceUsers})
	}
	if state.NeedsReconcile {
		s.requestWSResync(ctx, "machine_mailbox_reconcile")
	}
}

func (s *Service) requestWSResync(ctx context.Context, reason string) {
	if !s.wsResyncPending.CompareAndSwap(false, true) {
		return
	}
	s.logf("warn", "ws state may be stale, scheduling REST reconciliation", "reason", reason)
	s.pullViaAPIAsync(ctx)
}

func (s *Service) wsMetrics() map[string]interface{} {
	status := monitor.Collect()
	m := s.buildMetrics(status)
	m["kernel_status"] = s.kernelRunning()
	return m
}

// handleWSStatus reacts to WS connectivity changes.
//
// - On disconnect: record timestamp, immediately REST poll.
// - On reconnect: clear disconnect timestamp, REST poll to catch missed events.
func (s *Service) handleWSStatus(ctx context.Context, status controlplane.StatusChange) {
	if status.NeedsResync {
		s.requestWSResync(ctx, "drop_detected")
	}
	if status.Connected {
		s.metricsMu.Lock()
		s.wsDisconnectAt = time.Time{}
		s.metricsMu.Unlock()
		s.logf("info", "ws connected")
		// After reconnect, proactively pull once to ensure we haven't missed
		// any updates during the disconnection window.
		s.pullViaAPIAsync(ctx)
	} else {
		s.metricsMu.Lock()
		if s.wsDisconnectAt.IsZero() {
			s.wsDisconnectAt = time.Now()
		}
		s.metricsMu.Unlock()
		s.logf("info", "ws disconnected")
		// Clear global device state on disconnect
		if k := s.activeKernel(); k != nil {
			k.ClearGlobalDevices()
		}
		s.pullViaAPIAsync(ctx)
	}
}

// wsDiscovery periodically checks WS availability:
//
//  1. REST-only mode (wsClient == nil): Re-handshake to check if panel now has
//     WS enabled. If so, create and start a WS client. This handles the case
//     where WS was not enabled at startup but enabled later.
//
//  2. WS disconnected for >10 min: Re-handshake to check if WS config changed.
//     If WS is now disabled, stop the WS client and switch to REST-only.
//     If WS config changed (different URL/channel), restart with new config.
func (s *Service) wsDiscovery(ctx context.Context) {
	if !s.source.SupportsDiscovery() {
		return
	}

	needsCheck := false
	if s.wsClient == nil {
		needsCheck = true
		nlog.Core().Debug("push discovery: no push client, checking if control plane enabled push")
	} else if !s.wsDisconnectAt.IsZero() && time.Since(s.wsDisconnectAt) > 10*time.Minute {
		needsCheck = true
		nlog.Core().Debug("push discovery: push disconnected for >10min, re-checking")
	}
	if !needsCheck {
		return
	}

	pushClient, err := s.source.Discover(ctx, s.wsMetrics, s.wsEvents, s.wsStatusCh)
	if err != nil {
		nlog.Core().Debug("push discovery failed", "error", err)
		return
	}
	if s.source.SupportsPolling() {
		s.pullViaAPIAsync(ctx)
	}

	if pushClient != nil {
		if s.wsClient == nil {
			nlog.Core().Info("push discovery: control plane enabled push, creating client")
			s.metricsMu.Lock()
			s.wsClient = pushClient
			s.wsDisconnectAt = time.Time{}
			s.metricsMu.Unlock()
			s.startWSClient(ctx)
		}
	} else if s.wsClient != nil {
		nlog.Core().Info("push discovery: control plane disabled push, switching to polling")
		if s.wsCancel != nil {
			s.wsCancel()
		}
		s.metricsMu.Lock()
		s.wsClient = nil
		s.wsDisconnectAt = time.Time{}
		s.metricsMu.Unlock()
		s.wsCancel = nil
	}
}

// handleWSEvent processes data events received via WebSocket. Each event only
// updates the desired state; reconcile decides what the kernel needs.
func (s *Service) handleWSEvent(ctx context.Context, event controlplane.Event) {
	switch event.Type {
	case controlplane.EventSyncConfig:
		if event.Config == nil {
			return
		}
		newConfigHash := computeConfigHash(event.Config)
		if newConfigHash == s.lastConfigHash {
			// A repeated push of the target we already hold: nothing to do,
			// and a pending retry keeps its schedule.
			return
		}
		s.logf("info", "config received", "protocol", event.Config.Protocol, "port", event.Config.ServerPort, "users", len(s.lastUsers))
		s.setDesiredConfig(event.Config)
		if event.Users != nil {
			s.setDesiredUsers(event.Users)
		}
		s.reconcile(ctx)

	case controlplane.EventSyncUsers:
		if event.Users == nil {
			return
		}
		newHash := computeUserHash(event.Users)
		if newHash == s.lastUserHash {
			return
		}
		s.logf("info", fmt.Sprintf("users updated, %d users", len(event.Users)))
		s.applyUserUpdate(ctx, event.Users, newHash)

	case controlplane.EventSyncUserDelta:
		if len(event.DeltaUsers) == 0 {
			return
		}
		s.logf("info", fmt.Sprintf("users delta: %s, %d users", event.DeltaAction, len(event.DeltaUsers)))
		s.applyUserDelta(ctx, event.DeltaAction, event.DeltaUsers)

	case controlplane.EventSyncDevices:
		// Sync global device state
		if event.DeviceUsers != nil {
			if k := s.activeKernel(); k != nil {
				k.UpdateGlobalDevices(event.DeviceUsers)
			}
		}

	default:
		nlog.Core().Debug(fmt.Sprintf("unknown ws event: %v", event.Type))
	}
}

// pullViaAPIAsync fetches config/users from the panel API in a background
// goroutine and sends the result to pullResults for the main goroutine to apply.
func (s *Service) pullViaAPIAsync(ctx context.Context) {
	if !s.source.SupportsPolling() {
		return
	}
	if !s.pullActive.CompareAndSwap(false, true) {
		nlog.Core().Debug("pull already in progress, skipping")
		return
	}
	if s.pullBackoff.shouldSkip() {
		nlog.Core().Debug("skipping pull due to backoff")
		s.pullActive.Store(false)
		return
	}

	currentConfigHash := s.lastConfigHash
	certChanged := s.cert.CertRenewed()
	gen := s.desiredGen

	go func() {
		snapshot, err := s.source.Poll(ctx)
		if err != nil {
			s.pullActive.Store(false)
			nlog.Core().Error("poll control plane failed", "error", err)
			s.pullBackoff.onFailure()
			return
		}
		s.pullBackoff.onSuccess()

		result := pullResult{certChanged: certChanged, gen: gen}
		if snapshot.Config != nil {
			result.config = snapshot.Config
			result.configHash = computeConfigHash(snapshot.Config)
			if result.configHash == currentConfigHash && !certChanged {
				result.config = nil
			}
		}
		if snapshot.Users != nil {
			result.users = snapshot.Users
			result.userHash = computeUserHash(snapshot.Users)
		}

		// Release the slot before handing over so the main goroutine can
		// start a follow-up pull while it processes this result.
		s.pullActive.Store(false)
		select {
		case s.pullResults <- result:
		case <-ctx.Done():
		}
	}()
}

// applyPullResult processes the result of an async pullViaAPI on the main goroutine.
func (s *Service) applyPullResult(ctx context.Context, result pullResult) {
	s.wsResyncPending.Store(false)
	if result.certChanged {
		s.certRenewed = true
	}

	if result.gen != s.desiredGen &&
		((result.config != nil && result.configHash != s.lastConfigHash) ||
			(result.users != nil && result.userHash != s.lastUserHash)) {
		// A config or user push superseded this poll. A 304 config response
		// must not let an older user list undo a revocation.
		// The poll may be older than the push, so
		// it must not overwrite it; the panel is asked again without the
		// conditional-request cache so the answer is complete either way.
		s.logf("debug", "poll result superseded by a push, re-polling")
		s.source.ResetCache()
		s.pullViaAPIAsync(ctx)
		return
	}

	if result.certChanged {
		s.logf("info", "certificate renewed, kernel reload needed")
		s.certRenewed = true
	}

	if result.config != nil && result.configHash != s.lastConfigHash {
		s.logf("info", "config received", "protocol", result.config.Protocol, "port", result.config.ServerPort, "source", "rest")
		s.setDesiredConfig(result.config)
	}
	if result.users != nil && result.userHash != s.lastUserHash {
		s.logf("info", fmt.Sprintf("users updated, %d users", len(result.users)), "source", "rest")
		s.setDesiredUsers(result.users)
	}
	s.reconcile(ctx)
}

// ─── User update entry points ───────────────────────────────────────────────

// applyUserUpdate replaces the full user set. Called from WS sync.users and
// REST polling. The kernel is hot-swapped when it already serves the desired
// configuration, and started when it does not (including the zero-to-one
// user transition).
func (s *Service) applyUserUpdate(ctx context.Context, users []model.UserSpec, newHash string) {
	s.setDesiredUsers(users)
	if newHash != "" {
		s.lastUserHash = newHash
	}
	s.reconcile(ctx)
}

// applyUserDelta applies an incremental user change (add or remove) via the
// kernel's atomic user API when the kernel serves the desired configuration.
// Otherwise it only records the new desired user set and lets reconcile start
// or rebuild the kernel.
func (s *Service) applyUserDelta(ctx context.Context, action string, deltaUsers []model.UserSpec) {
	switch action {
	case "add":
		if len(deltaUsers) == 0 {
			return
		}
		merged := mergeUsers(s.lastUsers, deltaUsers)
		rotated := rotatesCredential(s.appliedState.Users, deltaUsers)
		s.setDesiredUsers(merged)
		if !s.servingDesiredConfig() {
			s.reconcile(ctx)
			return
		}
		k := s.activeKernel()
		s.setLimiterUsers(merged)
		var added int
		var err error
		if rotated {
			// A rotated credential keeps its ID. The kernels' full replace
			// removes the stale identity before adding the new one; a plain
			// AddUsers would keep the old credential valid, and a separate
			// removal could not fail safely (its failure would be followed by
			// an add that reports success, and on xray removing the only user
			// stops the kernel).
			added, _, err = k.UpdateUsers(merged)
		} else {
			added, err = k.AddUsers(deltaUsers)
			if err != nil {
				s.logf("warn", fmt.Sprintf("AddUsers failed: %v, falling back to UpdateUsers", err))
				added, _, err = k.UpdateUsers(merged)
			}
		}
		if err != nil {
			s.logf("error", fmt.Sprintf("user delta add failed: %v", err))
			s.failUserUpdate(err)
			return
		}
		s.appliedState.Users = model.CloneUserSpecs(merged)
		s.appliedState.UserHash = s.lastUserHash
		s.clearRetry()
		if added > 0 {
			s.logf("info", fmt.Sprintf("users added: +%d", added))
		}

	case "remove":
		if len(deltaUsers) == 0 {
			return
		}
		filtered := subtractUsers(s.lastUsers, deltaUsers)
		s.setDesiredUsers(filtered)
		if len(filtered) == 0 || !s.servingDesiredConfig() {
			s.reconcile(ctx)
			return
		}
		k := s.activeKernel()
		s.setLimiterUsers(filtered)
		removed, err := k.RemoveUsers(deltaUsers)
		if err != nil {
			s.logf("warn", fmt.Sprintf("RemoveUsers failed: %v, falling back to UpdateUsers", err))
			if _, _, err := k.UpdateUsers(filtered); err != nil {
				s.logf("error", fmt.Sprintf("UpdateUsers fallback failed: %v", err))
				s.failUserUpdate(err)
				return
			}
		}
		s.appliedState.Users = model.CloneUserSpecs(filtered)
		s.appliedState.UserHash = s.lastUserHash
		s.clearRetry()
		if removed > 0 {
			s.logf("info", fmt.Sprintf("users removed: -%d", removed))
		}

	default:
		s.logf("warn", fmt.Sprintf("unknown user delta action: %s", action))
	}
}

// rotatesCredential reports whether delta replaces the credential of a user
// the kernel currently serves (same ID, different UUID).
func rotatesCredential(applied, delta []model.UserSpec) bool {
	byID := make(map[int]string, len(applied))
	for _, u := range applied {
		byID[u.ID] = u.UUID
	}
	for _, u := range delta {
		if uuid, ok := byID[u.ID]; ok && uuid != u.UUID {
			return true
		}
	}
	return false
}

// mergeUsers overlays deltaUsers onto base (keyed by ID). New users are
// appended, existing users have their properties overwritten.
func mergeUsers(base, delta []model.UserSpec) []model.UserSpec {
	// Handle nil slices
	if base == nil {
		base = []model.UserSpec{}
	}
	if delta == nil {
		return base
	}

	m := make(map[int]model.UserSpec, len(base))
	order := make([]int, 0, len(base)+len(delta))
	for _, u := range base {
		if _, ok := m[u.ID]; !ok {
			order = append(order, u.ID)
		}
		m[u.ID] = u
	}
	for _, u := range delta {
		if _, ok := m[u.ID]; !ok {
			order = append(order, u.ID)
		}
		m[u.ID] = u
	}
	out := make([]model.UserSpec, 0, len(m))
	for _, id := range order {
		out = append(out, m[id])
	}
	return out
}

// subtractUsers returns base with all users in delta removed.
func subtractUsers(base, delta []model.UserSpec) []model.UserSpec {
	if base == nil {
		return nil
	}
	if len(delta) == 0 {
		return base
	}
	removeSet := make(map[int]struct{}, len(delta))
	for _, u := range delta {
		removeSet[u.ID] = struct{}{}
	}
	out := make([]model.UserSpec, 0, len(base))
	for _, u := range base {
		if _, ok := removeSet[u.ID]; !ok {
			out = append(out, u)
		}
	}
	return out
}

func (s *Service) trackAndEnforce(ctx context.Context) {
	k := s.activeKernel()
	if k == nil || !k.IsRunning() {
		return
	}

	traffic, aliveIPs, connCount, err := k.GetUserTraffic(ctx)
	if err != nil {
		nlog.Core().Debug("get user traffic failed", "error", err)
		return
	}

	s.tracker.Process(traffic, aliveIPs, connCount)

	// Only log stats if there's actual traffic or connections
	if connCount > 0 || len(traffic) > 0 {
		if s.nodeLog != nil {
			s.nodeLog.Debug(fmt.Sprintf("tracker: %d conns, %d users online", connCount, len(traffic)))
		} else {
			nlog.TrackerStats(connCount, len(traffic))
		}
	}
}

// pushReportAsync sends the report in a background goroutine so the select
// loop is never blocked by slow HTTP. Only one push runs at a time.
func (s *Service) pushReportAsync() {
	if !s.sink.SupportsReporting() {
		return
	}
	if !s.pushActive.CompareAndSwap(false, true) {
		nlog.Core().Debug("push already in progress, skipping")
		return
	}
	if s.pushBackoff.shouldSkip() {
		nlog.Core().Debug("skipping report due to backoff")
		s.pushActive.Store(false)
		return
	}

	traffic := s.tracker.FlushTraffic()
	aliveIPs := s.tracker.FlushAliveIPs()
	online := s.tracker.CurrentOnline()
	status := monitor.Collect()
	metrics := s.buildMetrics(status)
	metrics["kernel_status"] = s.kernelRunning()

	go func() {
		defer s.pushActive.Store(false)
		if err := s.sink.Report(controlplane.ReportPayload{Traffic: traffic, Alive: aliveIPs, Online: online, CPU: status.CPU, Mem: [2]uint64{status.MemTotal, status.MemUsed}, Swap: [2]uint64{status.SwapTotal, status.SwapUsed}, Disk: [2]uint64{status.DiskTotal, status.DiskUsed}, Metrics: metrics}); err != nil {
			nlog.Core().Warn("failed to push report", "error", err)
			if len(traffic) > 0 {
				s.tracker.RestoreTraffic(traffic)
			}
			if len(aliveIPs) > 0 {
				s.tracker.RestoreAliveIPs(aliveIPs)
			}
			s.pushBackoff.onFailure()
			return
		}
		s.pushBackoff.onSuccess()

		nlog.ReportPushed(len(traffic), len(online))
	}()
}

// pushReportSync is used only during shutdown to ensure final data is sent.
func (s *Service) pushReportSync() {
	if !s.sink.SupportsReporting() {
		return
	}
	traffic := s.tracker.FlushTraffic()
	aliveIPs := s.tracker.FlushAliveIPs()
	online := s.tracker.CurrentOnline()
	status := monitor.Collect()
	metrics := s.buildMetrics(status)
	metrics["kernel_status"] = s.kernelRunning()

	if err := s.sink.Report(controlplane.ReportPayload{Traffic: traffic, Alive: aliveIPs, Online: online, CPU: status.CPU, Mem: [2]uint64{status.MemTotal, status.MemUsed}, Swap: [2]uint64{status.SwapTotal, status.SwapUsed}, Disk: [2]uint64{status.DiskTotal, status.DiskUsed}, Metrics: metrics}); err != nil {
		nlog.Core().Warn("failed to push final report", "error", err)
	}
}

// buildMetrics aggregates node-level metrics to be reported to the panel.
// This includes active connections, per-core CPU, GC stats, API call stats,
// WebSocket status, and limiter hit counts.
func (s *Service) buildMetrics(status monitor.Status) map[string]interface{} {
	s.metricsMu.RLock()
	lastUsers := s.lastUsers
	wsClient := s.wsClient
	s.metricsMu.RUnlock()

	m := make(map[string]interface{})
	online := s.tracker.CurrentOnline()

	m["uptime"] = status.Uptime
	m["goroutines"] = status.Goroutines

	// Active connections (last measured during tracker.Process()).
	m["active_connections"] = s.tracker.ActiveConnections()
	m["total_connections"] = s.tracker.TotalConnections()
	m["active_users"] = len(online)
	m["total_users"] = len(lastUsers)

	// Speed
	m["inbound_speed"] = s.tracker.InboundSpeed()
	m["outbound_speed"] = s.tracker.OutboundSpeed()

	// Per-core CPU usage (if available).
	if len(status.CPUPerCore) > 0 {
		m["cpu_per_core"] = status.CPUPerCore
	}

	m["load"] = map[string]interface{}{
		"load1":  status.Load1,
		"load5":  status.Load5,
		"load15": status.Load15,
	}

	// Speed Limiter metrics
	m["speed_limiter"] = map[string]interface{}{
		"has_limits":    s.speedTracker.HasLimits(),
		"limited_users": s.speedTracker.LimitedUserCount(),
	}

	// GC metrics.
	m["gc"] = map[string]interface{}{
		"num_gc":        status.NumGC,
		"last_pause_ms": status.LastPauseMS,
	}

	// API metrics.
	api := s.source.Metrics()
	m["api"] = map[string]interface{}{
		"success": api.Success,
		"failure": api.Failure,
	}

	// WebSocket status.
	wsEnabled := wsClient != nil
	wsConnected := wsEnabled && wsClient.IsConnected()
	m["ws"] = map[string]interface{}{
		"enabled":   wsEnabled,
		"connected": wsConnected,
	}

	// Limiter metrics.
	lm := s.limiter.SnapshotMetrics()
	m["limits"] = map[string]interface{}{
		"device_limit_events": lm.DeviceLimitEvents,
		"speed_limited_users": s.speedTracker.LimitedUserCount(),
	}

	return m
}

// computeConfigHash returns a deterministic hash of the node config.
// It uses JSON marshaling to ensure all fields are captured, ensuring that
// any configuration change correctly triggers a kernel reload.
func computeConfigHash(cfg *model.NodeSpec) string {
	if cfg == nil {
		return ""
	}
	h := sha256.New()
	// We marshal the entire config to be safe. Node config updates are low-frequency,
	// so the robustness of capturing all fields outweighs the micro-performance of manual hashing.
	data, _ := json.Marshal(cfg)
	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// computeUserHash returns a deterministic hash of the user list for change detection.
// Uses direct byte encoding instead of binary.Write to avoid reflection overhead.
func computeUserHash(users []model.UserSpec) string {
	sorted := make([]model.UserSpec, len(users))
	copy(sorted, users)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	h := sha256.New()
	var buf [8]byte
	for _, u := range sorted {
		binary.LittleEndian.PutUint64(buf[:], uint64(u.ID))
		h.Write(buf[:])
		io.WriteString(h, u.UUID)
		binary.LittleEndian.PutUint64(buf[:], uint64(u.SpeedLimit))
		h.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], uint64(u.DeviceLimit))
		h.Write(buf[:])
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// ─── Device management ──────────────────────────────────────────────────

// sendDeviceBatch reports local device snapshot to panel via WS.
func (s *Service) sendDeviceBatch() {
	if s.wsClient == nil || !s.wsClient.IsConnected() {
		return
	}

	devices := s.tracker.FlushAliveIPs()
	// FlushAliveIPs returns nil if no changes since last flush
	if devices == nil {
		nlog.Core().Debug("device snapshot unchanged, skipping")
		return
	}
	s.sink.ReportDevices(s.wsClient, devices)
	nlog.Core().Debug("device snapshot sent", "users", len(devices))
}

// reportDevices periodically reports device snapshot to panel.
func (s *Service) reportDevices() {
	s.sendDeviceBatch()
}
