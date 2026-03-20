package service

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"sort"
	"time"

	"github.com/cedar2025/xboard-node/internal/cert"
	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/kernel/singbox"
	"github.com/cedar2025/xboard-node/internal/kernel/xray"
	"github.com/cedar2025/xboard-node/internal/limiter"
	"github.com/cedar2025/xboard-node/internal/monitor"
	"github.com/cedar2025/xboard-node/internal/panel"
	"github.com/cedar2025/xboard-node/internal/tracker"
)

type Service struct {
	cfg          *config.Config
	panel        *panel.Client
	kernel       kernel.Kernel
	tracker      *tracker.Tracker
	limiter      *limiter.Limiter
	speedTracker *limiter.SpeedTracker
	cert         *cert.Manager

	lastConfig *panel.NodeConfig
	lastUsers  []panel.User

	// appliedState tracks the configuration and users that are currently
	// successfully running in the kernel.
	appliedState struct {
		Config *panel.NodeConfig
		Users  []panel.User
	}

	pushInterval int // seconds
	pullInterval int // seconds

	lastUserHash   string     // hash of user list for change detection
	lastConfigHash string     // hash of full config for change detection
	pullBackoff    apiBackoff // backoff for panel pull failures
	pushBackoff    apiBackoff // backoff for panel push failures

	wsClient       *panel.WSClient           // WebSocket client (nil if WS not enabled)
	wsEvents       chan panel.WSEvent        // receives data events from WS client
	wsStatusCh     chan panel.WSStatusChange // receives WS connect/disconnect notifications
	wsCancel       context.CancelFunc        // cancels the WS client goroutine
	wsDisconnectAt time.Time                 // when WS last disconnected (zero if connected)
}

// apiBackoff implements simple exponential backoff for API failures.
type apiBackoff struct {
	skipRemaining int
}

func (b *apiBackoff) shouldSkip() bool {
	if b.skipRemaining > 0 {
		b.skipRemaining--
		return true
	}
	return false
}

func (b *apiBackoff) onSuccess() { b.skipRemaining = 0 }
func (b *apiBackoff) onFailure() {
	if b.skipRemaining <= 0 {
		b.skipRemaining = 1
	} else if b.skipRemaining < 8 {
		b.skipRemaining *= 2
	}
}

func New(cfg *config.Config) *Service {
	panelClient := panel.NewClient(cfg.Panel)
	certMgr := cert.NewManager(cfg.Cert)

	var k kernel.Kernel
	switch cfg.Kernel.Type {
	case "singbox":
		k = singbox.New(cfg.Kernel)
	case "xray":
		k = xray.New(cfg.Kernel)
	default:
		slog.Error("unsupported kernel type, defaulting to sing-box", "type", cfg.Kernel.Type)
		k = singbox.New(cfg.Kernel)
	}

	l := limiter.New()
	st := limiter.NewSpeedTracker(l)

	return &Service{
		cfg:          cfg,
		panel:        panelClient,
		kernel:       k,
		tracker:      tracker.New(),
		limiter:      l,
		speedTracker: st,
		cert:         certMgr,
		wsEvents:     make(chan panel.WSEvent, 16),
		wsStatusCh:   make(chan panel.WSStatusChange, 4),
	}
}

func (s *Service) Run(ctx context.Context) error {
	// Start cert manager (handles auto-TLS or manual cert verification)
	if err := s.cert.Start(ctx); err != nil {
		return fmt.Errorf("cert manager: %w", err)
	}
	defer s.cert.Stop()

	// Handshake: get WS config + initial data in one call
	if err := s.initialSetup(ctx); err != nil {
		return fmt.Errorf("initial setup: %w", err)
	}
	defer s.kernel.Stop()

	// Set up tickers
	trackTicker := time.NewTicker(10 * time.Second)
	pushInterval := time.Duration(math.Max(float64(s.pushInterval), 5)) * time.Second
	pullInterval := time.Duration(s.pullInterval) * time.Second
	if pullInterval < 10*time.Second {
		pullInterval = 60 * time.Second
	}
	reportTicker := time.NewTicker(pushInterval)
	pullTicker := time.NewTicker(pullInterval)

	slog.Info("tickers initialized", "push", pushInterval, "pull", pullInterval)

	// WS discovery: when in REST-only mode, periodically re-handshake to check
	// if WS has been enabled. When WS is disconnected for too long, re-check
	// if it's still available.
	wsDiscoveryTicker := time.NewTicker(5 * time.Minute)

	defer trackTicker.Stop()
	defer reportTicker.Stop()
	defer pullTicker.Stop()
	defer wsDiscoveryTicker.Stop()

	s.startWSClient(ctx)

	sMode := "disabled"
	if s.wsClient != nil {
		sMode = "connecting"
	}
	slog.Info("service started",
		"kernel", s.kernel.Name(),
		"push_interval", s.pushInterval,
		"pull_interval", s.pullInterval,
		"websocket", sMode,
	)

	for {
		select {
		case <-ctx.Done():
			slog.Info("service shutting down")
			s.pushReport()
			return nil

		case <-trackTicker.C:
			s.trackAndEnforce(ctx)

		case <-reportTicker.C:
			s.pushReport()

		case <-pullTicker.C:
			// When WebSocket is connected, skip REST polling entirely.
			// Config/user updates arrive via WS push.
			if s.wsClient != nil && s.wsClient.IsConnected() {
				slog.Debug("ws connected, skipping REST pull")
				continue
			}
			slog.Info("ws not connected or disabled, polling from API")
			s.pullViaAPI(ctx)

		case <-wsDiscoveryTicker.C:
			s.wsDiscovery(ctx)

		case status := <-s.wsStatusCh:
			s.handleWSStatus(ctx, status)

		case event := <-s.wsEvents:
			s.handleWSEvent(ctx, event)
		}
	}
}

func (s *Service) initialSetup(ctx context.Context) error {
	// Register speed limit lookup with kernel unconditionally (before WS/V1 branch).
	// This ensures speedLimitFunc is set regardless of which code path applies config.
	s.kernel.SetSpeedLimitFunc(s.speedTracker.GetLimiter)

	slog.Info("performing handshake with panel")

	var hs *panel.HandshakeResponse
	var err error

	// Retry loop for initial handshake
	for attempt := 1; ; attempt++ {
		hs, err = s.panel.Handshake()
		if err != nil {
			slog.Error("handshake failed", "attempt", attempt, "error", err)
			if attempt >= 5 {
				return fmt.Errorf("handshake failed after %d attempts: %w", attempt, err)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt*5) * time.Second):
				continue
			}
		}
		break
	}

	// Apply settings from panel handshake (Handshake provides default intervals)
	if s.cfg.Node.PushInterval == 0 && hs.Settings.PushInterval > 0 {
		s.pushInterval = hs.Settings.PushInterval
	} else {
		s.pushInterval = s.cfg.Node.PushInterval
	}
	if s.pushInterval == 0 {
		s.pushInterval = 60
	}

	if s.cfg.Node.PullInterval == 0 && hs.Settings.PullInterval > 0 {
		s.pullInterval = hs.Settings.PullInterval
	} else {
		s.pullInterval = s.cfg.Node.PullInterval
	}
	if s.pullInterval == 0 {
		s.pullInterval = 60
	}

	// If WebSocket is enabled, skip initial V1 APIs fetch and wait for推送
	if hs.WebSocket.Enabled && hs.WebSocket.WSURL != "" {
		s.wsClient = s.newWSClient(hs.WebSocket.WSURL)
		slog.Info("handshake complete (websocket enabled), waiting for data push...",
			"ws_url", hs.WebSocket.WSURL,
		)
		return nil
	}

	// Falls back to V1 APIs only if WebSocket is disabled in panel
	slog.Info("websocket disabled or missing, falling back to V1 APIs")

	// Fetch initial config and users via V1 APIs
	nodeConfig, err := s.panel.GetConfig()
	if err != nil {
		return fmt.Errorf("initial config fetch: %w", err)
	}
	if nodeConfig == nil {
		return fmt.Errorf("initial config is nil")
	}

	users, err := s.panel.GetUsers()
	if err != nil {
		return fmt.Errorf("initial user fetch: %w", err)
	}

	// Apply initial data
	s.lastConfig = nodeConfig
	s.lastUsers = users
	s.lastUserHash = computeUserHash(users)
	s.lastConfigHash = computeConfigHash(nodeConfig)
	s.limiter.UpdateUsers(users)
	s.speedTracker.UpdateBuckets()

	slog.Info("handshake complete (V1 fallback)",
		"protocol", nodeConfig.Protocol,
		"port", nodeConfig.ServerPort,
		"users", len(users),
	)

	if len(users) == 0 {
		slog.Warn("no users, kernel will not start until users are available")
		return nil
	}

	// Update service-level config overrides from remote NodeConfig if present
	s.applyRemoteOverrides(ctx, nodeConfig)

	if err := s.kernel.Start(nodeConfig, users, s.cert.CertFile(), s.cert.KeyFile()); err != nil {
		return fmt.Errorf("start kernel: %w", err)
	}

	// record applied state on success
	s.appliedState.Config = nodeConfig
	s.appliedState.Users = users

	return nil
}

// applyRemoteOverrides updates service-level settings (log level, cert config)
// from the panel's NodeConfig. Returns true if cert paths changed (kernel restart needed).
func (s *Service) applyRemoteOverrides(ctx context.Context, nc *panel.NodeConfig) bool {
	if nc == nil {
		return false
	}

	// Dynamic Log Level (Kernel)
	if nc.KernelLogLevel != "" && nc.KernelLogLevel != s.cfg.Kernel.LogLevel {
		slog.Info("cert: kernel log level override", "old", s.cfg.Kernel.LogLevel, "new", nc.KernelLogLevel)
		s.cfg.Kernel.LogLevel = nc.KernelLogLevel
	}

	// Certificate configuration from panel (panel-first: takes precedence over local config)
	if nc.CertConfig != nil {
		return s.applyPanelCert(ctx, nc.CertConfig)
	}

	// Legacy fields (deprecated: prefer cert_config)
	if nc.AutoTLS != s.cfg.Cert.AutoTLS {
		slog.Info("cert: auto_tls policy changed (deprecated field)", "new", nc.AutoTLS)
		s.cfg.Cert.AutoTLS = nc.AutoTLS
	}
	if nc.Domain != "" && nc.Domain != s.cfg.Cert.Domain {
		s.cfg.Cert.Domain = nc.Domain
	}

	return false
}

// applyPanelCert converts a panel CertConfig into the local config format and
// reconfigures the cert manager. Reports whether cert paths changed.
func (s *Service) applyPanelCert(ctx context.Context, pc *panel.CertConfig) bool {
	newCfg := config.CertConfig{
		CertMode:    pc.CertMode,
		Domain:      pc.Domain,
		Email:       pc.Email,
		DNSProvider: pc.DNSProvider,
		DNSEnv:      pc.DNSEnv,
		HTTPPort:    pc.HTTPPort,
		CertFile:    pc.CertFile,
		KeyFile:     pc.KeyFile,
		CertContent: pc.CertContent,
		KeyContent:  pc.KeyContent,
		// Preserve local storage dir — only the operator controls where certs live.
		CertDir: s.cfg.Cert.CertDir,
	}

	changed, err := s.cert.Reconfigure(ctx, newCfg)
	if err != nil {
		slog.Error("failed to apply panel cert config", "mode", pc.CertMode, "error", err)
		return false
	}
	s.cfg.Cert = newCfg
	if changed {
		slog.Info("cert: paths updated from panel", "cert", s.cert.CertFile(), "key", s.cert.KeyFile())
	}
	return changed
}

// startWSClient starts the WS client goroutine if a client is configured.
func (s *Service) startWSClient(ctx context.Context) {
	if s.wsClient == nil {
		return
	}
	wsCtx, wsCancel := context.WithCancel(ctx)
	s.wsCancel = wsCancel
	go s.wsClient.Run(wsCtx)
}

// newWSClient creates a WSClient with standard event/status callbacks.
func (s *Service) newWSClient(wsURL string) *panel.WSClient {
	return panel.NewWSClient(
		wsURL,
		s.cfg.Panel.Token,
		s.cfg.Panel.NodeID,
		func(event panel.WSEvent) {
			select {
			case s.wsEvents <- event:
			default:
				slog.Warn("ws event channel full, dropping event", "type", event.Type)
			}
		},
		func(status panel.WSStatusChange) {
			select {
			case s.wsStatusCh <- status:
			default:
			}
		},
		func() map[string]interface{} {
			status := monitor.Collect()
			m := s.buildMetrics(status)
			m["kernel_status"] = s.kernel.IsRunning()
			return m
		},
	)
}

// handleWSStatus reacts to WS connectivity changes.
//
// - On disconnect: record timestamp, immediately REST poll.
// - On reconnect: clear disconnect timestamp, REST poll to catch missed events.
func (s *Service) handleWSStatus(ctx context.Context, status panel.WSStatusChange) {
	if status.Connected {
		s.wsDisconnectAt = time.Time{}
		slog.Info("ws connected, waiting for server-side full sync push")
		// No REST pull needed — server detects new connection and pushes
		// full config + users automatically on auth success.
	} else {
		if s.wsDisconnectAt.IsZero() {
			s.wsDisconnectAt = time.Now()
		}
		slog.Info("ws disconnected, falling back to REST polling")
		s.pullViaAPI(ctx)
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
	needsCheck := false

	if s.wsClient == nil {
		needsCheck = true
		slog.Debug("ws discovery: no WS client, checking if panel enabled WS")
	} else if !s.wsDisconnectAt.IsZero() && time.Since(s.wsDisconnectAt) > 10*time.Minute {
		needsCheck = true
		slog.Debug("ws discovery: WS disconnected for >10min, re-checking WS config")
	}

	if !needsCheck {
		return
	}

	hs, err := s.panel.Handshake()
	if err != nil {
		slog.Debug("ws discovery: handshake failed", "error", err)
		return
	}

	// Apply any latest config/user changes via dedicated APIs
	s.pullViaAPI(ctx)

	if hs.WebSocket.Enabled && hs.WebSocket.WSURL != "" {
		if s.wsClient == nil {
			slog.Info("ws discovery: panel has WS enabled, creating WS client")
			s.wsClient = s.newWSClient(hs.WebSocket.WSURL)
			s.wsDisconnectAt = time.Time{}
			s.startWSClient(ctx)
		}
	} else if s.wsClient != nil {
		slog.Info("ws discovery: panel disabled WS, switching to REST-only")
		if s.wsCancel != nil {
			s.wsCancel()
		}
		s.wsClient = nil
		s.wsCancel = nil
		s.wsDisconnectAt = time.Time{}
	}
}

// handleWSEvent processes data events received via WebSocket
func (s *Service) handleWSEvent(ctx context.Context, event panel.WSEvent) {
	switch event.Type {
	case panel.WSEventSyncConfig:
		if event.Config == nil {
			slog.Warn("ws: sync.config event with nil config, ignoring")
			return
		}
		newConfigHash := computeConfigHash(event.Config)
		if newConfigHash == s.lastConfigHash {
			slog.Debug("ws: config unchanged (same hash), skipping")
			return
		}
		slog.Info("ws: applying config update", "protocol", event.Config.Protocol)
		s.lastConfig = event.Config
		s.lastConfigHash = newConfigHash
		s.applyRemoteOverrides(ctx, event.Config)
		s.applyChanges(ctx, true, false)

	case panel.WSEventSyncUsers:
		if event.Users == nil {
			slog.Warn("ws: sync.users event with nil users, ignoring")
			return
		}
		newHash := computeUserHash(event.Users)
		if newHash == s.lastUserHash {
			slog.Debug("ws: users unchanged (same hash), skipping")
			return
		}
		slog.Info("ws: applying user update", "count", len(event.Users))
		s.applyUserUpdate(ctx, event.Users, newHash)

	case panel.WSEventSyncUserDelta:
		if len(event.DeltaUsers) == 0 {
			slog.Warn("ws: sync.user.delta event with empty users, ignoring")
			return
		}
		slog.Info("ws: applying user delta", "action", event.DeltaAction, "count", len(event.DeltaUsers))
		s.applyUserDelta(ctx, event.DeltaAction, event.DeltaUsers)

	default:
		slog.Debug("ws: unknown event type", "type", event.Type)
	}
}

// pullViaAPI re-calls the config and user APIs for polling fallback.
// Also opportunistically detects WS enablement when in REST-only mode.
func (s *Service) pullViaAPI(ctx context.Context) {
	if s.pullBackoff.shouldSkip() {
		slog.Debug("skipping pull due to backoff")
		return
	}

	config, err := s.panel.GetConfig()
	if err != nil {
		slog.Error("poll config failed", "error", err)
		s.pullBackoff.onFailure()
		return
	}

	users, err := s.panel.GetUsers()
	if err != nil {
		slog.Error("poll users failed", "error", err)
		s.pullBackoff.onFailure()
		return
	}

	s.pullBackoff.onSuccess()

	configChanged := false

	if s.cert.CertRenewed() {
		slog.Info("certificate renewed, kernel restart needed")
		configChanged = true
	}

	if config != nil {
		newConfigHash := computeConfigHash(config)
		if s.lastConfigHash != newConfigHash {
			configChanged = true
			slog.Info("config updated from panel",
				"protocol", config.Protocol, "port", config.ServerPort)
			s.lastConfig = config
			s.lastConfigHash = newConfigHash
			// Apply kernel overrides and cert updates from REST pull
			if s.applyRemoteOverrides(ctx, config) {
				configChanged = true // Restart kernel if cert paths changed
			}
		}
	}

	if users != nil {
		newHash := computeUserHash(users)
		usersChanged := newHash != s.lastUserHash

		if usersChanged && !configChanged {
			s.applyUserUpdate(ctx, users, newHash)
		} else if usersChanged {
			// Config is also changing — Start will restart the kernel with the
			// updated user list, so skip the intermediate UpdateUsers.
			s.updateUserState(users)
		}
	}

	if configChanged {
		s.applyChanges(ctx, true, false)
	}
}

// ─── User state helpers ─────────────────────────────────────────────────────

// updateUserState is the single point that refreshes limiter, speedTracker,
// and the cached user list/hash. Every code path that changes the user set
// MUST go through here to keep the three data structures in sync.
func (s *Service) updateUserState(users []panel.User) {
	s.limiter.UpdateUsers(users)
	s.speedTracker.UpdateBuckets()
	s.lastUsers = users
	s.lastUserHash = computeUserHash(users)
}

// startKernel starts (or restarts) the kernel with the given config/users and
// records the successfully applied state. Returns false on error.
func (s *Service) startKernel(nc *panel.NodeConfig, users []panel.User) bool {
	if err := s.kernel.Start(nc, users, s.cert.CertFile(), s.cert.KeyFile()); err != nil {
		slog.Error("failed to start kernel", "error", err)
		return false
	}

	s.appliedState.Config = nc
	s.appliedState.Users = users

	slog.Info("kernel started successfully",
		"node_id", s.cfg.Panel.NodeID,
		"protocol", nc.Protocol,
		"port", nc.ServerPort,
		"users", len(users),
	)
	return true
}

// ensureRunning starts the kernel if it is not running and there are users +
// config available. Returns true if the kernel is running afterwards.
func (s *Service) ensureRunning() bool {
	if s.kernel.IsRunning() {
		return true
	}
	if len(s.lastUsers) > 0 && s.lastConfig != nil {
		return s.startKernel(s.lastConfig, s.lastUsers)
	}
	return false
}

// ─── User update entry points ───────────────────────────────────────────────

// applyUserUpdate replaces the full user set and hot-swaps the kernel.
// Called from WS sync.users and REST polling.
func (s *Service) applyUserUpdate(ctx context.Context, users []panel.User, newHash string) {
	// Update limiter/speed state first so even if kernel ops fail,
	// the in-memory limits are already correct.
	s.updateUserState(users)

	if !s.ensureRunning() {
		return
	}

	added, removed, err := s.kernel.UpdateUsers(users)
	if err != nil {
		slog.Warn("UpdateUsers failed, falling back to full restart", "error", err)
		s.startKernel(s.lastConfig, users)
		return
	}
	slog.Info("users updated via kernel", "added", added, "removed", removed)
}

// applyUserDelta applies an incremental user change (add or remove) directly
// via the kernel's atomic user API.
func (s *Service) applyUserDelta(ctx context.Context, action string, deltaUsers []panel.User) {
	switch action {
	case "add":
		merged := mergeUsers(s.lastUsers, deltaUsers)
		s.updateUserState(merged)

		if !s.ensureRunning() {
			return
		}

		added, err := s.kernel.AddUsers(deltaUsers)
		if err != nil {
			slog.Warn("AddUsers failed, falling back to full UpdateUsers", "error", err)
			if _, _, err := s.kernel.UpdateUsers(merged); err != nil {
				slog.Error("UpdateUsers fallback also failed", "error", err)
			}
		} else {
			slog.Info("users added via kernel", "added", added)
		}

	case "remove":
		filtered := subtractUsers(s.lastUsers, deltaUsers)
		s.updateUserState(filtered)

		if !s.kernel.IsRunning() {
			return
		}

		removed, err := s.kernel.RemoveUsers(deltaUsers)
		if err != nil {
			slog.Warn("RemoveUsers failed, falling back to full UpdateUsers", "error", err)
			if _, _, err := s.kernel.UpdateUsers(filtered); err != nil {
				slog.Error("UpdateUsers fallback also failed", "error", err)
			}
		} else {
			slog.Info("users removed via kernel", "removed", removed)
		}

	default:
		slog.Warn("ws: unknown user delta action", "action", action)
	}
}

// mergeUsers overlays deltaUsers onto base (keyed by ID). New users are
// appended, existing users have their properties overwritten.
func mergeUsers(base, delta []panel.User) []panel.User {
	m := make(map[int]panel.User, len(base))
	for _, u := range base {
		m[u.ID] = u
	}
	for _, u := range delta {
		m[u.ID] = u
	}
	out := make([]panel.User, 0, len(m))
	for _, u := range m {
		out = append(out, u)
	}
	return out
}

// subtractUsers returns base with all users in delta removed.
func subtractUsers(base, delta []panel.User) []panel.User {
	removeSet := make(map[int]struct{}, len(delta))
	for _, u := range delta {
		removeSet[u.ID] = struct{}{}
	}
	out := make([]panel.User, 0, len(base))
	for _, u := range base {
		if _, ok := removeSet[u.ID]; !ok {
			out = append(out, u)
		}
	}
	return out
}

// applyChanges applies config changes to the kernel. User-only changes are
// handled by applyUserUpdate/applyUserDelta directly via the atomic user API.
func (s *Service) applyChanges(ctx context.Context, configChanged, usersChanged bool) {
	if !configChanged {
		return
	}

	if s.lastConfig == nil || len(s.lastUsers) == 0 {
		if len(s.lastUsers) == 0 {
			slog.Warn("no users, stopping kernel")
			s.kernel.Stop()
			s.appliedState.Users = nil
		}
		return
	}

	// If config changed, delegate to kernel.Reload. The kernel implementation
	// decides whether to hot-swap users, reconstruct inbounds, or restart itself.
	if configChanged && s.kernel.IsRunning() {
		if err := s.kernel.Reload(s.lastConfig, s.lastUsers, s.cert.CertFile(), s.cert.KeyFile()); err != nil {
			slog.Warn("reload failed, falling back to full restart", "error", err)
			s.startKernel(s.lastConfig, s.lastUsers)
		} else {
			s.appliedState.Config = s.lastConfig
			s.appliedState.Users = s.lastUsers
		}
	} else if !s.kernel.IsRunning() {
		s.startKernel(s.lastConfig, s.lastUsers)
	}
}

// updateUserState is the single point that refreshes limiter, speedTracker,

func (s *Service) trackAndEnforce(ctx context.Context) {
	if !s.kernel.IsRunning() {
		return
	}

	conns, err := s.kernel.GetConnections(ctx)
	if err != nil {
		slog.Debug("get connections failed", "error", err)
		return
	}

	s.tracker.Process(conns)
	s.tracker.LogStats()
	slog.Debug("kernel connection snapshot", "count", len(conns))

	kicks := s.limiter.Check(conns)
	s.executeKicks(ctx, kicks)
}

func (s *Service) executeKicks(ctx context.Context, kicks []limiter.KickAction) {
	for _, kick := range kicks {
		slog.Info("kicking connection",
			"user_id", kick.UserID,
			"conn_id", kick.ConnID,
			"reason", kick.Reason,
		)
		if err := s.kernel.CloseConnection(ctx, kick.ConnID); err != nil {
			slog.Error("failed to close connection", "conn_id", kick.ConnID, "error", err)
		}
	}
}

// pushReport sends consolidated traffic + alive + status to the panel.
// When WebSocket is connected, node.status is already sent every 10s via WS,
// so we still push the full report (traffic/alive/online) but at the normal
// pushInterval — the panel deduplicates metrics from both channels.
func (s *Service) pushReport() {
	if s.pushBackoff.shouldSkip() {
		slog.Debug("skipping report due to backoff")
		return
	}

	traffic := s.tracker.FlushTraffic()
	aliveIPs := s.tracker.FlushAliveIPs()
	online := s.tracker.FlushOnline()
	status := monitor.Collect()

	metrics := s.buildMetrics(status)
	metrics["kernel_status"] = s.kernel.IsRunning()

	// Always report even if no traffic, to maintain heartbeats and status.
	if err := s.panel.Report(
		traffic, aliveIPs, online,
		status.CPU,
		[2]uint64{status.MemTotal, status.MemUsed},
		[2]uint64{status.SwapTotal, status.SwapUsed},
		[2]uint64{status.DiskTotal, status.DiskUsed},
		metrics,
	); err != nil {
		slog.Error("failed to push report", "error", err)
		if len(traffic) > 0 {
			s.tracker.RestoreTraffic(traffic)
		}
		if len(aliveIPs) > 0 {
			s.tracker.RestoreAliveIPs(aliveIPs)
		}
		if len(online) > 0 {
			s.tracker.RestoreOnline(online)
		}
		s.pushBackoff.onFailure()
		return
	}

	s.pushBackoff.onSuccess()
	slog.Info("report pushed", "users_with_traffic", len(traffic), "online_devices", len(online))
}

// buildMetrics aggregates node-level metrics to be reported to the panel.
// This includes active connections, per-core CPU, GC stats, API call stats,
// WebSocket status, and limiter hit counts.
func (s *Service) buildMetrics(status monitor.Status) map[string]interface{} {
	m := make(map[string]interface{})
	online := s.tracker.CurrentOnline()

	m["uptime"] = status.Uptime
	m["goroutines"] = status.Goroutines

	// Active connections (last measured during tracker.Process()).
	m["active_connections"] = s.tracker.ActiveConnections()
	m["total_connections"] = s.tracker.TotalConnections()
	m["active_users"] = len(online)
	m["total_users"] = len(s.lastUsers)

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
	api := s.panel.SnapshotMetrics()
	m["api"] = map[string]interface{}{
		"success": api.Success,
		"failure": api.Failure,
	}

	// WebSocket status.
	wsEnabled := s.wsClient != nil
	wsConnected := wsEnabled && s.wsClient.IsConnected()
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
func computeConfigHash(cfg *panel.NodeConfig) string {
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
func computeUserHash(users []panel.User) string {
	sorted := make([]panel.User, len(users))
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
