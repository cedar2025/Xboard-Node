package singbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	singLog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	singJSON "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"golang.org/x/time/rate"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

// drainTimeout is how long stop() waits for in-flight connections to finish
// naturally after closing all listen sockets, before hard-killing them.
const drainTimeout = 5 * time.Second

// SingBox implements kernel.Kernel by embedding sing-box as a Go library.
//
// User operations (AddUsers/RemoveUsers/UpdateUsers) use sing-box's native
// UpdatableInbound interface, which hot-swaps user credentials without
// restarting listeners — zero connection disruption.
type SingBox struct {
	cfg config.KernelConfig

	mu     sync.RWMutex
	box    *box.Box
	ctx    context.Context
	cancel context.CancelFunc

	users      []model.UserSpec
	nodeConfig *model.NodeSpec
	tls        kernel.TLSCert

	// connTracker is our lightweight in-process byte/IP tracker.
	// Created fresh on every Start (full restart).
	// Survives Reload (hot-swap) since live connections persist.
	connTracker *ConnTracker

	// speedLimitFunc resolves a user UUID to a *rate.Limiter.
	// Set once by SetSpeedLimitFunc and forwarded to every new ConnTracker.
	speedLimitFunc func(string) *rate.Limiter
	// uploadLimitFunc resolves a user UUID to their upload limiter.
	uploadLimitFunc func(string) *rate.Limiter

	// deviceLimitFunc resolves a user UUID to (limit, hasLimit) for gate-keeping.
	// Set once by SetDeviceLimitFunc and forwarded to every new ConnTracker.
	deviceLimitFunc func(string) (int, bool)

	// trackerRegistered prevents duplicate AppendTracker calls on the same
	// Router instance during Reload. Reset to false on full restart.
	trackerRegistered bool
}

func New(cfg config.KernelConfig) *SingBox {
	return &SingBox{cfg: cfg}
}

var _ kernel.Kernel = (*SingBox)(nil)

func (s *SingBox) Name() string { return "sing-box" }

func (s *SingBox) Capabilities() kernel.Capabilities {
	return kernel.Capabilities{
		PerUserSpeedLimit:    true,
		DeviceLimit:          true,
		BuiltInTrafficStats:  false,
		AliveIPTracking:      true,
		ForceCloseConnection: false,
		ForceCloseUser:       true,
	}
}

func (s *SingBox) Protocols() []string {
	return []string{
		"vmess", "vless", "trojan", "shadowsocks",
		"hysteria", "hysteria2", "tuic", "naive", "socks", "http", "anytls", "mieru",
	}
}

func (s *SingBox) Start(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfgMap := buildConfig(s.cfg, nodeConfig, users, tls)
	data, err := json.Marshal(cfgMap)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	nlog.Core().Debug("sing-box config generated", "len", len(data))

	ctx, cancel := context.WithCancel(context.Background())
	ctx = include.Context(ctx)

	opts, err := singJSON.UnmarshalExtendedContext[option.Options](ctx, data)
	if err != nil {
		cancel()
		return fmt.Errorf("parse sing-box options: %w", err)
	}

	// Save old state before creating the new instance.
	oldBox := s.box
	oldCancel := s.cancel
	oldCtx := s.ctx
	oldTracker := s.connTracker

	instance, err := box.New(box.Options{
		Context: ctx,
		Options: opts,
	})
	if err != nil {
		cancel()
		return fmt.Errorf("create sing-box instance: %w", err)
	}

	if err := instance.Start(); err != nil {
		instance.Close()
		cancel()
		return fmt.Errorf("start sing-box: %w", err)
	}

	// New instance started successfully — swap state.
	s.box = instance
	s.ctx = ctx
	s.cancel = cancel
	s.users = users
	s.nodeConfig = nodeConfig
	s.tls = tls

	// Fresh tracker on full restart.
	s.connTracker = NewConnTracker(0)
	s.connTracker.SetManagedInbound(inboundTag(nodeConfig))
	s.connTracker.SetUserMap(buildUserMap(users))
	if s.speedLimitFunc != nil {
		s.connTracker.SetSpeedLimitFunc(s.speedLimitFunc)
	}
	if s.uploadLimitFunc != nil {
		s.connTracker.SetUploadLimitFunc(s.uploadLimitFunc)
	}
	if s.deviceLimitFunc != nil {
		s.connTracker.SetDeviceLimitFunc(s.deviceLimitFunc)
	}

	s.trackerRegistered = false
	s.registerTracker(ctx)

	// Recycle old instance in background — drain then close.
	if oldBox != nil {
		go recycleOldBox(oldBox, oldCancel, oldCtx, oldTracker)
	}

	nlog.Core().Debug("sing-box started", "users", len(users))
	return nil
}

// recycleOldBox gracefully shuts down a previous sing-box instance in the
// background. It closes listen sockets first, waits for connections to drain,
// then hard-closes. This avoids blocking the new instance's startup.
func recycleOldBox(oldBox *box.Box, oldCancel context.CancelFunc, oldCtx context.Context, oldTracker *ConnTracker) {
	// Step 1: close listen sockets so no new connections arrive on old ports.
	if im := service.FromContext[adapter.InboundManager](oldCtx); im != nil {
		_ = im.Close()
	}

	// Step 2: drain in-flight connections (best-effort).
	if oldTracker != nil {
		deadline := time.Now().Add(drainTimeout)
		for time.Now().Before(deadline) {
			if oldTracker.ActiveCount() == 0 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Step 3: hard-close everything.
	oldBox.Close()
	if oldCancel != nil {
		oldCancel()
	}
	nlog.Core().Debug("sing-box: old instance recycled")
}

// Reload hot-swaps the inbound users and routing rules without restarting the box.
// Routes, outbounds, and the connTracker stay alive so in-flight connections
// continue to be tracked correctly.
func (s *SingBox) Reload(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return fmt.Errorf("not running")
	}

	cfgMap := buildConfig(s.cfg, nodeConfig, users, tls)
	data, err := json.Marshal(cfgMap)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	opts, err := singJSON.UnmarshalExtendedContext[option.Options](s.ctx, data)
	if err != nil {
		return fmt.Errorf("parse options: %w", err)
	}

	im := service.FromContext[adapter.InboundManager](s.ctx)
	if im == nil {
		return fmt.Errorf("inbound manager not available")
	}

	router := service.FromContext[adapter.Router](s.ctx)
	if router == nil {
		return fmt.Errorf("router not available")
	}

	// Update routing rules
	if err := router.UpdateRules(opts.Route.Rules, opts.Route.RuleSet); err != nil {
		nlog.Core().Debug("routing reload failed", "error", err)
	} else {
		nlog.Core().Debug("sing-box routing reloaded")
	}

	nopFactory := singLog.NewNOPFactory()

	// Configuration hash check for inbound reconstruction
	tlsChanged := !bytes.Equal(s.tls.CertPEM, tls.CertPEM) || !bytes.Equal(s.tls.KeyPEM, tls.KeyPEM)
	configChanged := tlsChanged || s.nodeConfig == nil || kernel.ComputeHash(nodeConfig, users) != kernel.ComputeHash(s.nodeConfig, s.users)

	for _, inb := range opts.Inbounds {
		tag := inb.Tag
		if !configChanged {
			if existing, ok := im.Get(tag); ok && existing.Type() == inb.Type {
				var err error
				switch v := existing.(type) {
				case adapter.UpdatableInbound[option.VMessUser]:
					if opts, ok := inb.Options.(*option.VMessInboundOptions); ok {
						err = v.UpdateUsers(opts.Users)
					}
				case adapter.UpdatableInbound[option.VLESSUser]:
					if opts, ok := inb.Options.(*option.VLESSInboundOptions); ok {
						err = v.UpdateUsers(opts.Users)
					}
				case adapter.UpdatableInbound[option.TrojanUser]:
					if opts, ok := inb.Options.(*option.TrojanInboundOptions); ok {
						err = v.UpdateUsers(opts.Users)
					}
				case adapter.UpdatableInbound[option.Hysteria2User]:
					if opts, ok := inb.Options.(*option.Hysteria2InboundOptions); ok {
						err = v.UpdateUsers(opts.Users)
					}
				case adapter.UpdatableShadowsocksInbound:
					if opts, ok := inb.Options.(*option.ShadowsocksInboundOptions); ok {
						err = v.UpdateUsersByOptions(opts.Users)
					}
				case adapter.UpdatableInbound[option.TUICUser]:
					if opts, ok := inb.Options.(*option.TUICInboundOptions); ok {
						err = v.UpdateUsers(opts.Users)
					}
				case adapter.UpdatableInbound[option.AnyTLSUser]:
					if opts, ok := inb.Options.(*option.AnyTLSInboundOptions); ok {
						err = v.UpdateUsers(opts.Users)
					}
				case adapter.UpdatableInbound[option.MieruUser]:
					if opts, ok := inb.Options.(*option.MieruInboundOptions); ok {
						err = v.UpdateUsers(opts.Users)
					}
				case adapter.UpdatableInbound[auth.User]:
					switch opts := inb.Options.(type) {
					case *option.NaiveInboundOptions:
						err = v.UpdateUsers(opts.Users)
					case *option.SocksInboundOptions:
						err = v.UpdateUsers(opts.Users)
					case *option.HTTPMixedInboundOptions:
						err = v.UpdateUsers(opts.Users)
					}
				}
				if err == nil {
					continue
				}
				nlog.Core().Warn("incremental update failed, falling back to recreate", "tag", tag, "error", err)
			}
		}

		// Config mismatch or incremental update failure: Reconstruct Inbound.
		// Remove the existing inbound first so im.Create() can bind the same port.
		// im.Create() cannot atomically swap a TCP listener — it tries to start the
		// new socket before the old one is closed, causing "address already in use".
		// The brief listen gap (< 1 ms) is far less disruptive than a full restart.
		_ = im.Remove(tag) // ignore error when tag doesn't exist yet
		logger := nopFactory.NewLogger(fmt.Sprintf("inbound/%s[%s]", inb.Type, tag))
		if err := im.Create(s.ctx, router, logger, tag, inb.Type, inb.Options); err != nil {
			return fmt.Errorf("recreate inbound %s: %w", tag, err)
		}
	}

	// Trackers remain registered on the Router (which survives ReloadUsers).
	// Only update the user map — do NOT re-register or traffic is double-counted.
	if s.connTracker != nil {
		s.connTracker.SetManagedInbound(inboundTag(nodeConfig))
		s.connTracker.SetUserMap(buildUserMap(users))
	}

	nlog.Core().Debug("sing-box reloaded", "users", len(users))
	s.users = users
	s.nodeConfig = nodeConfig
	s.tls = tls
	return nil
}

// registerTracker wires the ConnTracker to the current Router exactly once.
// The ConnTracker handles both byte counting and optional rate limiting
// in a single wrapper, so no additional trackers are needed.
func (s *SingBox) registerTracker(ctx context.Context) {
	if s.trackerRegistered {
		return
	}
	router := service.FromContext[adapter.Router](ctx)
	if router == nil {
		return
	}
	if s.connTracker != nil {
		router.AppendTracker(s.connTracker)
	}
	s.trackerRegistered = true
}

func (s *SingBox) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stop()
}

func (s *SingBox) stop() {
	if s.box == nil {
		return
	}

	// Step 1: close all listen sockets so no new connections are accepted.
	// im.Close() sets m.started=false so the subsequent box.Close() call is a no-op
	// for inbounds (avoids double-close), but box.Close() still tears down routers
	// and outbounds.
	if im := service.FromContext[adapter.InboundManager](s.ctx); im != nil {
		_ = im.Close()
	}

	// Step 2: wait for in-flight connections to drain naturally (best-effort).
	if s.connTracker != nil {
		deadline := time.Now().Add(drainTimeout)
		for time.Now().Before(deadline) {
			if s.connTracker.ActiveCount() == 0 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Step 3: hard-close everything that is still open.
	s.box.Close()
	s.box = nil
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	s.ctx = nil
}

func (s *SingBox) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.box != nil
}

// connTrackerLocked returns the connTracker under a read-optimised lock.
func (s *SingBox) connTrackerSafe() *ConnTracker {
	s.mu.Lock()
	ct := s.connTracker
	s.mu.Unlock()
	return ct
}

// SetSpeedLimitFunc configures per-user bandwidth throttling.
func (s *SingBox) SetSpeedLimitFunc(fn func(uuid string) *rate.Limiter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.speedLimitFunc = fn
	if s.connTracker != nil {
		s.connTracker.SetSpeedLimitFunc(fn)
	}
}

// SetUploadLimitFunc configures the per-user upload limiter.
func (s *SingBox) SetUploadLimitFunc(fn func(uuid string) *rate.Limiter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.uploadLimitFunc = fn
	if s.connTracker != nil {
		s.connTracker.SetUploadLimitFunc(fn)
	}
}

// SetDeviceLimitFunc configures per-user device limit gate-keeping.
// Connections exceeding the limit are rejected at connect time.
func (s *SingBox) SetDeviceLimitFunc(fn func(uuid string) (int, bool)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deviceLimitFunc = fn
	if s.connTracker != nil {
		s.connTracker.SetDeviceLimitFunc(fn)
	}
}

// UpdateGlobalDevices updates the global device state from panel (for multi-node).
func (s *SingBox) UpdateGlobalDevices(users map[int][]string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.connTracker != nil {
		s.connTracker.UpdateGlobalDevices(users)
	}
}

// ClearGlobalDevices clears the global device state (on WS disconnect).
func (s *SingBox) ClearGlobalDevices() {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.connTracker != nil {
		s.connTracker.ClearGlobalDevices()
	}
}

// ─── User management (non-disruptive) ───────────────────────────────────────

// AddUsers hot-swaps users into running inbounds. Zero connection disruption.
func (s *SingBox) AddUsers(users []model.UserSpec) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return 0, fmt.Errorf("not running")
	}

	existing := make(map[int]struct{}, len(s.users))
	for _, u := range s.users {
		existing[u.ID] = struct{}{}
	}
	var toAdd []model.UserSpec
	for _, u := range users {
		if _, dup := existing[u.ID]; !dup {
			toAdd = append(toAdd, u)
		}
	}
	if len(toAdd) == 0 {
		return 0, nil
	}

	merged := append(append([]model.UserSpec{}, s.users...), toAdd...)
	if err := s.reloadInboundsLocked(merged); err != nil {
		return 0, err
	}
	s.users = merged
	return len(toAdd), nil
}

// RemoveUsers hot-swaps users out of running inbounds. Zero connection disruption
// for remaining users.
func (s *SingBox) RemoveUsers(users []model.UserSpec) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return 0, fmt.Errorf("not running")
	}

	removeSet := make(map[int]struct{}, len(users))
	for _, u := range users {
		removeSet[u.ID] = struct{}{}
	}
	var kept []model.UserSpec
	removed := 0
	for _, u := range s.users {
		if _, rm := removeSet[u.ID]; rm {
			removed++
		} else {
			kept = append(kept, u)
		}
	}
	if removed == 0 {
		return 0, nil
	}

	if err := s.reloadInboundsLocked(kept); err != nil {
		return 0, err
	}
	s.users = kept
	return removed, nil
}

// UpdateUsers replaces the entire user set atomically via hot-swap.
func (s *SingBox) UpdateUsers(users []model.UserSpec) (added, removed int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return 0, 0, fmt.Errorf("not running")
	}

	toAdd, toRemove := kernel.UserDiff(s.users, users)
	added, removed = len(toAdd), len(toRemove)

	if added == 0 && removed == 0 {
		// Only limits may have changed — update tracker map.
		if s.connTracker != nil {
			s.connTracker.SetUserMap(buildUserMap(users))
		}
		s.users = users
		return 0, 0, nil
	}

	if err = s.reloadInboundsLocked(users); err != nil {
		return 0, 0, err
	}
	s.users = users
	return
}

// reloadInboundsLocked hot-swaps inbound users using UpdatableInbound.
// Must be called with s.mu held.
func (s *SingBox) reloadInboundsLocked(users []model.UserSpec) error {
	cfgMap := buildConfig(s.cfg, s.nodeConfig, users, s.tls)
	data, err := json.Marshal(cfgMap)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	opts, err := singJSON.UnmarshalExtendedContext[option.Options](s.ctx, data)
	if err != nil {
		return fmt.Errorf("parse options: %w", err)
	}

	im := service.FromContext[adapter.InboundManager](s.ctx)
	if im == nil {
		return fmt.Errorf("inbound manager not available")
	}

	router := service.FromContext[adapter.Router](s.ctx)
	if router == nil {
		return fmt.Errorf("router not available")
	}

	nopFactory := singLog.NewNOPFactory()

	for _, inb := range opts.Inbounds {
		tag := inb.Tag
		if existing, ok := im.Get(tag); ok && existing.Type() == inb.Type {
			var err error
			switch v := existing.(type) {
			case adapter.UpdatableInbound[option.VMessUser]:
				if opts, ok := inb.Options.(*option.VMessInboundOptions); ok {
					err = v.UpdateUsers(opts.Users)
				}
			case adapter.UpdatableInbound[option.VLESSUser]:
				if opts, ok := inb.Options.(*option.VLESSInboundOptions); ok {
					err = v.UpdateUsers(opts.Users)
				}
			case adapter.UpdatableInbound[option.TrojanUser]:
				if opts, ok := inb.Options.(*option.TrojanInboundOptions); ok {
					err = v.UpdateUsers(opts.Users)
				}
			case adapter.UpdatableInbound[option.Hysteria2User]:
				if opts, ok := inb.Options.(*option.Hysteria2InboundOptions); ok {
					err = v.UpdateUsers(opts.Users)
				}
			case adapter.UpdatableShadowsocksInbound:
				if opts, ok := inb.Options.(*option.ShadowsocksInboundOptions); ok {
					err = v.UpdateUsersByOptions(opts.Users)
				}
			case adapter.UpdatableInbound[option.TUICUser]:
				if opts, ok := inb.Options.(*option.TUICInboundOptions); ok {
					err = v.UpdateUsers(opts.Users)
				}
			case adapter.UpdatableInbound[option.AnyTLSUser]:
				if opts, ok := inb.Options.(*option.AnyTLSInboundOptions); ok {
					err = v.UpdateUsers(opts.Users)
				}
			case adapter.UpdatableInbound[option.MieruUser]:
				if opts, ok := inb.Options.(*option.MieruInboundOptions); ok {
					err = v.UpdateUsers(opts.Users)
				}
			case adapter.UpdatableInbound[auth.User]:
				switch opts := inb.Options.(type) {
				case *option.NaiveInboundOptions:
					err = v.UpdateUsers(opts.Users)
				case *option.SocksInboundOptions:
					err = v.UpdateUsers(opts.Users)
				case *option.HTTPMixedInboundOptions:
					err = v.UpdateUsers(opts.Users)
				}
			}
			if err == nil {
				continue
			}
			nlog.Core().Warn("incremental update failed, recreating inbound", "tag", tag, "error", err)
		}

		_ = im.Remove(tag)
		logger := nopFactory.NewLogger(fmt.Sprintf("inbound/%s[%s]", inb.Type, tag))
		if err := im.Create(s.ctx, router, logger, tag, inb.Type, inb.Options); err != nil {
			return fmt.Errorf("recreate inbound %s: %w", tag, err)
		}
	}

	if s.connTracker != nil {
		s.connTracker.SetUserMap(buildUserMap(users))
	}

	nlog.Core().Debug("sing-box users hot-swapped", "users", len(users))
	return nil
}

// ─── Observability ──────────────────────────────────────────────────────────
func (s *SingBox) GetUserTraffic(_ context.Context) (traffic map[int][2]int64, aliveIPs map[int]map[string]bool, connCount int, err error) {
	ct := s.connTrackerSafe()
	if ct == nil {
		return nil, nil, 0, nil
	}
	traffic, aliveIPs, connCount = ct.GetUserTraffic()
	return traffic, aliveIPs, connCount, nil
}

// CloseConnection force-closes a specific connection by its ID.
func (s *SingBox) CloseConnection(_ context.Context, connID string) error {
	ct := s.connTrackerSafe()
	if ct == nil {
		return fmt.Errorf("not running")
	}
	if !ct.CloseByID(connID) {
		nlog.Core().Debug("CloseConnection: connection not found (already closed?)", "id", connID)
	}
	return nil
}

// CloseUserConnections terminates all connections for a user UUID.
func (s *SingBox) CloseUserConnections(_ context.Context, uuid string) error {
	ct := s.connTrackerSafe()
	if ct == nil {
		return nil
	}
	ct.CloseByUUID(uuid)
	return nil
}

// buildUserMap maps each identity an inbound reports as metadata.User to the
// user ID, so ConnTracker can attribute connections and reject removed users.
// Every protocol uses the user's UUID as name/username except naive, which
// authenticates with the numeric user ID.
func buildUserMap(users []model.UserSpec) map[string]int {
	m := make(map[string]int, 2*len(users))
	for _, u := range users {
		m[u.UUID] = u.ID
		m[strconv.Itoa(u.ID)] = u.ID
	}
	return m
}
