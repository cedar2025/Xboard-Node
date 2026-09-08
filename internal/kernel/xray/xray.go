package xray

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	xrayCore "github.com/xtls/xray-core/core"
	featurebandwidth "github.com/xtls/xray-core/features/bandwidth"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/infra/conf/serial"
	xrayProxy "github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"
	"golang.org/x/time/rate"

	_ "github.com/xtls/xray-core/main/distro/all"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/kernel/geodata"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

const (
	// drainTimeout is how long Stop waits for in-flight connections to finish
	// after the listener stopped accepting, before hard-closing the instance.
	drainTimeout = 5 * time.Second
	// switchGrace is the bounded wait when one instance replaces another: the
	// previous listener is already closed, so a long drain only delays the
	// moment the new configuration starts serving.
	switchGrace = time.Second
	// startTimeout caps how long instance.Start() may block.
	startTimeout = 30 * time.Second
)

// Xray implements kernel.Kernel by embedding xray-core as a Go library.
//
// Lifecycle:  Start  →  running  →  Stop / Reload
//
// Lock discipline:
//   - mu is held only for brief field swaps (microseconds).
//   - instance.Start() and instance.Close() run OUTSIDE the lock.
//   - running (atomic) gates fast-path checks in IsRunning / GetConnections.
type Xray struct {
	cfg config.KernelConfig

	// mu protects instance, limitDispatcher, users, protocol, inboundTag,
	// lastKernelHash, and cumTraffic. Never held during slow I/O.
	mu              sync.Mutex
	instance        *xrayCore.Instance
	limitDispatcher *LimitDispatcher
	users           []model.UserSpec
	nodeConfig      *model.NodeSpec
	tls             kernel.TLSCert
	protocol        string
	inboundTag      string
	lastKernelHash  string
	cumTraffic      map[int][2]int64
	speedLimitFunc  func(string) *rate.Limiter

	// running is set after a successful Start and cleared before shutdown.
	// Atomic so IsRunning / GetConnections never block.
	running atomic.Bool
}

func New(cfg config.KernelConfig) *Xray {
	return &Xray{
		cfg:        cfg,
		cumTraffic: make(map[int][2]int64),
	}
}

func (x *Xray) Name() string { return "xray" }

func (x *Xray) Capabilities() kernel.Capabilities {
	return kernel.Capabilities{
		PerUserSpeedLimit:    true,
		DeviceLimit:          true,
		BuiltInTrafficStats:  true,
		AliveIPTracking:      true,
		ForceCloseConnection: false,
		ForceCloseUser:       false,
	}
}

func (x *Xray) Protocols() []string {
	return []string{
		"vmess", "vless", "trojan", "shadowsocks",
		"hysteria",
	}
}

// ─── Lifecycle ──────────────────────────────────────────────────────────────

// Validate builds the protobuf configuration for the target the way Start
// does, without creating an instance or binding a listener.
func (x *Xray) Validate(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	if nodeConfig == nil {
		return fmt.Errorf("node config is nil")
	}
	cfgMap := buildConfig(x.cfg, nodeConfig, users, tls)
	inbounds, _ := cfgMap["inbounds"].([]M)
	if len(inbounds) == 0 {
		return fmt.Errorf("protocol %q has no xray inbound builder", nodeConfig.Protocol)
	}
	data, err := json.Marshal(cfgMap)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if _, err := serial.LoadJSONConfig(bytes.NewReader(data)); err != nil {
		return fmt.Errorf("parse xray config: %w", err)
	}
	return nil
}

// Start builds a new xray-core instance and replaces the running one. The
// method is organised in phases so that the kernel mutex is never held during
// slow operations (Start / Close):
//
//	Phase 1 – Build:     generate protobuf config           (no lock)
//	Phase 2 – Create:    xrayCore.New + capture LD          (brief global lock)
//	Phase 3 – Retire:    close the previous inbound, drain  (bounded, no lock)
//	Phase 4 – StartNew:  instance.Start                     (no lock)
//	Phase 5 – Swap:      publish the new instance           (brief kernel lock)
//
// The previous listener is closed before the new one binds: with reusePort
// both could bind the same port, and a lingering previous listener would keep
// accepting connections with the previous configuration and user set. When
// the new instance fails to start, the previous configuration is rebuilt
// with the user set of this call so the node keeps serving while the caller
// retries; the original error is returned.
func (x *Xray) Start(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	// ── Phase 1: Build config (no shared state) ─────────────────────────
	x.ensureGeoData(nodeConfig)

	inst, ld, err := x.createInstance(nodeConfig, users, tls)
	if err != nil {
		return err
	}

	// ── Phase 3: Retire the previous instance (bounded) ─────────────────
	x.mu.Lock()
	old := x.instance
	oldLD := x.limitDispatcher
	oldTag := x.inboundTag
	oldConfig := x.nodeConfig
	oldTLS := x.tls
	x.mu.Unlock()
	if old != nil {
		x.running.Store(false)
		closeInstance(old, oldLD, oldTag, switchGrace)
	}

	// ── Phase 4: Start new (no lock, potentially slow) ──────────────────
	if err := startWithTimeout(inst, startTimeout); err != nil {
		inst.Close()
		if old != nil && oldConfig != nil && len(users) > 0 {
			x.restorePrevious(oldConfig, users, oldTLS)
		}
		return err
	}

	x.publish(inst, ld, nodeConfig, users, tls)

	nlog.Core().Info("xray started",
		"users", len(users),
		"protocol", nodeConfig.Protocol,
	)
	return nil
}

// createInstance runs phases 1–2: it builds and creates an instance without
// binding anything.
func (x *Xray) createInstance(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) (*xrayCore.Instance, *LimitDispatcher, error) {
	data, err := marshalConfig(x.cfg, nodeConfig, users, tls)
	if err != nil {
		return nil, nil, err
	}
	pbConfig, err := serial.LoadJSONConfig(bytes.NewReader(data))
	if err != nil {
		return nil, nil, fmt.Errorf("parse xray config: %w", err)
	}

	// ── Phase 2: Create instance (global lock for LD capture) ───────────
	xrayCreationMu.Lock()
	inst, err := xrayCore.New(pbConfig)
	ld := globalLimitDispatcher.Load()
	xrayCreationMu.Unlock()
	if err != nil {
		return nil, nil, fmt.Errorf("create xray: %w", err)
	}
	return inst, ld, nil
}

// publish runs phase 5: the started instance becomes the running one.
func (x *Xray) publish(inst *xrayCore.Instance, ld *LimitDispatcher, nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) {
	x.mu.Lock()
	x.instance = inst
	x.limitDispatcher = ld
	x.users = users
	x.nodeConfig = nodeConfig
	x.tls = tls
	x.protocol = nodeConfig.Protocol
	x.inboundTag = nodeConfig.Protocol + "-in"
	x.cumTraffic = make(map[int][2]int64)
	x.lastKernelHash = kernel.ComputeHash(nodeConfig, users)
	x.running.Store(true)
	x.mu.Unlock()

	x.updateDispatcherLimits(users)
	x.updateBandwidthLimits(users)
}

// restorePrevious rebuilds the previous configuration after a failed
// replacement, with the latest user set.
func (x *Xray) restorePrevious(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) {
	inst, ld, err := x.createInstance(nodeConfig, users, tls)
	if err != nil {
		nlog.Core().Error("xray: rollback to previous config failed", "protocol", nodeConfig.Protocol, "error", err)
		return
	}
	if err := startWithTimeout(inst, startTimeout); err != nil {
		inst.Close()
		nlog.Core().Error("xray: rollback to previous config failed", "protocol", nodeConfig.Protocol, "error", err)
		return
	}
	x.publish(inst, ld, nodeConfig, users, tls)
	nlog.Core().Warn("xray: restored previous config after failed replacement", "protocol", nodeConfig.Protocol, "port", nodeConfig.ServerPort)
}

// Reload updates dispatcher limits and handles configuration changes.
// Since Xray does not support granular inbound reconstruction without an
// instance restart for most transport/TLS settings, it triggers a full restart
// if any kernel-affecting fields (hash mismatch) have changed.
func (x *Xray) Reload(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	x.updateDispatcherLimits(users)
	x.updateBandwidthLimits(users)

	newHash := kernel.ComputeHash(nodeConfig, users)

	x.mu.Lock()
	same := x.lastKernelHash == newHash && tlsEqual(x.tls, tls)
	if same {
		x.users = users
		x.mu.Unlock()
		nlog.Core().Debug("xray: limits updated, kernel configuration unchanged")
		return nil
	}
	x.mu.Unlock()

	nlog.Core().Info("xray: configuration changed, performing full restart")
	return x.Start(nodeConfig, users, tls)
}

// Stop shuts the kernel down: the inbound stops accepting at once, in-flight
// connections get a bounded drain, then the instance is closed. It returns
// only when the listener is gone, so a caller may bind the port afterwards.
func (x *Xray) Stop() {
	x.running.Store(false)

	x.mu.Lock()
	inst := x.instance
	ld := x.limitDispatcher
	tag := x.inboundTag
	x.instance = nil
	x.limitDispatcher = nil
	x.mu.Unlock()

	closeInstance(inst, ld, tag, drainTimeout)
}

func (x *Xray) IsRunning() bool { return x.running.Load() }

func tlsEqual(a, b kernel.TLSCert) bool {
	return bytes.Equal(a.CertPEM, b.CertPEM) && bytes.Equal(a.KeyPEM, b.KeyPEM)
}

// ─── Observability ──────────────────────────────────────────────────────────

// GetUserTraffic returns per-user cumulative traffic from xray's built-in
// stats pipeline and connection state from the admission dispatcher when
// available. The dispatcher intentionally no longer wraps transport links,
// so traffic accounting must come from xray-core itself.
func (x *Xray) GetUserTraffic(_ context.Context) (traffic map[int][2]int64, aliveIPs map[int]map[string]bool, connCount int, err error) {
	if !x.running.Load() {
		return nil, nil, 0, nil
	}

	x.mu.Lock()
	ld := x.limitDispatcher
	traffic, err = x.aggregateStats()
	x.mu.Unlock()
	if err != nil {
		return nil, nil, 0, err
	}

	if ld != nil {
		aliveIPs, connCount = ld.GetConnectionState()
	}
	return traffic, aliveIPs, connCount, nil
}

func (x *Xray) CloseConnection(_ context.Context, _ string) error {
	// No-op: xray doesn't support force-closing individual connections.
	// User removal goes through RemoveUsers which removes the inbound user.
	return nil
}

func (x *Xray) CloseUserConnections(_ context.Context, _ string) error {
	// No-op: handled by RemoveUsers at the xray core level.
	return nil
}

// SetSpeedLimitFunc wires xray's patched bandwidth feature to the shared
// per-user limiter callback used by the service layer. Unlike the old no-op
// behavior, xray now consumes this callback to support dynamic speed updates.
func (x *Xray) SetSpeedLimitFunc(fn func(string) *rate.Limiter) {
	x.mu.Lock()
	x.speedLimitFunc = fn
	x.mu.Unlock()
	x.updateBandwidthLimits(nil)
}

// SetDeviceLimitFunc is a no-op for xray — device limits are already
// gate-kept by LimitDispatcher.checkDeviceLimit at Dispatch time.
func (x *Xray) SetDeviceLimitFunc(_ func(string) (int, bool)) {}

// UpdateGlobalDevices is a no-op for xray — xray handles device limits differently.
func (x *Xray) UpdateGlobalDevices(_ map[int][]string) {}

// ClearGlobalDevices is a no-op for xray.
func (x *Xray) ClearGlobalDevices() {}

// ─── User management (non-disruptive where possible) ────────────────────────
//
// AddUsers, RemoveUsers and UpdateUsers share one contract:
//
//   - every credential to add is converted and checked before the first
//     native change, so an unusable one is reported while the kernel still
//     holds the previous account set unchanged;
//   - native changes run remove-before-add, once per identity (a rotated
//     credential keeps its ID, so UserDiff lists its old identity for removal
//     and its new one for addition);
//   - x.users only ever describes accounts the UserManager holds: a failure
//     part-way records exactly the operations that succeeded;
//   - a native failure is never reported as success. The instance is rebuilt
//     from the desired user set (the controlled restart already used for
//     protocols without a UserManager); when that fails too, the error is
//     returned so the caller stops the listener and retries.

// AddUsers adds new users to the running kernel via xray's UserManager API.
// For protocols that support UserManager (vmess, vless, trojan, shadowsocks),
// this is truly hitless — no restart, no connection disruption.
// For unsupported protocols (socks, http), falls back to full restart.
//
// Delta "add" events also carry property updates (speed/device limits) for
// existing users, so this method always merges properties and refreshes the
// dispatcher limits — even when no brand-new users need to be added.
func (x *Xray) AddUsers(users []model.UserSpec) (int, error) {
	x.mu.Lock()
	if x.instance == nil {
		x.mu.Unlock()
		return 0, fmt.Errorf("not running")
	}
	current := x.users

	// Merge: overwrite existing users' properties, collect truly new ones.
	userMap := make(map[int]model.UserSpec, len(current))
	for _, u := range current {
		userMap[u.ID] = u
	}
	var toAdd []model.UserSpec
	for _, u := range users {
		if _, exists := userMap[u.ID]; !exists {
			toAdd = append(toAdd, u)
		}
		userMap[u.ID] = u // always overwrite properties
	}
	merged := make([]model.UserSpec, 0, len(userMap))
	for _, u := range userMap {
		merged = append(merged, u)
	}

	if len(toAdd) == 0 {
		// No new kernel users, but properties (limits) may have changed.
		x.users = merged
		x.mu.Unlock()
		x.updateDispatcherLimits(merged)
		x.updateBandwidthLimits(merged)
		return 0, nil
	}

	um, err := x.getUserManager()
	if err != nil {
		// Protocol doesn't support UserManager → full restart
		nc, t := x.nodeConfig, x.tls
		x.mu.Unlock()
		nlog.Core().Debug("xray: AddUsers fallback to restart", "reason", err)
		if err := x.Start(nc, merged, t); err != nil {
			return 0, err
		}
		return len(toAdd), nil
	}

	proto, nc, t := x.protocol, x.nodeConfig, x.tls
	x.mu.Unlock()

	accounts, err := memoryUsers(proto, nc, toAdd)
	if err != nil {
		return 0, err
	}
	held, added, _, err := nativeUserUpdate(um, current, nil, toAdd, accounts)
	if err != nil {
		x.setUsers(held)
		if err := x.rebuildAfterFailedUserUpdate(nc, merged, t, err); err != nil {
			return 0, err
		}
		return len(toAdd), nil
	}

	// Update bookkeeping with full merged list (new users + updated properties).
	x.setUsers(merged)
	x.updateDispatcherLimits(merged)
	x.updateBandwidthLimits(merged)

	nlog.Core().Info("xray: users added via UserManager", "added", added, "total", len(merged))
	return added, nil
}

// RemoveUsers removes users from the running kernel via xray's UserManager API.
// Truly hitless for supported protocols — remaining connections unaffected.
func (x *Xray) RemoveUsers(users []model.UserSpec) (int, error) {
	x.mu.Lock()
	if x.instance == nil {
		x.mu.Unlock()
		return 0, fmt.Errorf("not running")
	}
	removeSet := make(map[int]struct{}, len(users))
	for _, u := range users {
		removeSet[u.ID] = struct{}{}
	}
	current := x.users
	var kept, toRemove []model.UserSpec
	for _, u := range current {
		if _, rm := removeSet[u.ID]; rm {
			toRemove = append(toRemove, u)
		} else {
			kept = append(kept, u)
		}
	}
	if len(toRemove) == 0 {
		x.mu.Unlock()
		return 0, nil
	}

	if len(kept) == 0 {
		x.mu.Unlock()
		x.Stop()
		return len(toRemove), nil
	}

	um, err := x.getUserManager()
	if err != nil {
		nc, t := x.nodeConfig, x.tls
		x.mu.Unlock()
		nlog.Core().Debug("xray: RemoveUsers fallback to restart", "reason", err)
		if err := x.Start(nc, kept, t); err != nil {
			return 0, err
		}
		return len(toRemove), nil
	}
	nc, t := x.nodeConfig, x.tls
	x.mu.Unlock()

	held, _, removed, err := nativeUserUpdate(um, current, toRemove, nil, nil)
	if err != nil {
		x.setUsers(held)
		if err := x.rebuildAfterFailedUserUpdate(nc, kept, t, err); err != nil {
			return 0, err
		}
		return len(toRemove), nil
	}

	x.setUsers(kept)
	x.updateDispatcherLimits(kept)
	x.updateBandwidthLimits(kept)

	nlog.Core().Info("xray: users removed via UserManager", "removed", removed, "total", len(kept))
	return removed, nil
}

// UpdateUsers replaces the entire user set. If only speed/device limits
// changed, updates the dispatcher without restarting. Otherwise uses
// UserManager for hitless add/remove where supported.
func (x *Xray) UpdateUsers(users []model.UserSpec) (int, int, error) {
	x.mu.Lock()
	if x.instance == nil {
		x.mu.Unlock()
		return 0, 0, fmt.Errorf("not running")
	}
	current := x.users
	toAdd, toRemove := kernel.UserDiff(current, users)

	if len(toAdd) == 0 && len(toRemove) == 0 {
		// Only limits changed — update dispatcher without restart.
		x.users = users
		x.mu.Unlock()
		x.updateDispatcherLimits(users)
		x.updateBandwidthLimits(users)
		nlog.Core().Info("xray: limits updated, kernel unchanged")
		return 0, 0, nil
	}

	um, umErr := x.getUserManager()
	if umErr != nil {
		// Protocol doesn't support UserManager → full restart
		nc, t := x.nodeConfig, x.tls
		x.mu.Unlock()
		nlog.Core().Debug("xray: UpdateUsers fallback to restart", "reason", umErr)
		if err := x.Start(nc, users, t); err != nil {
			return 0, 0, err
		}
		return len(toAdd), len(toRemove), nil
	}

	proto, nc, t := x.protocol, x.nodeConfig, x.tls
	x.mu.Unlock()

	accounts, err := memoryUsers(proto, nc, toAdd)
	if err != nil {
		return 0, 0, err
	}
	held, added, removed, err := nativeUserUpdate(um, current, toRemove, toAdd, accounts)
	if err != nil {
		x.setUsers(held)
		if err := x.rebuildAfterFailedUserUpdate(nc, users, t, err); err != nil {
			return 0, 0, err
		}
		return len(toAdd), len(toRemove), nil
	}

	x.setUsers(users)
	x.updateDispatcherLimits(users)
	x.updateBandwidthLimits(users)

	nlog.Core().Info("xray: users updated via UserManager", "added", added, "removed", removed, "total", len(users))
	return added, removed, nil
}

// setUsers replaces the bookkeeping snapshot of the accounts the kernel holds.
func (x *Xray) setUsers(users []model.UserSpec) {
	x.mu.Lock()
	x.users = users
	x.mu.Unlock()
}

// memoryUsers converts every credential before any native change, so that an
// unusable one is reported while the kernel still holds the previous account
// set unchanged. The result is index-aligned with users.
func memoryUsers(proto string, nc *model.NodeSpec, users []model.UserSpec) ([]*protocol.MemoryUser, error) {
	accounts := make([]*protocol.MemoryUser, 0, len(users))
	for _, u := range users {
		mu, err := toMemoryUser(proto, nc, u)
		if err != nil {
			return nil, fmt.Errorf("user %d: %w", u.ID, err)
		}
		accounts = append(accounts, mu)
	}
	return accounts, nil
}

// nativeUserUpdate applies toRemove and then toAdd through the UserManager
// and returns the account set the manager holds afterwards, together with the
// number of accounts actually removed and added. The update stops at the
// first failure, so a caller gets an exact record of a partial change: removed
// accounts are gone from the snapshot, accounts the manager never accepted
// are absent from it. A removal error is forgiven only when the manager
// proves the account absent afterwards (GetUser returns nil); it is then not
// counted as removed. accounts holds the converted toAdd credentials,
// index-aligned with toAdd.
func nativeUserUpdate(um xrayProxy.UserManager, current, toRemove, toAdd []model.UserSpec, accounts []*protocol.MemoryUser) (held []model.UserSpec, added, removed int, err error) {
	ctx := context.Background()
	byID := make(map[int]model.UserSpec, len(current)+len(toAdd))
	order := make([]int, 0, len(current)+len(toAdd))
	for _, u := range current {
		byID[u.ID] = u
		order = append(order, u.ID)
	}
	snapshot := func() []model.UserSpec {
		out := make([]model.UserSpec, 0, len(byID))
		seen := make(map[int]struct{}, len(byID))
		for _, id := range order {
			if _, done := seen[id]; done {
				continue
			}
			if u, ok := byID[id]; ok {
				out = append(out, u)
				seen[id] = struct{}{}
			}
		}
		return out
	}

	for _, u := range toRemove {
		email := userEmail(u.ID)
		if err := um.RemoveUser(ctx, email); err != nil {
			if um.GetUser(ctx, email) != nil {
				// The account is still there: the kernel keeps accepting it.
				return snapshot(), added, removed, fmt.Errorf("remove user %d: %w", u.ID, err)
			}
			nlog.Core().Debug("xray: account already absent", "user", u.ID, "error", err)
		} else {
			removed++
		}
		delete(byID, u.ID)
	}
	for i, u := range toAdd {
		if err := um.AddUser(ctx, accounts[i]); err != nil {
			return snapshot(), added, removed, fmt.Errorf("add user %d: %w", u.ID, err)
		}
		byID[u.ID] = u
		order = append(order, u.ID)
		added++
	}
	return snapshot(), added, removed, nil
}

// rebuildAfterFailedUserUpdate recovers from a native user operation that
// failed part-way: the instance is rebuilt from the desired user set with the
// controlled restart also used for protocols without a UserManager. A
// successful rebuild serves exactly users, because the new instance was built
// from them. A failed rebuild is returned as an error, so the caller stops the
// listener and retries with the desired set rather than leaving a mixed
// account set accepting connections.
func (x *Xray) rebuildAfterFailedUserUpdate(nc *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert, cause error) error {
	nlog.Core().Warn("xray: native user update failed, rebuilding instance with the desired user set", "users", len(users), "error", cause)
	if err := x.Start(nc, users, tls); err != nil {
		return fmt.Errorf("native user update failed (%v); rebuild with the desired users failed: %w", cause, err)
	}
	nlog.Core().Warn("xray: instance rebuilt with the desired user set after a failed native update", "users", len(users))
	return nil
}

var _ kernel.Kernel = (*Xray)(nil)

// ─── Internal helpers ───────────────────────────────────────────────────────

// getUserManager extracts the UserManager from the running xray instance's
// inbound handler. Must be called with x.mu held.
// Returns error for protocols that don't support UserManager (socks, http).
func (x *Xray) getUserManager() (xrayProxy.UserManager, error) {
	if x.instance == nil {
		return nil, fmt.Errorf("instance is nil")
	}

	im := x.instance.GetFeature(inbound.ManagerType())
	if im == nil {
		return nil, fmt.Errorf("inbound manager not available")
	}
	inboundMgr, ok := im.(inbound.Manager)
	if !ok {
		return nil, fmt.Errorf("inbound manager type assertion failed")
	}

	handler, err := inboundMgr.GetHandler(context.Background(), x.inboundTag)
	if err != nil {
		return nil, fmt.Errorf("get handler %q: %w", x.inboundTag, err)
	}

	gi, ok := handler.(xrayProxy.GetInbound)
	if !ok {
		return nil, fmt.Errorf("handler does not implement GetInbound")
	}

	um, ok := gi.GetInbound().(xrayProxy.UserManager)
	if !ok {
		return nil, fmt.Errorf("protocol %q does not support UserManager", x.protocol)
	}

	return um, nil
}

// toMemoryUser converts a model.UserSpec into an xray protocol.MemoryUser for the
// given protocol. Each protocol needs a different Account type.
func toMemoryUser(proto string, nc *model.NodeSpec, u model.UserSpec) (*protocol.MemoryUser, error) {
	email := userEmail(u.ID)
	mu := &protocol.MemoryUser{Email: email, Level: 0}

	switch proto {
	case "vmess":
		id, err := uuid.ParseString(u.UUID)
		if err != nil {
			return nil, fmt.Errorf("parse vmess UUID: %w", err)
		}
		mu.Account = &vmess.MemoryAccount{
			ID:       protocol.NewID(id),
			Security: protocol.SecurityType_AUTO,
		}

	case "vless":
		id, err := uuid.ParseString(u.UUID)
		if err != nil {
			return nil, fmt.Errorf("parse vless UUID: %w", err)
		}
		account := &vless.MemoryAccount{
			ID:         protocol.NewID(id),
			Encryption: "none",
		}
		if nc.Flow != "" {
			account.Flow = nc.Flow
		}
		mu.Account = account

	case "trojan":
		mu.Account = &trojan.MemoryAccount{
			Password: u.UUID,
			Key:      trojanHexSha224(u.UUID),
		}

	case "shadowsocks":
		if strings.HasPrefix(nc.Cipher, "2022-blake3-") {
			// 2022-blake3 multi-user mode
			mu.Account = &ss2022.MemoryAccount{Key: u.UUID}
		} else {
			// Traditional SS — build via getCipher path
			ct := parseCipherType(nc.Cipher)
			cipherObj, err := (&shadowsocks.Account{CipherType: ct, Password: u.UUID}).AsAccount()
			if err != nil {
				return nil, fmt.Errorf("build ss account: %w", err)
			}
			mu.Account = cipherObj
		}

	default:
		return nil, fmt.Errorf("protocol %q does not support MemoryUser", proto)
	}

	return mu, nil
}

// parseCipherType maps a cipher name string to the xray CipherType enum.
func parseCipherType(cipher string) shadowsocks.CipherType {
	switch cipher {
	case "aes-128-gcm":
		return shadowsocks.CipherType_AES_128_GCM
	case "aes-256-gcm":
		return shadowsocks.CipherType_AES_256_GCM
	case "chacha20-ietf-poly1305", "chacha20-poly1305":
		return shadowsocks.CipherType_CHACHA20_POLY1305
	case "xchacha20-ietf-poly1305", "xchacha20-poly1305":
		return shadowsocks.CipherType_XCHACHA20_POLY1305
	case "none", "plain":
		return shadowsocks.CipherType_NONE
	default:
		return shadowsocks.CipherType_AES_256_GCM
	}
}

// trojanHexSha224 computes the SHA-224 hex key used by trojan protocol.
func trojanHexSha224(password string) []byte {
	// Replicates the exact logic from xray-core/proxy/trojan/config.go hexSha224
	h := sha256.New224()
	h.Write([]byte(password))
	buf := make([]byte, 56)
	hexEncode(buf, h.Sum(nil))
	return buf
}

// hexEncode is a minimal hex encoder (avoids importing encoding/hex).
func hexEncode(dst, src []byte) {
	const hextable = "0123456789abcdef"
	for i, v := range src {
		dst[i*2] = hextable[v>>4]
		dst[i*2+1] = hextable[v&0x0f]
	}
}

// ensureGeoData downloads geo databases when routes reference geoip/geosite.
func (x *Xray) ensureGeoData(nc *model.NodeSpec) {
	needIP, needSite := kernel.NeedsGeoIP(nc.Routes), kernel.NeedsGeoSite(nc.Routes)
	if !needIP && !needSite {
		return
	}
	dir := x.cfg.GeoDataDir
	if err := geodata.Ensure(dir, needIP, needSite, "xray"); err != nil {
		nlog.Core().Warn("geo database unavailable", "error", err)
	}
	os.Setenv("XRAY_LOCATION_ASSET", dir)
}

// marshalConfig builds the xray JSON config and returns the raw bytes.
func marshalConfig(cfg config.KernelConfig, nc *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) ([]byte, error) {
	cfgMap := buildConfig(cfg, nc, users, tls)
	data, err := json.MarshalIndent(cfgMap, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	nlog.Core().Debug("xray config generated", "len", len(data))
	return data, nil
}

// startWithTimeout runs instance.Start() with a bounded deadline.
func startWithTimeout(inst *xrayCore.Instance, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- inst.Start() }()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("start xray: %w", err)
		}
		return nil
	case <-time.After(timeout):
		go inst.Close()
		return fmt.Errorf("start xray: timeout after %v", timeout)
	}
}

// closeInstance retires an instance: the inbound handler is removed first so
// the listener stops accepting, in-flight connections get up to grace to
// finish, then everything is closed. It is synchronous by design — the
// caller relies on the port being free when it returns.
func closeInstance(inst *xrayCore.Instance, ld *LimitDispatcher, tag string, grace time.Duration) {
	if inst == nil {
		return
	}
	if tag != "" {
		if feature := inst.GetFeature(inbound.ManagerType()); feature != nil {
			if im, ok := feature.(inbound.Manager); ok {
				if err := im.RemoveHandler(context.Background(), tag); err != nil {
					nlog.Core().Debug("xray: remove inbound handler", "tag", tag, "error", err)
				}
			}
		}
	}
	if ld != nil {
		drainConns(ld, grace)
	}
	inst.Close()
	if ld != nil {
		ld.ResetConns()
	}
	nlog.Core().Debug("xray: instance closed", "tag", tag)
}

// drainConns waits up to timeout for the dispatcher's active connections to
// reach zero. Used only during graceful Stop, not during hot-reload.
func drainConns(ld *LimitDispatcher, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ld.connCount.Load() == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// aggregateStats is a fallback path that reads xray's built-in stats counters
// when LimitDispatcher is not available. Returns per-user cumulative traffic.
// Must be called with x.mu held.
func (x *Xray) aggregateStats() (map[int][2]int64, error) {
	sm := x.instance.GetFeature(stats.ManagerType())
	if sm == nil {
		return nil, nil
	}
	mgr, ok := sm.(stats.Manager)
	if !ok {
		return nil, nil
	}

	traffic := make(map[int][2]int64)
	for _, u := range x.users {
		email := userEmail(u.ID)

		var dUp, dDown int64
		if c := mgr.GetCounter(fmt.Sprintf("user>>>%s>>>traffic>>>uplink", email)); c != nil {
			dUp = c.Set(0)
		}
		if c := mgr.GetCounter(fmt.Sprintf("user>>>%s>>>traffic>>>downlink", email)); c != nil {
			dDown = c.Set(0)
		}

		if dUp > 0 || dDown > 0 {
			cum := x.cumTraffic[u.ID]
			cum[0] += dUp
			cum[1] += dDown
			x.cumTraffic[u.ID] = cum
		}

		if cum := x.cumTraffic[u.ID]; cum[0] > 0 || cum[1] > 0 {
			traffic[u.ID] = cum
		}
	}
	return traffic, nil
}

// updateBandwidthLimits configures the patched xray-core bandwidth feature
// with per-user speed limits in bytes per second.
func (x *Xray) updateBandwidthLimits(users []model.UserSpec) {
	x.mu.Lock()
	inst := x.instance
	fn := x.speedLimitFunc
	currentUsers := x.users
	x.mu.Unlock()
	if inst == nil {
		return
	}
	feat := inst.GetFeature(featurebandwidth.ManagerType())
	if feat == nil {
		return
	}
	bm, ok := feat.(featurebandwidth.Manager)
	if !ok {
		return
	}
	bm.Reset()
	if users == nil {
		users = currentUsers
	}
	for _, u := range users {
		email := userEmail(u.ID)
		if fn != nil {
			bm.SetUserLimiter(email, fn(u.UUID))
			continue
		}
		bps := int64(u.SpeedLimit) * 1_000_000 / 8
		bm.SetUserLimit(email, bps)
	}
}

// updateDispatcherLimits configures the LimitDispatcher with per-user
// device-limit admission metadata only. Speed limits are enforced by the
// patched xray-core bandwidth feature.
func (x *Xray) updateDispatcherLimits(users []model.UserSpec) {
	x.mu.Lock()
	ld := x.limitDispatcher
	x.mu.Unlock()
	if ld == nil {
		return
	}

	emailToUID := make(map[string]int, len(users)*2)
	deviceLimits := make(map[string]int)

	for _, u := range users {
		email := userEmail(u.ID)
		emailToUID[email] = u.ID
		emailToUID[u.UUID] = u.ID
		if u.DeviceLimit > 0 {
			deviceLimits[email] = u.DeviceLimit
			deviceLimits[u.UUID] = u.DeviceLimit
		}
	}

	ld.UpdateLimits(emailToUID, deviceLimits, nil)
}

// xrayCreationMu serialises xrayCore.New() + globalLimitDispatcher capture
// so that concurrent Xray instances in multi-node mode each capture their
// own LimitDispatcher.
var xrayCreationMu sync.Mutex
