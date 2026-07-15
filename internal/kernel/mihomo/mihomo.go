package mihomo

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
)

const drainTimeout = 5 * time.Second

// Mihomo implements kernel.Kernel by embedding mihomo as a Go library.
//
// Lifecycle: Start → running → Stop / Reload
//
// User management triggers a config rebuild and re-parse via hub.Parse.
// Mihomo's PatchInboundListeners handles listener diffing — unchanged
// listeners are skipped, changed ones are recreated with brief disruption.
type Mihomo struct {
	cfg config.KernelConfig

	mu         sync.Mutex
	running    atomic.Bool
	users      []model.UserSpec
	nodeConfig *model.NodeSpec
	tls        kernel.TLSCert

	// userToID maps username ("uid_123") → user ID (123) for traffic tracking.
	userToID map[string]int

	// certFiles tracks temporary TLS cert/key files for cleanup.
	certFiles []string

	// Callback functions set by Xboard-Node framework.
	speedLimitFunc  func(string) *rate.Limiter
	deviceLimitFunc func(string) (int, bool)
}

func New(cfg config.KernelConfig) *Mihomo {
	return &Mihomo{
		cfg:      cfg,
		userToID: make(map[string]int),
	}
}

var _ kernel.Kernel = (*Mihomo)(nil)

// ─── Identity ──────────────────────────────────────────────────────

func (m *Mihomo) Name() string { return "mihomo" }

func (m *Mihomo) Protocols() []string {
	return []string{
		"vmess", "vless", "trojan", "shadowsocks",
		"hysteria", "hysteria2", "tuic", "wireguard",
		"anytls", "mieru", "trusttunnel", "sudoku",
	}
}

func (m *Mihomo) Capabilities() kernel.Capabilities {
	return kernel.Capabilities{
		PerUserSpeedLimit:    false,
		DeviceLimit:          false,
		BuiltInTrafficStats:  true,
		AliveIPTracking:      true,
		ForceCloseConnection: true,
		ForceCloseUser:       true,
	}
}

// ─── Lifecycle ─────────────────────────────────────────────────────

func (m *Mihomo) Start(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running.Load() {
		m.stopLocked()
	}

	m.nodeConfig = nodeConfig
	m.users = users
	m.tls = tls
	m.rebuildUserMap(users)

	if err := m.applyConfig(); err != nil {
		return err
	}

	m.running.Store(true)
	return nil
}

func (m *Mihomo) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
}

func (m *Mihomo) stopLocked() {
	if !m.running.Load() {
		return
	}
	executor.Shutdown()
	m.running.Store(false)
	m.cleanupCertFiles()
}

func (m *Mihomo) IsRunning() bool {
	return m.running.Load()
}

func (m *Mihomo) Reload(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running.Load() {
		return m.startLocked(nodeConfig, users, tls)
	}

	m.nodeConfig = nodeConfig
	m.users = users
	m.tls = tls
	m.rebuildUserMap(users)

	return m.applyConfig()
}

func (m *Mihomo) startLocked(nodeConfig *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
	m.nodeConfig = nodeConfig
	m.users = users
	m.tls = tls
	m.rebuildUserMap(users)

	if err := m.applyConfig(); err != nil {
		return err
	}

	m.running.Store(true)
	return nil
}

// ─── User management (non-disruptive as possible) ──────────────────

func (m *Mihomo) AddUsers(users []model.UserSpec) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing := make(map[int]bool, len(m.users))
	for _, u := range m.users {
		existing[u.ID] = true
	}

	added := 0
	for _, u := range users {
		if !existing[u.ID] {
			m.users = append(m.users, u)
			added++
		}
	}

	if added > 0 {
		m.rebuildUserMap(m.users)
		if err := m.applyConfig(); err != nil {
			return 0, err
		}
	}
	return added, nil
}

func (m *Mihomo) RemoveUsers(users []model.UserSpec) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	removeSet := make(map[int]bool, len(users))
	for _, u := range users {
		removeSet[u.ID] = true
	}

	kept := make([]model.UserSpec, 0, len(m.users))
	for _, u := range m.users {
		if !removeSet[u.ID] {
			kept = append(kept, u)
		}
	}

	removed := len(m.users) - len(kept)
	if removed > 0 {
		m.users = kept
		m.rebuildUserMap(m.users)
		if err := m.applyConfig(); err != nil {
			return 0, err
		}
	}
	return removed, nil
}

func (m *Mihomo) UpdateUsers(users []model.UserSpec) (int, int, error) {
	toAdd, toRemove := kernel.UserDiff(m.users, users)

	removed, err := m.RemoveUsers(toRemove)
	if err != nil {
		return 0, removed, err
	}

	added, err := m.AddUsers(toAdd)
	if err != nil {
		return added, removed, err
	}

	return added, removed, nil
}

// ─── Observability ─────────────────────────────────────────────────

func (m *Mihomo) GetUserTraffic(ctx context.Context) (map[int][2]int64, map[int]map[string]bool, int, error) {
	stringTraffic, stringIPs, connCount, err := statistic.DefaultManager.GetUserTraffic(ctx)
	if err != nil {
		return nil, nil, 0, err
	}

	traffic := make(map[int][2]int64, len(stringTraffic))
	for user, td := range stringTraffic {
		if id, ok := m.userToID[user]; ok {
			traffic[id] = td
		}
	}

	aliveIPs := make(map[int]map[string]bool, len(stringIPs))
	for user, ips := range stringIPs {
		if id, ok := m.userToID[user]; ok {
			aliveIPs[id] = ips
		}
	}

	return traffic, aliveIPs, connCount, nil
}

func (m *Mihomo) CloseConnection(_ context.Context, connID string) error {
	return statistic.DefaultManager.CloseConnectionByID(connID)
}

func (m *Mihomo) CloseUserConnections(_ context.Context, uuid string) error {
	// Try to find the username for this UUID from our user list.
	m.mu.Lock()
	username := ""
	for _, u := range m.users {
		if u.UUID == uuid {
			username = userUID(u)
			break
		}
	}
	m.mu.Unlock()

	if username == "" {
		return nil
	}
	statistic.DefaultManager.CloseUserConnections(username)
	return nil
}

func (m *Mihomo) SetSpeedLimitFunc(fn func(uuid string) *rate.Limiter) {
	m.mu.Lock()
	m.speedLimitFunc = fn
	m.mu.Unlock()
}

func (m *Mihomo) SetDeviceLimitFunc(fn func(uuid string) (int, bool)) {
	m.mu.Lock()
	m.deviceLimitFunc = fn
	m.mu.Unlock()
}

func (m *Mihomo) UpdateGlobalDevices(_ map[int][]string) {}

func (m *Mihomo) ClearGlobalDevices() {}

// ─── Internal helpers ──────────────────────────────────────────────

// rebuildUserMap rebuilds the userToID mapping from the current user list.
func (m *Mihomo) rebuildUserMap(users []model.UserSpec) {
	m.userToID = make(map[string]int, len(users))
	for _, u := range users {
		m.userToID[userUID(u)] = u.ID
	}
}

// applyConfig generates mihomo YAML and applies it via hub.Parse.
func (m *Mihomo) applyConfig() error {
	certDir := m.cfg.ConfigDir
	if certDir == "" {
		certDir = os.TempDir()
	}

	jsonBytes, certFiles, err := buildMihomoConfig(m.nodeConfig, m.users, m.tls, certDir)
	if err != nil {
		return err
	}

	// Clean up old cert files before applying new ones.
	m.cleanupCertFiles()
	m.certFiles = certFiles

	return hub.Parse(jsonBytes)
}

// cleanupCertFiles removes temporary TLS certificate files.
func (m *Mihomo) cleanupCertFiles() {
	for _, f := range m.certFiles {
		os.Remove(f)
	}
	m.certFiles = nil
}
