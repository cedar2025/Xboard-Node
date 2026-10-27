package kernel

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/cedar2025/xboard-node/internal/model"
	"golang.org/x/time/rate"
)

type Capabilities struct {
	PerUserSpeedLimit    bool
	DeviceLimit          bool
	BuiltInTrafficStats  bool
	AliveIPTracking      bool
	ForceCloseConnection bool
	ForceCloseUser       bool
}

// TLSCert holds PEM-encoded TLS certificate material.
// All cert modes (self-signed, file, ACME, panel-content) normalise to PEM
// so kernels never need to deal with file paths.
type TLSCert struct {
	CertPEM []byte
	KeyPEM  []byte
}

// HasCert reports whether a valid cert+key pair is available.
func (t TLSCert) HasCert() bool {
	return len(t.CertPEM) > 0 && len(t.KeyPEM) > 0
}

// Kernel is the interface for proxy kernel backends (sing-box, xray, etc.).
//
// The interface is split into lifecycle, user management, and observability
// groups. User operations (AddUsers/RemoveUsers) are designed to be atomic
// and non-disruptive — they MUST NOT restart listeners or drop existing
// connections. Only Start and Reload may (re)bind ports.
//
// Implementors: singbox.SingBox, xray.Xray
type Kernel interface {
	// ─── Identity ───────────────────────────────────────────────────────
	// Name returns the kernel identifier (e.g. "sing-box", "xray").
	Name() string
	// Protocols returns the protocol names this kernel supports.
	Protocols() []string
	// Capabilities returns the explicit runtime semantics supported by the kernel.
	Capabilities() Capabilities

	// ─── Lifecycle ──────────────────────────────────────────────────────
	// Start initialises the kernel with the given node config and initial
	// user set, binds listeners, and begins accepting connections.
	// Calling Start on an already-running kernel stops the old instance first.
	Start(nodeConfig *model.NodeSpec, users []model.UserSpec, tls TLSCert) error
	// Stop gracefully shuts down the kernel, draining active connections.
	Stop()
	// IsRunning returns whether the kernel is currently accepting connections.
	IsRunning() bool
	// Reload re-generates the full config and hot-swaps listeners/routes.
	// Use this when port, protocol, or TLS settings change.
	// Existing connections MAY be briefly interrupted.
	Reload(nodeConfig *model.NodeSpec, users []model.UserSpec, tls TLSCert) error

	// ─── User management (non-disruptive) ───────────────────────────────
	// AddUsers registers new users with the running kernel.
	// Existing connections are unaffected. Returns the count actually added
	// (duplicates are silently skipped).
	AddUsers(users []model.UserSpec) (added int, err error)
	// RemoveUsers deregisters users from the running kernel.
	// Active connections of removed users are terminated. Returns the count
	// actually removed (unknown IDs are silently skipped).
	RemoveUsers(users []model.UserSpec) (removed int, err error)
	// UpdateUsers replaces the entire user set atomically.
	// This is equivalent to computing the diff and calling Add/Remove, but
	// may be more efficient for bulk changes. Returns (added, removed) counts.
	UpdateUsers(users []model.UserSpec) (added, removed int, err error)

	// ─── Observability ──────────────────────────────────────────────────
	// GetUserTraffic returns per-user cumulative traffic counters and
	// per-user alive IP sets. The kernel maintains these internally using
	// per-user atomic counters — no per-connection iteration needed.
	// aliveIPs maps userID → set of source IPs currently connected.
	// traffic maps userID → [upload, download] cumulative bytes.
	// connCount is the total number of active connections (for metrics).
	GetUserTraffic(ctx context.Context) (traffic map[int][2]int64, aliveIPs map[int]map[string]bool, connCount int, err error)
	// CloseConnection terminates a specific connection by ID.
	CloseConnection(ctx context.Context, connID string) error
	// CloseUserConnections terminates all connections for the given user UUID.
	CloseUserConnections(ctx context.Context, uuid string) error
	// SetSpeedLimitFunc configures per-user bandwidth throttling.
	// The function resolves a user UUID to a *rate.Limiter (nil = unlimited).
	SetSpeedLimitFunc(fn func(uuid string) *rate.Limiter)
	// SetUploadLimitFunc configures the per-user upload limiter, separate
	// from the download one set by SetSpeedLimitFunc (nil = unlimited).
	SetUploadLimitFunc(fn func(uuid string) *rate.Limiter)
	// SetDeviceLimitFunc configures per-user device limit gate-keeping.
	// The function resolves a user UUID to (limit, hasLimit).
	// Kernels that already gate-keep internally (e.g. xray) may no-op.
	SetDeviceLimitFunc(fn func(uuid string) (int, bool))
	// UpdateGlobalDevices updates the global device state from panel (for multi-node).
	UpdateGlobalDevices(users map[int][]string)
	// ClearGlobalDevices clears the global device state (on WS disconnect).
	ClearGlobalDevices()
}

// DeviceEchoWindow bounds how long after a device leaves a node the panel's
// global device state can still list it only because this node reported it:
// one tracker tick, one device report interval and one panel push, at their
// defaults (10s + 30s + 10s), plus slack.
const DeviceEchoWindow = 60 * time.Second

// AdmitDevice decides whether sourceIP may connect for a user allowed limit
// devices. local holds the user's IPs online on this node and elsewhere those
// online on other nodes. An IP already online is kept; a new IP is admitted
// only while fewer than limit are online, first come first served.
func AdmitDevice(local map[string]int, elsewhere map[string]bool, sourceIP string, limit int) bool {
	if local[sourceIP] > 0 || elsewhere[sourceIP] {
		return true
	}
	online := len(local)
	for ip := range elsewhere {
		if local[ip] == 0 {
			online++
		}
	}
	return online < limit
}

// OverLimitDevices returns the local IPs to disconnect when the user's IPs
// online on all nodes exceed limit. Two nodes can each admit a device before
// the panel tells them about the other, and neither knows which came first,
// so every node keeps the limit lowest-sorting IPs: the nodes agree on the
// survivors without talking to each other.
func OverLimitDevices(local map[string]int, elsewhere map[string]bool, limit int) []string {
	if limit <= 0 || len(local) == 0 {
		return nil
	}
	all := make([]string, 0, len(local)+len(elsewhere))
	for ip := range local {
		all = append(all, ip)
	}
	for ip := range elsewhere {
		if local[ip] == 0 {
			all = append(all, ip)
		}
	}
	if len(all) <= limit {
		return nil
	}
	sort.Strings(all)
	var over []string
	for _, ip := range all[limit:] {
		if local[ip] > 0 {
			over = append(over, ip)
		}
	}
	return over
}

// ComputeHash returns a hash of config + user identities that would
// require a kernel restart/reconstruction if changed.
func ComputeHash(nc *model.NodeSpec, users []model.UserSpec) string {
	h := sha256.New()
	configData, _ := json.Marshal(nc)
	h.Write(configData)
	sorted := make([]model.UserSpec, len(users))
	copy(sorted, users)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	for _, u := range sorted {
		fmt.Fprintf(h, "%d:%s,", u.ID, u.UUID)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// UserDiff computes which users to add and which to remove when transitioning
// from oldUsers to newUsers. This is a pure helper used by callers; kernels
// may also use it internally.
func UserDiff(oldUsers, newUsers []model.UserSpec) (toAdd, toRemove []model.UserSpec) {
	oldMap := make(map[int]model.UserSpec, len(oldUsers))
	for _, u := range oldUsers {
		oldMap[u.ID] = u
	}
	newMap := make(map[int]model.UserSpec, len(newUsers))
	for _, u := range newUsers {
		newMap[u.ID] = u
	}

	for _, u := range newUsers {
		old, exists := oldMap[u.ID]
		if !exists || old.UUID != u.UUID {
			toAdd = append(toAdd, u)
		}
	}
	for _, u := range oldUsers {
		if replacement, exists := newMap[u.ID]; !exists || replacement.UUID != u.UUID {
			toRemove = append(toRemove, u)
		}
	}
	return
}
