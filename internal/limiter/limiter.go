package limiter

import (
	"sync"
	"sync/atomic"

	"github.com/cedar2025/xboard-node/internal/model"
)

// Limiter enforces per-user device limits and detects removed users.
type Limiter struct {
	mu    sync.RWMutex
	users map[int]model.UserSpec

	// uuidDeviceLimit provides O(1) UUID→device-limit lookup for the
	// kernel gate-keeping hot path (called per new connection).
	uuidDeviceLimit map[string]int

	// Fast-path: when no users have a device limit, GetDeviceLimitByUUID
	// returns (0, false) immediately without any lock.
	hasDeviceLimits atomic.Bool

	deviceLimitEvents atomic.Uint64
}

func New() *Limiter {
	return &Limiter{
		users:           make(map[int]model.UserSpec),
		uuidDeviceLimit: make(map[string]int),
	}
}

// UpdateUsers refreshes the user limit configuration and returns
// the IDs of users that were present before but are now removed.
func (l *Limiter) UpdateUsers(users []model.UserSpec) []int {
	l.mu.Lock()
	defer l.mu.Unlock()

	newUsers := make(map[int]model.UserSpec, len(users))
	for _, u := range users {
		newUsers[u.ID] = u
	}

	// Find removed users
	var removed []int
	for id := range l.users {
		if _, ok := newUsers[id]; !ok {
			removed = append(removed, id)
		}
	}

	l.users = newUsers

	// Rebuild UUID→device-limit index for O(1) lookups.
	idx := make(map[string]int, len(newUsers))
	for _, u := range newUsers {
		if u.DeviceLimit > 0 {
			idx[u.UUID] = u.DeviceLimit
		}
	}
	l.uuidDeviceLimit = idx
	l.hasDeviceLimits.Store(len(idx) > 0)

	return removed
}

// LimiterMetrics holds aggregated limiter statistics.
type LimiterMetrics struct {
	// DeviceLimitEvents is the total number of times a user exceeded
	// the configured device limit (since process start).
	DeviceLimitEvents uint64
}

// SnapshotMetrics returns a snapshot of limiter metrics.
func (l *Limiter) SnapshotMetrics() LimiterMetrics {
	return LimiterMetrics{
		DeviceLimitEvents: l.deviceLimitEvents.Load(),
	}
}

// GetDeviceLimitByUUID returns the device limit for a user identified by UUID.
// Returns (limit, true) if a device limit is set, (0, false) otherwise.
// This is designed to be passed as a function reference to kernel.SetDeviceLimitFunc.
func (l *Limiter) GetDeviceLimitByUUID(uuid string) (int, bool) {
	if !l.hasDeviceLimits.Load() {
		return 0, false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	limit, ok := l.uuidDeviceLimit[uuid]
	return limit, ok
}
