package limiter

import (
	"sync"
	"sync/atomic"

	"github.com/cedar2025/xboard-node/internal/model"
	"golang.org/x/time/rate"
)

// SpeedTrackerLogCallback is called when bucket updates occur.
type SpeedTrackerLogCallback func(msg string)

// speedSnapshot is an immutable view of the speed limiter state.
// Published atomically so GetLimiter reads without any lock.
type speedSnapshot struct {
	uuidMap map[string]int        // UUID → userID
	buckets map[int]*rate.Limiter // userID → shared rate limiter
}

// SpeedTracker manages per-user token-bucket rate limiters.
// It does NOT wrap connections itself — instead, ConnTracker consults it
// via GetLimiter to embed rate limiting in the same tracked connection
// wrapper that does byte counting.
//
// Architecture: uuidMap and buckets are stored as an immutable snapshot
// behind an atomic.Pointer. UpdateBuckets builds a new snapshot and swaps
// it in. GetLimiter reads the snapshot lock-free via a single atomic.Load.
// On-demand limiter creation (first connection from a limited user) uses
// a separate write lock to extend the snapshot, re-published atomically.
type SpeedTracker struct {
	limiter *Limiter

	// Immutable snapshot, swapped atomically. Readers never block.
	snap atomic.Pointer[speedSnapshot]

	// mu protects on-demand bucket creation (rare path: first connection
	// from a speed-limited user whose bucket doesn't exist yet).
	mu sync.Mutex

	// Optional callback for logging
	logFunc SpeedTrackerLogCallback
}

// NewSpeedTracker creates a bucket manager for per-user bandwidth throttling.
func NewSpeedTracker(l *Limiter) *SpeedTracker {
	st := &SpeedTracker{limiter: l}
	st.snap.Store(&speedSnapshot{
		uuidMap: make(map[string]int),
		buckets: make(map[int]*rate.Limiter),
	})
	return st
}

// SetLogCallback sets the logging callback.
func (t *SpeedTracker) SetLogCallback(f SpeedTrackerLogCallback) {
	t.logFunc = f
}

// UpdateBuckets rebuilds the immutable snapshot from the current user list.
// Called infrequently (on user sync). O(users) + O(bucket mutations).
func (t *SpeedTracker) UpdateBuckets() {
	t.limiter.mu.RLock()
	currentUsers := make([]model.UserSpec, 0, len(t.limiter.users))
	for _, u := range t.limiter.users {
		currentUsers = append(currentUsers, u)
	}
	t.limiter.mu.RUnlock()

	// Load current snapshot for bucket reuse.
	old := t.snap.Load()

	newUUIDMap := make(map[string]int, len(currentUsers))
	newBuckets := make(map[int]*rate.Limiter, len(currentUsers))

	for _, user := range currentUsers {
		if user.UUID != "" {
			newUUIDMap[user.UUID] = user.ID
		}

		if user.SpeedLimit > 0 {
			bytesPerSec := int(user.SpeedLimit) * 1_000_000 / 8
			burst := bytesPerSec
			if burst < 64*1024 {
				burst = 64 * 1024
			}
			if cap4s := bytesPerSec * 4; cap4s > 64*1024 && burst > cap4s {
				burst = cap4s
			}

			// Reuse existing limiter if present (avoids resetting token bucket).
			if lim, ok := old.buckets[user.ID]; ok {
				lim.SetLimit(rate.Limit(bytesPerSec))
				lim.SetBurst(burst)
				newBuckets[user.ID] = lim
			} else {
				newBuckets[user.ID] = rate.NewLimiter(rate.Limit(bytesPerSec), burst)
			}
		}
		// Users with SpeedLimit <= 0 are not copied → their old bucket is dropped.
	}

	// Publish new immutable snapshot (single atomic pointer swap).
	t.snap.Store(&speedSnapshot{
		uuidMap: newUUIDMap,
		buckets: newBuckets,
	})

	if t.logFunc != nil {
		t.logFunc("buckets updated")
	}
}

// GetLimiter returns the rate limiter for the given user UUID, or nil if
// no limit applies. Creates limiter on-demand if not exists.
// Thread-safe. Lock-free fast path (atomic pointer load + map lookup).
func (t *SpeedTracker) GetLimiter(user string) *rate.Limiter {
	s := t.snap.Load()

	uid, exists := s.uuidMap[user]
	if !exists {
		return nil
	}
	if lim, ok := s.buckets[uid]; ok {
		return lim
	}

	// No bucket yet — user has SpeedLimit but hasn't connected before.
	// Look up user info to create on-demand.
	t.limiter.mu.RLock()
	u, userExists := t.limiter.users[uid]
	t.limiter.mu.RUnlock()

	if !userExists || u.SpeedLimit <= 0 {
		return nil
	}

	// Create limiter on-demand under write lock.
	bytesPerSec := int(u.SpeedLimit) * 1_000_000 / 8
	burst := bytesPerSec
	if burst < 64*1024 {
		burst = 64 * 1024
	}
	if cap4s := bytesPerSec * 4; cap4s > 64*1024 && burst > cap4s {
		burst = cap4s
	}

	lim := rate.NewLimiter(rate.Limit(bytesPerSec), burst)

	t.mu.Lock()
	// Re-check under lock: another goroutine may have created it.
	cur := t.snap.Load()
	if existing, ok := cur.buckets[uid]; ok {
		t.mu.Unlock()
		return existing
	}
	// Extend the snapshot with the new bucket.
	extended := make(map[int]*rate.Limiter, len(cur.buckets)+1)
	for k, v := range cur.buckets {
		extended[k] = v
	}
	extended[uid] = lim
	t.snap.Store(&speedSnapshot{uuidMap: cur.uuidMap, buckets: extended})
	t.mu.Unlock()

	return lim
}

// HasLimits returns true if any user currently has a speed limit configured.
func (t *SpeedTracker) HasLimits() bool {
	return len(t.snap.Load().buckets) > 0
}

// LimitedUserCount returns the number of users with active speed limits.
func (t *SpeedTracker) LimitedUserCount() int {
	return len(t.snap.Load().buckets)
}
