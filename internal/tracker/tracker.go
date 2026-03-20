package tracker

import (
	"log/slog"

	"github.com/cedar2025/xboard-node/internal/kernel"
)

const (
	// DefaultMaxConnState caps how many connection-state entries we maintain.
	// Prevents unbounded memory growth from rogue / DDoS connection floods.
	DefaultMaxConnState = 100_000

	// DefaultMaxAliveIPsPerUser caps the per-user IP set tracked per push interval.
	// 200 IPs per user is generous for any legitimate use case.
	DefaultMaxAliveIPsPerUser = 200
)

// Tracker tracks per-connection traffic deltas and accumulates per-user totals.
//
// Thread safety model: Tracker is designed for SINGLE-GOROUTINE use only.
// All methods (Process, Flush*, Restore*, CurrentOnline, speed accessors) are
// called exclusively from the service goroutine's select loop. No internal
// locking is provided. Do NOT call Tracker methods from multiple goroutines.
//
// Hot-path optimisation (②): activeConns is allocated once and cleared in-place
// every Process() call instead of being reallocated, saving GC pressure at high
// connection counts.
//
// OOM protection (④): connState and aliveIPs are capped at configurable maximums.
type Tracker struct {
	connState map[string][2]int64     // conn_id → last [upload, download]
	traffic   map[int][2]int64        // user_id → accumulated [upload, download]
	aliveIPs  map[int]map[string]bool // user_id → set of source IPs
	online    map[int]int             // user_id → unique device count (unique IPs)

	// ② Reused buffer: cleared each Process() call, not reallocated.
	activeConns map[string]struct{}

	// ④ Limits (set at construction, never mutated).
	maxConnState       int
	maxAliveIPsPerUser int

	// lastActiveConns stores the last observed number of active connections.
	// This is updated on each Process() call and read by the service when
	// building node metrics for panel reporting.
	lastActiveConns int
	totalConns      int64 // cumulative number of connections seen since startup

	// lastUserCount is used to pre-size intervalTraffic each cycle, avoiding
	// repeated map rehashing under heavy user counts.
	lastUserCount int

	inSpeed  int64
	outSpeed int64
}

func New() *Tracker {
	return NewWithLimits(DefaultMaxConnState, DefaultMaxAliveIPsPerUser)
}

func NewWithLimits(maxConnState, maxAliveIPsPerUser int) *Tracker {
	return &Tracker{
		connState:          make(map[string][2]int64),
		traffic:            make(map[int][2]int64),
		aliveIPs:           make(map[int]map[string]bool),
		online:             make(map[int]int),
		activeConns:        make(map[string]struct{}),
		maxConnState:       maxConnState,
		maxAliveIPsPerUser: maxAliveIPsPerUser,
	}
}

// Process calculates per-user traffic deltas for this interval.
// Internally accumulates totals for panel push and tracks alive IPs.
// Returns per-user interval traffic [upload, download] for the limiter.
func (t *Tracker) Process(conns []kernel.Connection) map[int][2]int64 {
	// Pre-size using last cycle's user count to avoid rehashing under heavy load.
	intervalTraffic := make(map[int][2]int64, t.lastUserCount)

	// Clear activeConns in-place (no alloc, backing array retained).
	for k := range t.activeConns {
		delete(t.activeConns, k)
	}

	// Rebuild aliveIPs each cycle so only currently-active IPs are reported.
	// Previously, IPs accumulated across cycles leading to stale entries.
	for uid := range t.aliveIPs {
		for ip := range t.aliveIPs[uid] {
			delete(t.aliveIPs[uid], ip)
		}
	}

	// Clear online counts (will be rebuilt from unique IPs below)
	for uid := range t.online {
		delete(t.online, uid)
	}

	for _, conn := range conns {
		t.activeConns[conn.ID] = struct{}{}

		if conn.UserID == 0 {
			continue
		}

		var deltaUp, deltaDown int64
		prev, exists := t.connState[conn.ID]
		if exists {
			deltaUp = conn.Upload - prev[0]
			deltaDown = conn.Download - prev[1]
			if deltaUp < 0 {
				deltaUp = conn.Upload
			}
			if deltaDown < 0 {
				deltaDown = conn.Download
			}
		} else {
			// ④ New connection: only track if below the state cap.
			if len(t.connState) >= t.maxConnState {
				slog.Debug("connState cap reached, skipping new connection",
					"cap", t.maxConnState, "conn_id", conn.ID)
				continue
			}
			deltaUp = conn.Upload
			deltaDown = conn.Download
			t.totalConns++
		}
		t.connState[conn.ID] = [2]int64{conn.Upload, conn.Download}

		if deltaUp > 0 || deltaDown > 0 {
			cur := t.traffic[conn.UserID]
			cur[0] += deltaUp
			cur[1] += deltaDown
			t.traffic[conn.UserID] = cur

			it := intervalTraffic[conn.UserID]
			it[0] += deltaUp
			it[1] += deltaDown
			intervalTraffic[conn.UserID] = it
		}

		// ④ Track alive IPs, capped per user.
		if conn.SourceIP != "" {
			ips := t.aliveIPs[conn.UserID]
			if ips == nil {
				ips = make(map[string]bool)
				t.aliveIPs[conn.UserID] = ips
			}
			if len(ips) < t.maxAliveIPsPerUser {
				ips[conn.SourceIP] = true
			}
		}
	}

	// Rebuild online counts from unique IPs (device count, not connection count).
	// This ensures online[uid] == number of distinct source IPs for that user.
	for uid, ips := range t.aliveIPs {
		if n := len(ips); n > 0 {
			t.online[uid] = n
		}
	}

	// Cleanup stale connState entries for connections that are no longer active.
	for id := range t.connState {
		if _, active := t.activeConns[id]; !active {
			delete(t.connState, id)
		}
	}

	// Snapshot current active connection count for metrics reporting.
	t.lastActiveConns = len(t.connState)

	// Derive speed directly from intervalTraffic deltas accumulated this cycle.
	// This avoids the negative-diff bug that occurs when connState entries for
	// closed connections are removed, which made cumulative totals drop and
	// clamped speed to 0 for one cycle after a mass disconnect.
	var cycleIn, cycleOut int64
	for _, it := range intervalTraffic {
		cycleOut += it[0]
		cycleIn += it[1]
	}
	t.inSpeed = cycleIn
	t.outSpeed = cycleOut

	// Update hint for next cycle's map pre-sizing.
	if n := len(intervalTraffic); n > 0 {
		t.lastUserCount = n
	}

	return intervalTraffic
}

// FlushTraffic returns accumulated per-user traffic and resets the counter.
func (t *Tracker) FlushTraffic() map[int][2]int64 {
	data := t.traffic
	t.traffic = make(map[int][2]int64, len(data))
	return data
}

// RestoreTraffic adds traffic back (used when push to panel fails).
func (t *Tracker) RestoreTraffic(data map[int][2]int64) {
	for uid, d := range data {
		cur := t.traffic[uid]
		cur[0] += d[0]
		cur[1] += d[1]
		t.traffic[uid] = cur
	}
}

// HasTraffic returns true if there is accumulated traffic to report.
func (t *Tracker) HasTraffic() bool {
	return len(t.traffic) > 0
}

// FlushAliveIPs returns per-user alive IPs and resets the tracker.
func (t *Tracker) FlushAliveIPs() map[int][]string {
	data := make(map[int][]string, len(t.aliveIPs))
	for uid, ips := range t.aliveIPs {
		ipList := make([]string, 0, len(ips))
		for ip := range ips {
			ipList = append(ipList, ip)
		}
		data[uid] = ipList
	}
	t.aliveIPs = make(map[int]map[string]bool, len(t.aliveIPs))
	return data
}

// FlushOnline returns a snapshot of per-user online device counts and resets.
// This makes online consistent with FlushTraffic/FlushAliveIPs: the caller
// gets an owned copy and the tracker starts fresh.
func (t *Tracker) FlushOnline() map[int]int {
	data := t.online
	t.online = make(map[int]int, len(data))
	return data
}

// RestoreOnline merges online counts back (used when push to panel fails).
func (t *Tracker) RestoreOnline(data map[int]int) {
	for uid, count := range data {
		if count > t.online[uid] {
			t.online[uid] = count
		}
	}
}

// CurrentOnline returns a reference to the current online map (read-only).
// Prefer FlushOnline for report pushes to ensure atomicity with restore.
func (t *Tracker) CurrentOnline() map[int]int {
	return t.online
}

// RestoreAliveIPs merges alive IPs back in (used when push to panel fails).
func (t *Tracker) RestoreAliveIPs(data map[int][]string) {
	for uid, ipList := range data {
		ips := t.aliveIPs[uid]
		if ips == nil {
			ips = make(map[string]bool, len(ipList))
			t.aliveIPs[uid] = ips
		}
		for _, ip := range ipList {
			if len(ips) < t.maxAliveIPsPerUser {
				ips[ip] = true
			}
		}
	}
}

// LogStats logs current tracking statistics.
func (t *Tracker) LogStats() {
	slog.Debug("tracker stats",
		"active_connections", len(t.connState),
		"users_with_traffic", len(t.traffic),
		"users_with_ips", len(t.aliveIPs),
	)
}

// ActiveConnections returns the last observed active connection count.
// This is cheap and safe because Tracker is only mutated from the service
// goroutine; reads happen from the same goroutine when pushing reports.
func (t *Tracker) ActiveConnections() int {
	return t.lastActiveConns
}

// TotalConnections returns the cumulative connection count since startup.
func (t *Tracker) TotalConnections() int64 {
	return t.totalConns
}

// InboundSpeed returns the last observed inbound (download) speed in bytes/second.
// Process() is called every 10 seconds, so we divide the 10-second total by 10.
func (t *Tracker) InboundSpeed() int64 {
	return t.inSpeed / 10
}

// OutboundSpeed returns the last observed outbound (upload) speed in bytes/second.
// Process() is called every 10 seconds, so we divide the 10-second total by 10.
func (t *Tracker) OutboundSpeed() int64 {
	return t.outSpeed / 10
}
