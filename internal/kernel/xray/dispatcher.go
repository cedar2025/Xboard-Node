package xray

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
	_ "unsafe"

	xrayDispatcher "github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"golang.org/x/time/rate"

	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

// Access xray's internal config creator registry so we can replace the
// default dispatcher factory with ours. This runs AFTER xray's init()
// functions because our package imports xray (dependency order guarantee).
//
//go:linkname typeCreatorRegistry github.com/xtls/xray-core/common.typeCreatorRegistry
var typeCreatorRegistry map[reflect.Type]common.ConfigCreator

var origDispatcherFactory common.ConfigCreator

// globalLimitDispatcher is set when the factory creates a LimitDispatcher.
// The Xray kernel reads it to configure limits and get connections.
var globalLimitDispatcher atomic.Pointer[LimitDispatcher]

func init() {
	configType := reflect.TypeOf((*xrayDispatcher.Config)(nil))
	origDispatcherFactory = typeCreatorRegistry[configType]
	typeCreatorRegistry[configType] = limitDispatcherFactory
}

func limitDispatcherFactory(ctx context.Context, config interface{}) (interface{}, error) {
	orig, err := origDispatcherFactory(ctx, config)
	if err != nil {
		return nil, err
	}
	inner, ok := orig.(routing.Dispatcher)
	if !ok {
		return orig, nil
	}
	ld := &LimitDispatcher{
		inner:      orig,
		innerDisp:  inner,
		limitedIPs: make(map[string]map[string]int),
	}
	globalLimitDispatcher.Store(ld)
	nlog.Core().Debug("xray: limit dispatcher installed")
	return ld, nil
}

// LimitDispatcher wraps xray's DefaultDispatcher to enforce per-user
// admission checks before a request is dispatched into xray-core.
//
// It does NOT mutate the links of Dispatch: xray's mux/XUDP close path
// requires the original concrete *pipe.Reader to remain intact. The only link
// it touches is the inbound's own link handed to DispatchLink, whose uplink
// reader it rate-limits for speed-limited users (see limitUplink).
type LimitDispatcher struct {
	inner     interface{}        // original DefaultDispatcher (Feature + Dispatcher)
	innerDisp routing.Dispatcher // same object, typed as Dispatcher

	// limitedUsers: users with device limit > 0, protected by mu.
	// Needs deterministic IP ordering for kick decisions.
	mu           sync.RWMutex
	limitedIPs   map[string]map[string]int // email → sourceIP → refcount
	deviceLimits map[string]int            // email → max devices
	speedLimits  map[string]int            // email → Mbps, users with a speed limit only
	emailToUID   map[string]int            // email → panel user ID
	// uploadLimiters: email → upload limiter of speed-limited users. The
	// downlink is throttled by xray-core with a separate download limiter.
	uploadLimiters map[string]*rate.Limiter
	// departed: when a limited user's IP last went offline here.
	departed map[string]map[string]time.Time // email → sourceIP → time

	// unlimitedIPs: users without device limit — sync.Map for lock-free access.
	// Each entry is *ipCounter{ips sync.Map}.
	unlimitedIPs sync.Map // email → *ipCounter

	connCount atomic.Int64 // total active connections tracked by dispatcher

	// links holds live dispatched links so UpdateLimits can interrupt those
	// of removed users. linksMu is taken before mu, never after.
	linksMu  sync.Mutex
	links    map[uint64]trackedLink
	nextLink uint64

	globalMu         sync.RWMutex
	globalDevices    map[int]map[string]bool // userID → IPs online on any node
	globalLastUpdate time.Time
}

type trackedLink struct {
	email    string
	sourceIP string
	limited  bool // counted toward the user's device limit
	link     *transport.Link
	conn     net.Conn // client connection from the inbound session; may be nil
}

// errUserRemoved rejects sessions whose user is no longer on this node.
var errUserRemoved = errors.New("xray: user removed")

// ipCounter tracks IPs for unlimited users without any lock.
type ipCounter struct {
	ips sync.Map // sourceIP → *atomic.Int64 (refcount)
}

// aliveIPs returns a snapshot of distinct IPs.
func (ic *ipCounter) aliveIPs() map[string]bool {
	result := make(map[string]bool)
	ic.ips.Range(func(key, _ interface{}) bool {
		if rv, ok := ic.ips.Load(key); ok && rv.(*atomic.Int64).Load() > 0 {
			result[key.(string)] = true
		}
		return true
	})
	return result
}

// ─── routing.Dispatcher ──────────────────────────────────────────────────────

func (d *LimitDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	email, sourceIP, limited, err := d.identifyAndCheck(ctx)
	if err != nil {
		return nil, err
	}

	link, err := d.innerDisp.Dispatch(ctx, dest)
	if err != nil {
		if email != "" {
			d.delConn(email, sourceIP, limited)
		}
		return nil, err
	}

	if email != "" && !d.trackLink(ctx, link, email, sourceIP, limited) {
		return nil, errUserRemoved
	}
	return link, nil
}

func (d *LimitDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	email, sourceIP, limited, err := d.identifyAndCheck(ctx)
	if err != nil {
		return err
	}

	if email != "" && !d.trackLink(ctx, link, email, sourceIP, limited) {
		return errUserRemoved
	}
	if email != "" && d.speedLimited(email) {
		d.limitUplink(ctx, link, email)
	}
	return d.innerDisp.DispatchLink(ctx, dest, link)
}

// limitUplink throttles what a speed-limited user sends. xray-core's WrapLink
// rate-limits only the writer (downlink) of a link handed in through
// DispatchLink, which is how VLESS dispatches, so uploads ran at full speed.
// The uplink has its own limiter, so upload and download are each capped at
// the speed limit, as for sing-box users.
func (d *LimitDispatcher) limitUplink(ctx context.Context, link *transport.Link, email string) {
	d.mu.RLock()
	lim := d.uploadLimiters[email]
	d.mu.RUnlock()
	if lim != nil {
		link.Reader = &rateLimitedReader{Reader: link.Reader, limiter: lim, ctx: ctx}
	}
}

// SetUploadLimiters replaces the upload limiters of speed-limited users.
func (d *LimitDispatcher) SetUploadLimiters(limiters map[string]*rate.Limiter) {
	d.mu.Lock()
	d.uploadLimiters = limiters
	d.mu.Unlock()
}

// rateLimitedReader waits for limiter tokens for every buffer it reads.
type rateLimitedReader struct {
	buf.Reader
	limiter *rate.Limiter
	ctx     context.Context
}

func (r *rateLimitedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	// WaitN rejects requests above the burst, so wait in burst-sized steps.
	for n := int(mb.Len()); n > 0; {
		step := min(n, r.limiter.Burst())
		if werr := r.limiter.WaitN(r.ctx, step); werr != nil {
			buf.ReleaseMulti(mb)
			return nil, werr
		}
		n -= step
	}
	return mb, err
}

func (r *rateLimitedReader) Interrupt()   { common.Interrupt(r.Reader) }
func (r *rateLimitedReader) Close() error { return common.Close(r.Reader) }

// identifyAndCheck extracts user identity from the session context, enforces
// device limits, and returns the user's email and source IP, plus whether
// the connection was counted as a limited user's. TCP and UDP links both
// count toward the device limit. Returns a non-nil error only when the
// connection should be rejected.
func (d *LimitDispatcher) identifyAndCheck(ctx context.Context) (email, sourceIP string, limited bool, err error) {
	si := session.InboundFromContext(ctx)
	if si == nil || si.User == nil || len(si.User.Email) == 0 {
		return "", "", false, nil
	}
	email = si.User.Email
	sourceIP = si.Source.Address.IP().String()

	// A mux connection authenticated before its user was removed keeps
	// dispatching sub-streams under the old identity.
	if !d.knownUser(email) {
		nlog.Core().Debug("xray: rejecting removed user", "email", email, "ip", sourceIP)
		return "", "", false, errUserRemoved
	}

	rejected, limited := d.checkDeviceLimit(email, sourceIP)
	if rejected {
		nlog.Core().Debug("xray: device limit exceeded", "email", email, "ip", sourceIP)
		return "", "", false, errors.New("device limit exceeded for " + email)
	}

	// Splice copy moves bytes in the kernel, past xray-core's rate limiter
	// and, once the limiter wraps the writer, past the user traffic counter.
	if d.speedLimited(email) {
		si.CanSpliceCopy = 3
	}
	return email, sourceIP, limited, nil
}

// speedLimited reports whether email has a speed limit.
func (d *LimitDispatcher) speedLimited(email string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.speedLimits[email] > 0
}

// trackLink records connection lifecycle without mutating xray-core owned
// transport primitives. This keeps mux/XUDP compatible while still allowing
// the dispatcher to release device-limit state when the link closes.
//
// The link is registered under linksMu after re-checking the user, the same
// lock UpdateLimits holds while it swaps users and picks links to interrupt,
// so a link is either rejected here or interrupted by that update. It returns
// false, with the link already interrupted, when the user was removed.
func (d *LimitDispatcher) trackLink(ctx context.Context, link *transport.Link, email, sourceIP string, limited bool) bool {
	d.connCount.Add(1)

	var id uint64
	onClose := func() {
		d.delConn(email, sourceIP, limited)
		d.connCount.Add(-1)
		d.linksMu.Lock()
		delete(d.links, id)
		d.linksMu.Unlock()
	}

	link.Writer = &closeTrackingWriter{
		Writer:  link.Writer,
		onClose: onClose,
	}

	tl := trackedLink{email: email, sourceIP: sourceIP, limited: limited, link: link}
	if si := session.InboundFromContext(ctx); si != nil {
		tl.conn = si.Conn
	}
	d.linksMu.Lock()
	if !d.knownUser(email) {
		d.linksMu.Unlock()
		tl.close()
		return false
	}
	if d.links == nil {
		d.links = make(map[uint64]trackedLink)
	}
	d.nextLink++
	id = d.nextLink
	d.links[id] = tl
	d.linksMu.Unlock()
	return true
}

// knownUser reports whether email belongs to a current user. Until the
// kernel supplies users every session is admitted.
func (d *LimitDispatcher) knownUser(email string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.emailToUID == nil {
		return true
	}
	_, ok := d.emailToUID[email]
	return ok
}

// close interrupts the link and closes the client connection behind it.
// Links an inbound builds over its own connection (plain VLESS, splice copy)
// only stop when that connection closes; for a mux sub-stream it is the
// authenticated mux connection, which ends the removed user's session.
func (tl trackedLink) close() {
	common.Interrupt(tl.link.Reader)
	common.Interrupt(tl.link.Writer)
	if tl.conn != nil {
		tl.conn.Close()
	}
}

// ─── features.Feature (delegated) ───────────────────────────────────────────

func (d *LimitDispatcher) Type() interface{} { return routing.DispatcherType() }

func (d *LimitDispatcher) Start() error {
	if s, ok := d.inner.(interface{ Start() error }); ok {
		return s.Start()
	}
	return nil
}

func (d *LimitDispatcher) Close() error {
	if c, ok := d.inner.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}

// ─── Limit management (called by Xray kernel) ──────────────────────────────

// UpdateLimits replaces the user set and interrupts the live links of users
// that are no longer present: removing a user from the inbound only stops new
// handshakes, while established connections and mux sessions would go on.
func (d *LimitDispatcher) UpdateLimits(emailToUID map[string]int, deviceLimits, speedLimits map[string]int) {
	d.linksMu.Lock()
	d.mu.Lock()
	d.emailToUID = emailToUID
	d.deviceLimits = deviceLimits
	d.speedLimits = speedLimits
	d.pruneDeparted(time.Now())
	d.mu.Unlock()
	var revoked []trackedLink
	if emailToUID != nil {
		for _, tl := range d.links {
			if _, ok := emailToUID[tl.email]; !ok {
				revoked = append(revoked, tl)
			}
		}
	}
	d.linksMu.Unlock()

	// Close outside linksMu: closing a link deregisters it.
	for _, tl := range revoked {
		tl.close()
	}
	if len(revoked) > 0 {
		nlog.Core().Info("xray: closed connections of removed users", "connections", len(revoked))
	}
}

// globalDevicesTTL is how long panel-pushed device state stays usable.
const globalDevicesTTL = 60 * time.Second

// UpdateGlobalDevices stores the IPs the panel reports online per user
// across all nodes, then disconnects local devices the new state shows to be
// over a user's limit. The map is replaced, never modified in place.
func (d *LimitDispatcher) UpdateGlobalDevices(users map[int][]string) {
	devices := make(map[int]map[string]bool, len(users))
	for uid, ips := range users {
		set := make(map[string]bool, len(ips))
		for _, ip := range ips {
			set[ip] = true
		}
		devices[uid] = set
	}
	d.globalMu.Lock()
	d.globalDevices = devices
	d.globalLastUpdate = time.Now()
	d.globalMu.Unlock()
	d.disconnectOverLimit()
}

// disconnectOverLimit closes the links of local devices that put a user over
// the device limit. Admission cannot prevent this alone: two nodes can each
// admit a new device before the panel tells them about the other.
func (d *LimitDispatcher) disconnectOverLimit() {
	d.linksMu.Lock()
	d.mu.RLock()
	over := make(map[string]map[string]bool)
	for email, local := range d.limitedIPs {
		for _, ip := range kernel.OverLimitDevices(local, d.devicesElsewhere(email), d.deviceLimits[email]) {
			if over[email] == nil {
				over[email] = make(map[string]bool)
			}
			over[email][ip] = true
			nlog.Core().Info("xray: disconnecting device over the limit",
				"user", d.emailToUID[email], "ip", ip, "limit", d.deviceLimits[email])
		}
	}
	d.mu.RUnlock()
	var revoked []trackedLink
	if len(over) > 0 {
		for _, tl := range d.links {
			if tl.limited && over[tl.email][tl.sourceIP] {
				revoked = append(revoked, tl)
			}
		}
	}
	d.linksMu.Unlock()

	// Close outside linksMu: closing a link deregisters it.
	for _, tl := range revoked {
		tl.close()
	}
}

// ClearGlobalDevices drops panel device state (WS disconnected).
func (d *LimitDispatcher) ClearGlobalDevices() {
	d.globalMu.Lock()
	d.globalDevices = nil
	d.globalLastUpdate = time.Time{}
	d.globalMu.Unlock()
}

// freshGlobalDevices returns the user's IPs online across nodes and when the
// panel sent them, or nil when the panel state is missing or older than
// globalDevicesTTL.
func (d *LimitDispatcher) freshGlobalDevices(uid int) (map[string]bool, time.Time) {
	d.globalMu.RLock()
	defer d.globalMu.RUnlock()
	if uid == 0 || time.Since(d.globalLastUpdate) > globalDevicesTTL {
		return nil, time.Time{}
	}
	return d.globalDevices[uid], d.globalLastUpdate
}

// devicesElsewhere returns the user's IPs online on other nodes. The panel's
// global state includes the devices this node reported and trails them, so an
// IP that left this node less than kernel.DeviceEchoWindow before the state
// arrived is taken for an echo of this node's own report and left out.
// The caller holds d.mu.
func (d *LimitDispatcher) devicesElsewhere(email string) map[string]bool {
	global, received := d.freshGlobalDevices(d.emailToUID[email])
	departed := d.departed[email]
	if len(global) == 0 || len(departed) == 0 {
		return global
	}
	elsewhere := make(map[string]bool, len(global))
	for ip := range global {
		if left, ok := departed[ip]; ok && received.Before(left.Add(kernel.DeviceEchoWindow)) {
			continue
		}
		elsewhere[ip] = true
	}
	return elsewhere
}

// pruneDeparted forgets departures too old to match any global state that is
// still fresh. The caller holds d.mu.
func (d *LimitDispatcher) pruneDeparted(now time.Time) {
	cutoff := now.Add(-kernel.DeviceEchoWindow - globalDevicesTTL)
	for email, ips := range d.departed {
		for ip, left := range ips {
			if left.Before(cutoff) {
				delete(ips, ip)
			}
		}
		if len(ips) == 0 {
			delete(d.departed, email)
		}
	}
}

func (d *LimitDispatcher) ResetConns() {
	d.mu.Lock()
	d.limitedIPs = make(map[string]map[string]int)
	d.departed = nil
	d.mu.Unlock()

	// Clear unlimited IPs
	d.unlimitedIPs.Range(func(key, _ interface{}) bool {
		d.unlimitedIPs.Delete(key)
		return true
	})

	d.connCount.Store(0)
}

// GetConnectionState returns dispatcher-tracked alive IPs and connection count.
// Traffic bytes are intentionally left to xray's built-in stats pipeline.
func (d *LimitDispatcher) GetConnectionState() (aliveIPs map[int]map[string]bool, connCount int) {
	aliveIPs = make(map[int]map[string]bool)

	d.mu.RLock()
	emailToUID := make(map[string]int, len(d.emailToUID))
	for email, uid := range d.emailToUID {
		emailToUID[email] = uid
	}

	// Copy limited-user state while connection updates are blocked by RLock.
	for email, ipsMap := range d.limitedIPs {
		uid := emailToUID[email]
		if uid == 0 {
			continue
		}
		ipSet := make(map[string]bool, len(ipsMap))
		for ip := range ipsMap {
			ipSet[ip] = true
		}
		if len(ipSet) > 0 {
			aliveIPs[uid] = ipSet
		}
	}
	d.mu.RUnlock()

	// Collect IPs from unlimited users (lock-free).
	d.unlimitedIPs.Range(func(key, value interface{}) bool {
		email := key.(string)
		uid := emailToUID[email]
		if uid == 0 {
			return true
		}
		ic := value.(*ipCounter)
		if ips := ic.aliveIPs(); len(ips) > 0 {
			// Merge with limited IPs if any
			if existing, ok := aliveIPs[uid]; ok {
				for ip := range ips {
					existing[ip] = true
				}
			} else {
				aliveIPs[uid] = ips
			}
		}
		return true
	})

	connCount = int(d.connCount.Load())
	return
}

// ─── Internal helpers ───────────────────────────────────────────────────────

// checkDeviceLimit enforces per-user device limits and counts the connection
// when it is admitted. limited reports which table holds the count; delConn
// needs it back, since the user's limit may change while the link is open.
// Fast path: unlimited users use lock-free sync.Map.
// Slow path: limited users use RWMutex.
func (d *LimitDispatcher) checkDeviceLimit(email, sourceIP string) (rejected, limited bool) {
	d.mu.RLock()
	limit, hasLimit := d.deviceLimits[email]
	d.mu.RUnlock()

	// Fast path: no device limit — use lock-free sync.Map.
	if !hasLimit || limit <= 0 {
		v, _ := d.unlimitedIPs.LoadOrStore(email, &ipCounter{})
		ic := v.(*ipCounter)

		// Increment IP refcount atomically.
		rv, _ := ic.ips.LoadOrStore(sourceIP, &atomic.Int64{})
		rv.(*atomic.Int64).Add(1)
		return false, false
	}

	// Keep limited-user admission and refcount changes in one critical section.
	// delConn can delete the user's map when its last connection closes, so
	// neither the map nor its capacity may be reused across a lock upgrade.
	d.mu.Lock()
	defer d.mu.Unlock()

	ips := d.limitedIPs[email]
	if !kernel.AdmitDevice(ips, d.devicesElsewhere(email), sourceIP, limit) {
		return true, true
	}
	if ips == nil {
		ips = make(map[string]int)
		d.limitedIPs[email] = ips
	}
	ips[sourceIP]++
	return false, true
}

// delConn decrements the IP refcount when a connection closes. limited is
// the table checkDeviceLimit counted the connection in.
func (d *LimitDispatcher) delConn(email, sourceIP string, limited bool) {
	if !limited {
		if v, ok := d.unlimitedIPs.Load(email); ok {
			ic := v.(*ipCounter)
			if rv, ok := ic.ips.Load(sourceIP); ok {
				counter := rv.(*atomic.Int64)
				if counter.Add(-1) <= 0 {
					ic.ips.Delete(sourceIP)
				}
			}
		}
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	ips, ok := d.limitedIPs[email]
	if !ok {
		return
	}
	ips[sourceIP]--
	if ips[sourceIP] <= 0 {
		delete(ips, sourceIP)
		d.markDeparted(email, sourceIP)
	}
	if len(ips) == 0 {
		delete(d.limitedIPs, email)
	}
}

// markDeparted records that the user's IP just went offline here. The caller
// holds d.mu.
func (d *LimitDispatcher) markDeparted(email, sourceIP string) {
	if d.departed == nil {
		d.departed = make(map[string]map[string]time.Time)
	}
	ips := d.departed[email]
	if ips == nil {
		ips = make(map[string]time.Time)
		d.departed[email] = ips
	}
	ips[sourceIP] = time.Now()
}

type closeTrackingWriter struct {
	buf.Writer
	onClose func()
	closed  atomic.Bool
}

func (w *closeTrackingWriter) Close() error {
	if w.closed.CompareAndSwap(false, true) {
		w.onClose()
	}
	return common.Close(w.Writer)
}

func (w *closeTrackingWriter) Interrupt() {
	if w.closed.CompareAndSwap(false, true) {
		w.onClose()
	}
	common.Interrupt(w.Writer)
}
