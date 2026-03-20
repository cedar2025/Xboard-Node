package xray

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
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
		inner:     orig,
		innerDisp: inner,
		conns:     make(map[string]*dispatchedConn),
		userIPs:   make(map[string]map[string]int),
	}
	globalLimitDispatcher.Store(ld)
	slog.Debug("xray: limit dispatcher installed")
	return ld, nil
}

// maxConns caps the xray dispatcher's connection map to prevent OOM under
// connection floods. This is analogous to sing-box's maxPending.
const maxConns = 100_000

// LimitDispatcher wraps xray's DefaultDispatcher to add per-user device
// limit enforcement, speed limiting, and per-connection source IP tracking.
// It hooks into Dispatch/DispatchLink which are called AFTER the protocol
// handler has identified the user, so it works for ALL protocols.
type LimitDispatcher struct {
	inner     interface{}        // original DefaultDispatcher (Feature + Dispatcher)
	innerDisp routing.Dispatcher // same object, typed as Dispatcher

	mu           sync.RWMutex
	conns        map[string]*dispatchedConn // connID → conn
	userIPs      map[string]map[string]int  // email → sourceIP → count
	deviceLimits map[string]int             // email → max devices
	speedLimits  map[string]int             // email → Mbps
	speedBuckets sync.Map                   // email → *rate.Limiter
	emailToUID   map[string]int             // email → panel user ID

	connIDSeq atomic.Uint64
}

type dispatchedConn struct {
	id       string
	email    string
	sourceIP string
	userID   int
	upload   atomic.Int64
	download atomic.Int64
	closed   atomic.Bool
}

// ─── routing.Dispatcher ──────────────────────────────────────────────────────

func (d *LimitDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	email, sourceIP, isTCP, err := d.identifyAndCheck(ctx, dest)
	if err != nil {
		return nil, err
	}

	link, err := d.innerDisp.Dispatch(ctx, dest)
	if err != nil {
		if email != "" && isTCP {
			d.delConn(email, sourceIP)
		}
		return nil, err
	}

	if email != "" {
		d.wrapLink(ctx, link, email, sourceIP, isTCP)
	}
	return link, nil
}

func (d *LimitDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	email, sourceIP, isTCP, err := d.identifyAndCheck(ctx, dest)
	if err != nil {
		return err
	}

	if email != "" {
		d.wrapLink(ctx, link, email, sourceIP, isTCP)
	}
	return d.innerDisp.DispatchLink(ctx, dest, link)
}

// identifyAndCheck extracts user identity from the session context, enforces
// device limits, and returns the user's email, source IP, and TCP flag.
// Returns a non-nil error only when the connection should be rejected.
func (d *LimitDispatcher) identifyAndCheck(ctx context.Context, dest net.Destination) (email, sourceIP string, isTCP bool, err error) {
	si := session.InboundFromContext(ctx)
	if si == nil || si.User == nil || len(si.User.Email) == 0 {
		return "", "", false, nil
	}
	email = si.User.Email
	sourceIP = si.Source.Address.IP().String()
	isTCP = dest.Network == net.Network_TCP

	if d.checkDeviceLimit(email, sourceIP, isTCP) {
		slog.Info("xray: device limit exceeded", "email", email, "ip", sourceIP)
		return "", "", false, errors.New("device limit exceeded for " + email)
	}
	return email, sourceIP, isTCP, nil
}

// wrapLink instruments a transport.Link with per-connection byte counting,
// rate limiting, and lifecycle tracking. Must only be called when email != "".
func (d *LimitDispatcher) wrapLink(ctx context.Context, link *transport.Link, email, sourceIP string, isTCP bool) {
	connID := "xd-" + strconv.FormatUint(d.connIDSeq.Add(1), 36)
	dc := &dispatchedConn{
		id:       connID,
		email:    email,
		sourceIP: sourceIP,
		userID:   d.getUID(email),
	}

	d.mu.Lock()
	if len(d.conns) >= maxConns {
		d.mu.Unlock()
		slog.Warn("xray: conns map at capacity, skipping tracking", "cap", maxConns, "email", email)
		return
	}
	d.conns[connID] = dc
	d.mu.Unlock()

	onClose := func() {
		if dc.closed.CompareAndSwap(false, true) {
			if isTCP {
				d.delConn(email, sourceIP)
			}
			d.mu.Lock()
			delete(d.conns, connID)
			d.mu.Unlock()
		}
	}

	limiter := d.getBucket(email)

	link.Reader = &statsCloseReader{
		Reader:  link.Reader,
		counter: &dc.upload,
		limiter: limiter,
		ctx:     ctx,
	}
	link.Writer = &statsCloseWriter{
		Writer:  link.Writer,
		counter: &dc.download,
		limiter: limiter,
		ctx:     ctx,
		onClose: onClose,
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

func (d *LimitDispatcher) UpdateLimits(emailToUID map[string]int, deviceLimits, speedLimits map[string]int) {
	d.mu.Lock()
	d.emailToUID = emailToUID
	d.deviceLimits = deviceLimits
	d.speedLimits = speedLimits
	d.mu.Unlock()

	d.speedBuckets.Range(func(key, _ interface{}) bool {
		if _, ok := speedLimits[key.(string)]; !ok {
			d.speedBuckets.Delete(key)
		}
		return true
	})
}

func (d *LimitDispatcher) ResetConns() {
	d.mu.Lock()
	d.conns = make(map[string]*dispatchedConn)
	d.userIPs = make(map[string]map[string]int)
	d.mu.Unlock()

	d.speedBuckets.Range(func(key, _ interface{}) bool {
		d.speedBuckets.Delete(key)
		return true
	})
}

func (d *LimitDispatcher) Snapshot() []kernel.Connection {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make([]kernel.Connection, 0, len(d.conns))
	for _, c := range d.conns {
		result = append(result, kernel.Connection{
			ID:       c.id,
			UserID:   c.userID,
			SourceIP: c.sourceIP,
			Upload:   c.upload.Load(),
			Download: c.download.Load(),
		})
	}
	return result
}

func (d *LimitDispatcher) CloseConn(id string) bool {
	d.mu.RLock()
	c, ok := d.conns[id]
	d.mu.RUnlock()
	if !ok {
		return false
	}
	c.closed.Store(true)
	d.delConn(c.email, c.sourceIP)
	d.mu.Lock()
	delete(d.conns, id)
	d.mu.Unlock()
	return true
}

// ─── Internal helpers ───────────────────────────────────────────────────────

func (d *LimitDispatcher) checkDeviceLimit(email, sourceIP string, isTCP bool) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	limit, hasLimit := d.deviceLimits[email]
	if !hasLimit || limit <= 0 {
		if isTCP {
			if d.userIPs[email] == nil {
				d.userIPs[email] = make(map[string]int)
			}
			d.userIPs[email][sourceIP]++
		}
		return false
	}

	ips := d.userIPs[email]
	if ips == nil {
		ips = make(map[string]int)
		d.userIPs[email] = ips
	}

	if ips[sourceIP] > 0 {
		if isTCP {
			ips[sourceIP]++
		}
		return false
	}

	if len(ips) < limit {
		if isTCP {
			ips[sourceIP]++
		}
		return false
	}

	// Over limit — deterministic: allow lowest IPs by numeric address.
	// Uses netip.Addr.Compare for consistency with the sing-box limiter,
	// avoiding lexicographic quirks (e.g. "10.x" vs "192.x", IPv6 ordering).
	type parsedIP struct {
		raw  string
		addr netip.Addr
	}
	ipList := make([]parsedIP, 0, len(ips)+1)
	for ip := range ips {
		a, _ := netip.ParseAddr(ip)
		ipList = append(ipList, parsedIP{raw: ip, addr: a})
	}
	srcAddr, _ := netip.ParseAddr(sourceIP)
	ipList = append(ipList, parsedIP{raw: sourceIP, addr: srcAddr})
	sort.Slice(ipList, func(i, j int) bool {
		return ipList[i].addr.Compare(ipList[j].addr) < 0
	})

	for i := 0; i < limit && i < len(ipList); i++ {
		if ipList[i].raw == sourceIP {
			if isTCP {
				ips[sourceIP]++
			}
			return false
		}
	}
	return true
}

func (d *LimitDispatcher) delConn(email, sourceIP string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if ips, ok := d.userIPs[email]; ok {
		ips[sourceIP]--
		if ips[sourceIP] <= 0 {
			delete(ips, sourceIP)
		}
		if len(ips) == 0 {
			delete(d.userIPs, email)
		}
	}
}

func (d *LimitDispatcher) getUID(email string) int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.emailToUID[email]
}

func (d *LimitDispatcher) getBucket(email string) *rate.Limiter {
	d.mu.RLock()
	mbps, ok := d.speedLimits[email]
	d.mu.RUnlock()
	if !ok || mbps <= 0 {
		return nil
	}
	bytesPerSec := int(mbps) * 1_000_000 / 8
	burst := bytesPerSec
	if burst < 64*1024 {
		burst = 64 * 1024
	}
	v, loaded := d.speedBuckets.LoadOrStore(email, rate.NewLimiter(rate.Limit(bytesPerSec), burst))
	lim := v.(*rate.Limiter)
	if loaded {
		// Update existing limiter in case speed limit changed.
		lim.SetLimit(rate.Limit(bytesPerSec))
		lim.SetBurst(burst)
	}
	return lim
}

// ─── I/O wrappers ───────────────────────────────────────────────────────────

type statsCloseReader struct {
	buf.Reader
	counter *atomic.Int64
	limiter *rate.Limiter
	ctx     context.Context
}

func (r *statsCloseReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	if n := int64(mb.Len()); n > 0 {
		r.counter.Add(n)
		if r.limiter != nil {
			waitN := int(n)
			if burst := r.limiter.Burst(); waitN > burst {
				waitN = burst
			}
			_ = r.limiter.WaitN(r.ctx, waitN)
		}
	}
	return mb, err
}

func (r *statsCloseReader) Close() error { return common.Close(r.Reader) }
func (r *statsCloseReader) Interrupt()   { common.Interrupt(r.Reader) }

type statsCloseWriter struct {
	buf.Writer
	counter *atomic.Int64
	limiter *rate.Limiter
	ctx     context.Context
	onClose func()
	closed  atomic.Bool
}

func (w *statsCloseWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	n := int64(mb.Len())
	if w.limiter != nil {
		waitN := int(n)
		if burst := w.limiter.Burst(); waitN > burst {
			waitN = burst
		}
		_ = w.limiter.WaitN(w.ctx, waitN)
	}
	w.counter.Add(n)
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *statsCloseWriter) Close() error {
	if w.closed.CompareAndSwap(false, true) {
		w.onClose()
	}
	return common.Close(w.Writer)
}

func (w *statsCloseWriter) Interrupt() {
	if w.closed.CompareAndSwap(false, true) {
		w.onClose()
	}
	common.Interrupt(w.Writer)
}
