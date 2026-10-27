// Package machine implements the machine-mode orchestrator that dynamically
// discovers nodes from the panel's machine API and manages their lifecycles.
package machine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/monitor"
	"github.com/cedar2025/xboard-node/internal/nlog"
	"github.com/cedar2025/xboard-node/internal/panel"
	"github.com/cedar2025/xboard-node/internal/service"
)

// Restart backoff for a node whose service exits on its own. A node is
// restarted by the next rediscover once its backoff has elapsed.
const (
	restartBackoffInitial = 10 * time.Second
	restartBackoffMax     = 5 * time.Minute
	// A node that ran at least this long before exiting starts its backoff afresh.
	restartResetAfter = 10 * time.Minute
)

// errNodeReturned stands in for the exit error of a service that returned
// nil although nobody asked it to stop.
var errNodeReturned = errors.New("node service returned without error")

// nodeRunner is the part of service.Service the orchestrator drives.
type nodeRunner interface {
	Run(ctx context.Context) error
}

// nodeHandle tracks a running node service.
type nodeHandle struct {
	cancel    context.CancelFunc
	done      chan struct{}
	mailbox   *controlplane.NodeMailbox
	startedAt time.Time
}

// restartState tracks a node whose service exited without being stopped.
type restartState struct {
	failures  int // consecutive exits
	notBefore time.Time
	lastErr   error
}

// Orchestrator manages all nodes bound to a panel machine. It:
//   - discovers nodes via GET /machine/nodes
//   - starts / stops Service instances as nodes are added / removed
//   - maintains a shared WS connection that demuxes events by node_id
//   - reports machine-level load via POST /machine/status
type Orchestrator struct {
	cfg    *config.Config
	client *panel.Client // machine-level client (no node_id)

	mu       sync.Mutex
	nodes    map[int]*nodeHandle   // node_id → handle
	restarts map[int]*restartState // node_id → pending restart after an exit

	// Per-node mailbox keyed by node_id. Shared WS events are aggregated here
	// and each node service drains the latest state when ready.
	eventsMu  sync.RWMutex
	mailboxes map[int]*controlplane.NodeMailbox
	statuses  map[int]chan<- controlplane.StatusChange

	// Shared WS client (nil when WS is disabled).
	ws       *panel.WSClient
	wsCancel context.CancelFunc

	// runCtx is stored from Run() so that onWSEvent can trigger rediscover
	// for sync.nodes events without blocking the main loop.
	runCtx context.Context

	pullInterval time.Duration
	pushInterval time.Duration

	// Seams for tests.
	newRunner func(mn panel.MachineNode, mb *controlplane.NodeMailbox) nodeRunner
	now       func() time.Time
}

// New creates a machine orchestrator from the given config.
func New(cfg *config.Config) *Orchestrator {
	panelCfg := config.PanelConfig{
		URL:       cfg.Panel.URL,
		Token:     cfg.Machine.Token,
		MachineID: cfg.Machine.MachineID,
	}
	o := &Orchestrator{
		cfg:       cfg,
		client:    panel.NewClient(panelCfg),
		nodes:     make(map[int]*nodeHandle),
		restarts:  make(map[int]*restartState),
		mailboxes: make(map[int]*controlplane.NodeMailbox),
		statuses:  make(map[int]chan<- controlplane.StatusChange),
		now:       time.Now,
	}
	o.newRunner = o.newNodeService
	return o
}

// Run is the main loop. It blocks until ctx is cancelled.
func (o *Orchestrator) Run(ctx context.Context) error {
	o.runCtx = ctx
	nodesResp, err := o.client.GetMachineNodes()
	if err != nil {
		return fmt.Errorf("initial node discovery: %w", err)
	}

	o.applyIntervals(nodesResp.BaseConfig)
	nlog.Core().Info(fmt.Sprintf("machine %d: discovered %d nodes",
		o.cfg.Machine.MachineID, len(nodesResp.Nodes)))

	// Start machine-level WS as early as possible so sync.nodes can reach an
	// empty machine before the first node is attached.
	o.tryStartWS(ctx)

	// Start initial nodes.
	for _, n := range nodesResp.Nodes {
		o.startNode(ctx, n)
	}

	discoveryTicker := time.NewTicker(o.pullInterval)
	statusTicker := time.NewTicker(o.pushInterval)
	defer discoveryTicker.Stop()
	defer statusTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			o.stopAll()
			return nil

		case <-discoveryTicker.C:
			o.rediscover(ctx)

		case <-statusTicker.C:
			o.reportMachineStatus()
		}
	}
}

// ─── Node lifecycle ──────────────────────────────────────────────────────

func (o *Orchestrator) startNode(ctx context.Context, mn panel.MachineNode) {
	o.mu.Lock()
	if _, exists := o.nodes[mn.ID]; exists {
		o.mu.Unlock()
		return
	}
	var restart restartState
	rs, restarting := o.restarts[mn.ID]
	if restarting {
		if o.now().Before(rs.notBefore) {
			o.mu.Unlock()
			return
		}
		restart = *rs
	}

	nodeCtx, cancel := context.WithCancel(ctx)
	mb := controlplane.NewNodeMailbox()
	h := &nodeHandle{cancel: cancel, done: make(chan struct{}), mailbox: mb, startedAt: o.now()}
	o.nodes[mn.ID] = h
	o.mu.Unlock()

	o.eventsMu.Lock()
	o.mailboxes[mn.ID] = mb
	o.eventsMu.Unlock()

	runner := o.newRunner(mn, mb)

	if restarting {
		nlog.Core().Warn(fmt.Sprintf("machine: restarting node %d (%s/%s)", mn.ID, mn.Type, mn.Name),
			"attempt", restart.failures, "last_error", restart.lastErr)
	} else {
		nlog.Core().Info(fmt.Sprintf("machine: starting node %d (%s/%s)",
			mn.ID, mn.Type, mn.Name))
	}

	go func() {
		defer close(h.done)
		err := runner.Run(nodeCtx)
		o.nodeExited(mn.ID, h, nodeCtx.Err() != nil, err)
	}()
}

// newNodeService builds the service that runs one machine node.
func (o *Orchestrator) newNodeService(mn panel.MachineNode, mb *controlplane.NodeMailbox) nodeRunner {
	nodeCfg := o.cfg.ExpandMachineNode(mn.ID, mn.Type)

	perNodeClient := o.client.ForNode(mn.ID)

	// Pre-fetch node config to detect transport-based kernel requirements.
	// If the transport (e.g. xhttp) is incompatible with the configured kernel
	// (e.g. singbox), auto-switch to the required kernel for this node.
	if cfgSnapshot, err := perNodeClient.GetConfig(); err == nil && cfgSnapshot != nil {
		if resolved := model.ResolveKernelForTransport(cfgSnapshot.Network, nodeCfg.Kernel.Type); resolved != nodeCfg.Kernel.Type {
			nlog.Core().Info(fmt.Sprintf("machine: auto-switching kernel for node %d (%s→%s, transport=%s)",
				mn.ID, nodeCfg.Kernel.Type, resolved, cfgSnapshot.Network))
			nodeCfg.Kernel.Type = resolved
		}
	}
	// Reset cached ETag so the subsequent GetConfig in Initial() gets a full response.
	perNodeClient.ResetConfigETag()

	var push controlplane.PushClient
	if o.ws != nil {
		push = &machineNodePush{
			nodeID: mn.ID,
			ws:     o.ws,
		}
	}

	// The registerFn is called by MachinePanelControlPlane.Initial() to expose
	// the node mailbox + status channel to the Service.
	nodeID := mn.ID
	registerFn := func(st chan<- controlplane.StatusChange) *controlplane.NodeMailbox {
		o.registerNode(nodeID, mb, st)
		return mb
	}

	cp := controlplane.NewMachinePanelControlPlane(perNodeClient, nodeCfg.Kernel, push, registerFn)
	return service.NewWithControlPlane(nodeCfg, cp)
}

// nodeExited cleans up after a node service returns. stopped reports whether
// the node's context was cancelled (stopNode or shutdown). Otherwise the node
// died on its own, and a restart is scheduled for the next rediscover.
func (o *Orchestrator) nodeExited(nodeID int, h *nodeHandle, stopped bool, err error) {
	o.unregisterNode(nodeID, h.mailbox)

	o.mu.Lock()
	defer o.mu.Unlock()
	// stopNode already dropped this handle, and a newer one may run in its place.
	if o.nodes[nodeID] != h {
		if err != nil {
			nlog.Core().Error("machine node exited with error", "node_id", nodeID, "error", err)
		}
		return
	}
	delete(o.nodes, nodeID)
	if stopped {
		if err != nil {
			nlog.Core().Error("machine node exited with error", "node_id", nodeID, "error", err)
		}
		return
	}

	if err == nil {
		err = errNodeReturned
	}
	rs, ok := o.restarts[nodeID]
	if !ok || o.now().Sub(h.startedAt) >= restartResetAfter {
		rs = &restartState{}
		o.restarts[nodeID] = rs
	}
	rs.failures++
	rs.lastErr = err
	delay := restartBackoff(rs.failures)
	rs.notBefore = o.now().Add(delay)
	nlog.Core().Error("machine node exited, will restart", "node_id", nodeID,
		"error", err, "failures", rs.failures, "restart_in", delay)
}

// restartBackoff is the wait before restarting a node after its n-th
// consecutive exit: restartBackoffInitial doubling up to restartBackoffMax.
func restartBackoff(failures int) time.Duration {
	d := restartBackoffInitial
	for i := 1; i < failures && d < restartBackoffMax; i++ {
		d *= 2
	}
	return min(d, restartBackoffMax)
}

func (o *Orchestrator) stopNode(nodeID int) {
	o.mu.Lock()
	delete(o.restarts, nodeID)
	h, ok := o.nodes[nodeID]
	if !ok {
		o.mu.Unlock()
		return
	}
	delete(o.nodes, nodeID)
	o.mu.Unlock()

	o.unregisterNode(nodeID, h.mailbox)

	nlog.Core().Info(fmt.Sprintf("machine: stopping node %d", nodeID))
	h.cancel()
	<-h.done
}

func (o *Orchestrator) stopAll() {
	o.mu.Lock()
	handles := make(map[int]*nodeHandle, len(o.nodes))
	for id, h := range o.nodes {
		handles[id] = h
	}
	o.mu.Unlock()

	for id, h := range handles {
		nlog.Core().Info(fmt.Sprintf("machine: stopping node %d", id))
		h.cancel()
	}
	for _, h := range handles {
		<-h.done
	}

	if o.wsCancel != nil {
		o.wsCancel()
	}
}

// ─── Node discovery ──────────────────────────────────────────────────────

func (o *Orchestrator) rediscover(ctx context.Context) {
	nodesResp, err := o.client.GetMachineNodes()
	if err != nil {
		nlog.Core().Warn("machine node discovery failed", "error", err)
		return
	}
	o.reconcile(ctx, nodesResp.Nodes)
}

// reconcile stops nodes the panel no longer lists and starts listed nodes
// that are not running, including ones whose service exited and whose
// restart backoff has elapsed.
func (o *Orchestrator) reconcile(ctx context.Context, nodes []panel.MachineNode) {
	wanted := make(map[int]panel.MachineNode, len(nodes))
	for _, n := range nodes {
		wanted[n.ID] = n
	}

	o.mu.Lock()
	var toRemove []int
	for id := range o.nodes {
		if _, ok := wanted[id]; !ok {
			toRemove = append(toRemove, id)
		}
	}
	for id := range o.restarts {
		if _, ok := wanted[id]; !ok {
			delete(o.restarts, id)
		}
	}
	o.mu.Unlock()

	for _, id := range toRemove {
		o.stopNode(id)
	}

	for _, n := range nodes {
		o.startNode(ctx, n) // no-op if already running or backing off
	}
}

// ─── Machine status reporting ────────────────────────────────────────────

func (o *Orchestrator) reportMachineStatus() {
	s := monitor.Collect()
	if err := o.client.ReportMachineStatus(
		s.CPU,
		[2]uint64{s.MemTotal, s.MemUsed},
		[2]uint64{s.SwapTotal, s.SwapUsed},
		[2]uint64{s.DiskTotal, s.DiskUsed},
		s.NetInSpeed, s.NetOutSpeed,
	); err != nil {
		nlog.Core().Warn("machine status report failed", "error", err)
	}
}

// ─── WS mux ─────────────────────────────────────────────────────────────

func (o *Orchestrator) tryStartWS(ctx context.Context) {
	hs, err := o.client.Handshake()
	if err != nil {
		nlog.Core().Warn("machine ws handshake failed, REST only", "error", err)
		return
	}
	if !hs.WebSocket.Enabled || hs.WebSocket.WSURL == "" {
		nlog.Core().Info("machine: ws disabled by panel, REST only")
		return
	}

	wsCfg := panel.WSClientConfig{
		StatusInterval:   time.Duration(o.cfg.WS.StatusInterval) * time.Second,
		HandshakeTimeout: time.Duration(o.cfg.WS.HandshakeTimeout) * time.Second,
		BackoffInitial:   time.Duration(o.cfg.WS.BackoffInitial) * time.Second,
		BackoffMax:       time.Duration(o.cfg.WS.BackoffMax) * time.Second,
		MachineID:        o.cfg.Machine.MachineID,
	}

	o.ws = panel.NewWSClient(
		hs.WebSocket.WSURL,
		o.cfg.Machine.Token,
		0, // no single node_id
		wsCfg,
		o.onWSEvent,
		o.onWSStatus,
		nil, // per-node status is sent via machineNodePush
	)

	wsCtx, wsCancel := context.WithCancel(ctx)
	o.wsCancel = wsCancel
	go o.ws.Run(wsCtx)

	nlog.Core().Info("machine: ws mux started")
}

// onWSEvent routes a WS event to the correct node's channel.
// sync.nodes is a machine-level event that triggers immediate rediscovery.
func (o *Orchestrator) onWSEvent(event panel.WSEvent) {
	// sync.nodes is a machine-level event, not per-node
	if event.Type == panel.WSEventSyncNodes {
		nlog.Core().Info("machine received sync.nodes, triggering immediate rediscovery")
		go o.rediscover(o.runCtx)
		return
	}

	nodeID := event.NodeID
	if nodeID == 0 {
		nlog.Core().Debug("machine ws event missing node_id, dropping", "type", event.Type)
		return
	}

	translated, err := controlplane.TranslateWSEvent(event, o.cfg.Kernel)
	if err != nil {
		nlog.Core().Warn("machine ws event translation failed",
			"type", event.Type, "node_id", nodeID, "error", err)
		return
	}

	o.eventsMu.RLock()
	mailbox, ok := o.mailboxes[nodeID]
	o.eventsMu.RUnlock()
	if !ok {
		nlog.Core().Debug("machine ws event for unknown node", "node_id", nodeID, "type", event.Type)
		return
	}
	mailbox.Apply(translated)
}

// onWSStatus broadcasts WS connectivity changes to all registered nodes.
func (o *Orchestrator) onWSStatus(status panel.WSStatusChange) {
	change := controlplane.StatusChange{Connected: status.Connected}
	o.eventsMu.RLock()
	defer o.eventsMu.RUnlock()
	for _, ch := range o.statuses {
		select {
		case ch <- change:
		default:
		}
	}
}

// registerNode and unregisterNode act only while mb is still the node's
// current mailbox, so a stale generation of a node id cannot touch the
// registration of the one that replaced it.
func (o *Orchestrator) registerNode(nodeID int, mb *controlplane.NodeMailbox, st chan<- controlplane.StatusChange) {
	o.eventsMu.Lock()
	if o.mailboxes[nodeID] == mb {
		o.statuses[nodeID] = st
	}
	o.eventsMu.Unlock()
}

func (o *Orchestrator) unregisterNode(nodeID int, mb *controlplane.NodeMailbox) {
	o.eventsMu.Lock()
	if o.mailboxes[nodeID] == mb {
		delete(o.mailboxes, nodeID)
		delete(o.statuses, nodeID)
	}
	o.eventsMu.Unlock()
}

func (o *Orchestrator) applyIntervals(bc panel.MachineBaseConfig) {
	o.pullInterval = time.Duration(bc.PullInterval) * time.Second
	if o.pullInterval < 30*time.Second {
		o.pullInterval = 60 * time.Second
	}
	o.pushInterval = time.Duration(bc.PushInterval) * time.Second
	if o.pushInterval < 10*time.Second {
		o.pushInterval = 60 * time.Second
	}
}

// ─── Virtual PushClient ─────────────────────────────────────────────────

// machineNodePush implements controlplane.PushClient for a single node
// backed by the shared machine WS connection. Events are routed by the
// WS mux directly to the Service's channels; this adapter only provides
// connectivity status and send capabilities.
type machineNodePush struct {
	nodeID int
	ws     *panel.WSClient
}

func (p *machineNodePush) Run(ctx context.Context) {
	// The shared WS mux pushes events into our channels; we just wait.
	<-ctx.Done()
}

func (p *machineNodePush) IsConnected() bool {
	return p.ws != nil && p.ws.IsConnected()
}

func (p *machineNodePush) SendDeviceReport(devices map[int][]string) {
	if p.ws == nil {
		return
	}
	payload := map[string]interface{}{
		"node_id": p.nodeID,
	}
	// Flatten into the standard format with node_id wrapper.
	strDevices := make(map[string][]string, len(devices))
	for uid, ips := range devices {
		strDevices[fmt.Sprintf("%d", uid)] = ips
	}
	payload["devices"] = strDevices
	data, _ := json.Marshal(payload)
	p.ws.SendRaw(panel.WSEventReportDevices, data)
}
