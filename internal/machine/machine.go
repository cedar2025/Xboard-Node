// Package machine implements the machine-mode orchestrator that dynamically
// discovers nodes from the panel's machine API and manages their lifecycles.
package machine

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/monitor"
	"github.com/cedar2025/xboard-node/internal/nlog"
	"github.com/cedar2025/xboard-node/internal/panel"
	"github.com/cedar2025/xboard-node/internal/service"
)

// nodeState is the lifecycle state of a bound node as the orchestrator sees it.
type nodeState int

const (
	// nodeRunning: a service goroutine owns the node.
	nodeRunning nodeState = iota
	// nodeBackoff: the service exited while the panel still binds the node;
	// it restarts when its retry is due or a wake-up arrives.
	nodeBackoff
)

// nodeHandle tracks one bound node. The handle reflects the real state of the
// service goroutine: an exited service is never left registered as running.
type nodeHandle struct {
	node    panel.MachineNode
	gen     uint64
	state   nodeState
	cancel  context.CancelFunc
	done    chan struct{}
	mailbox *controlplane.NodeMailbox

	attempts int
	retryAt  time.Time
	lastErr  error
}

// nodeExit is delivered to the main loop when a service goroutine returns.
type nodeExit struct {
	id  int
	gen uint64
	err error
}

// nodeRunner is what the orchestrator supervises; the production runner is a
// *service.Service.
type nodeRunner interface {
	Run(ctx context.Context) error
}

// Orchestrator manages all nodes bound to a panel machine. It:
//   - discovers nodes via GET /machine/nodes
//   - starts / stops Service instances as nodes are added / removed
//   - restarts a node whose service exited, with bounded backoff, as long as
//     the panel still binds it
//   - maintains a shared WS connection that demuxes events by node_id
//   - reports machine-level load via POST /machine/status
//
// Every lifecycle decision runs on the Run goroutine; goroutines only report
// back through channels, each carrying the generation of the handle it
// belongs to so a late exit of a replaced service cannot touch its successor.
type Orchestrator struct {
	cfg    *config.Config
	client *panel.Client // machine-level client (no node_id)

	mu     sync.Mutex
	nodes  map[int]*nodeHandle // node_id → handle
	genSeq uint64

	// Per-node mailbox keyed by node_id. Shared WS events are aggregated here
	// and each node service drains the latest state when ready.
	eventsMu  sync.RWMutex
	mailboxes map[int]*controlplane.NodeMailbox
	statuses  map[int]chan<- controlplane.StatusChange

	// Shared WS client (nil when WS is disabled).
	ws       *panel.WSClient
	wsCancel context.CancelFunc

	// Main-loop inputs.
	nodeExits    chan nodeExit
	rediscoverCh chan struct{}
	wakeCh       chan int
	retryTimer   *time.Timer
	retryPending bool

	pullInterval time.Duration
	pushInterval time.Duration

	// Test hooks.
	retryDelayFn func(attempt int) time.Duration
	newRunner    func(cfg *config.Config, cp controlplane.ControlPlane) nodeRunner
}

// Restart schedule for a node whose service exited.
const (
	nodeRetryBase = 5 * time.Second
	nodeRetryMax  = 5 * time.Minute
)

func nodeRetryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := nodeRetryBase
	for i := 1; i < attempt; i++ {
		delay *= 2
		if delay >= nodeRetryMax {
			return nodeRetryMax
		}
	}
	return delay
}

// New creates a machine orchestrator from the given config.
func New(cfg *config.Config) *Orchestrator {
	panelCfg := config.PanelConfig{
		URL:       cfg.Panel.URL,
		Token:     cfg.Machine.Token,
		MachineID: cfg.Machine.MachineID,
	}
	return &Orchestrator{
		cfg:          cfg,
		client:       panel.NewClient(panelCfg),
		nodes:        make(map[int]*nodeHandle),
		mailboxes:    make(map[int]*controlplane.NodeMailbox),
		statuses:     make(map[int]chan<- controlplane.StatusChange),
		nodeExits:    make(chan nodeExit, 16),
		rediscoverCh: make(chan struct{}, 1),
		wakeCh:       make(chan int, 16),
		retryDelayFn: nodeRetryDelay,
		newRunner: func(cfg *config.Config, cp controlplane.ControlPlane) nodeRunner {
			return service.NewWithControlPlane(cfg, cp)
		},
	}
}

// Run is the main loop. It blocks until ctx is cancelled.
func (o *Orchestrator) Run(ctx context.Context) error {
	var nodesResp *panel.MachineNodesResponse
	for attempt := 1; ; attempt++ {
		var err error
		nodesResp, err = o.client.GetMachineNodes()
		if err == nil {
			break
		}
		delay := o.retryDelayFn(attempt)
		nlog.Core().Warn("initial machine discovery failed, retrying", "error", err, "retry_in", delay)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
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
	defer o.stopRetryTimer()

	for {
		select {
		case <-ctx.Done():
			o.stopAll()
			return nil

		case <-discoveryTicker.C:
			o.rediscover(ctx)

		case <-o.rediscoverCh:
			o.rediscover(ctx)

		case <-statusTicker.C:
			o.reportMachineStatus()

		case exit := <-o.nodeExits:
			o.onNodeExit(ctx, exit)

		case id := <-o.wakeCh:
			o.wakeNode(ctx, id)

		case <-o.retryC():
			o.retryPending = false
			o.restartDue(ctx)
		}
	}
}

// ─── Node lifecycle ──────────────────────────────────────────────────────

// startNode ensures a service runs for mn. A node already running is left
// alone; a node in backoff is restarted at once because a fresh discovery of
// the binding is a reason to try again.
func (o *Orchestrator) startNode(ctx context.Context, mn panel.MachineNode) {
	o.mu.Lock()
	h, exists := o.nodes[mn.ID]
	if exists && h.state == nodeRunning {
		o.mu.Unlock()
		return
	}
	if !exists {
		h = &nodeHandle{node: mn}
		o.nodes[mn.ID] = h
	}
	h.node = mn
	o.mu.Unlock()
	o.launch(ctx, h)
}

// launch starts the service goroutine for a handle and registers its mailbox.
func (o *Orchestrator) launch(ctx context.Context, h *nodeHandle) {
	o.mu.Lock()
	o.genSeq++
	gen := o.genSeq
	nodeCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	mb := controlplane.NewNodeMailbox()
	mn := h.node
	h.gen = gen
	h.state = nodeRunning
	h.cancel = cancel
	h.done = done
	h.mailbox = mb
	o.mu.Unlock()

	o.eventsMu.Lock()
	o.mailboxes[mn.ID] = mb
	o.eventsMu.Unlock()

	nodeCfg := o.cfg.ExpandMachineNode(mn.ID, mn.Type)
	perNodeClient := o.client.ForNode(mn.ID)

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
		o.registerNode(nodeID, st)
		return mb
	}

	cp := controlplane.NewMachinePanelControlPlane(perNodeClient, nodeCfg.Kernel, push, registerFn)
	runner := o.newRunner(nodeCfg, cp)

	nlog.Core().Info(fmt.Sprintf("machine: starting node %d (%s/%s)", mn.ID, mn.Type, mn.Name), "generation", gen)

	go func() {
		err := runner.Run(nodeCtx)
		close(done)
		select {
		case o.nodeExits <- nodeExit{id: mn.ID, gen: gen, err: err}:
		case <-ctx.Done():
		}
	}()
}

// onNodeExit records that a service goroutine returned. An exit of a handle
// generation that is no longer current (the node was stopped or restarted in
// the meantime) is ignored. A node the panel still binds goes into backoff.
func (o *Orchestrator) onNodeExit(ctx context.Context, exit nodeExit) {
	if ctx.Err() != nil {
		return
	}
	o.mu.Lock()
	h, ok := o.nodes[exit.id]
	if !ok || h.gen != exit.gen || h.state != nodeRunning {
		o.mu.Unlock()
		nlog.Core().Debug("machine: ignoring exit of a replaced node service", "node_id", exit.id, "generation", exit.gen)
		return
	}
	h.state = nodeBackoff
	h.attempts++
	h.lastErr = exit.err
	delay := o.retryDelayFn(h.attempts)
	h.retryAt = time.Now().Add(delay)
	h.cancel = nil
	h.done = nil
	o.mu.Unlock()

	o.unregisterNode(exit.id)
	if exit.err != nil {
		nlog.Core().Error("machine node exited with error, scheduling restart",
			"node_id", exit.id, "attempt", h.attempts, "retry_in", delay, "error", exit.err)
	} else {
		nlog.Core().Warn("machine node exited, scheduling restart",
			"node_id", exit.id, "attempt", h.attempts, "retry_in", delay)
	}
	o.scheduleRetryCheck()
}

// wakeNode restarts a node in backoff right away, because a new push for it
// means the panel changed something worth trying.
func (o *Orchestrator) wakeNode(ctx context.Context, id int) {
	o.mu.Lock()
	h, ok := o.nodes[id]
	if !ok || h.state != nodeBackoff {
		o.mu.Unlock()
		return
	}
	o.mu.Unlock()
	nlog.Core().Info("machine: waking node after panel update", "node_id", id)
	o.launch(ctx, h)
}

// restartDue restarts every node whose backoff elapsed and reschedules the
// timer for the rest.
func (o *Orchestrator) restartDue(ctx context.Context) {
	now := time.Now()
	var due []*nodeHandle
	o.mu.Lock()
	for _, h := range o.nodes {
		if h.state == nodeBackoff && !now.Before(h.retryAt) {
			due = append(due, h)
		}
	}
	o.mu.Unlock()
	for _, h := range due {
		nlog.Core().Info("machine: restarting node after backoff", "node_id", h.node.ID, "attempt", h.attempts)
		o.launch(ctx, h)
	}
	o.scheduleRetryCheck()
}

// scheduleRetryCheck arms the retry timer for the earliest pending restart.
func (o *Orchestrator) scheduleRetryCheck() {
	var earliest time.Time
	o.mu.Lock()
	for _, h := range o.nodes {
		if h.state != nodeBackoff {
			continue
		}
		if earliest.IsZero() || h.retryAt.Before(earliest) {
			earliest = h.retryAt
		}
	}
	o.mu.Unlock()
	if earliest.IsZero() {
		o.stopRetryTimer()
		return
	}
	delay := time.Until(earliest)
	if delay < 0 {
		delay = 0
	}
	if o.retryTimer == nil {
		o.retryTimer = time.NewTimer(delay)
	} else {
		o.stopRetryTimer()
		o.retryTimer.Reset(delay)
	}
	o.retryPending = true
}

func (o *Orchestrator) stopRetryTimer() {
	if o.retryTimer != nil && !o.retryTimer.Stop() {
		select {
		case <-o.retryTimer.C:
		default:
		}
	}
	o.retryPending = false
}

func (o *Orchestrator) retryC() <-chan time.Time {
	if !o.retryPending || o.retryTimer == nil {
		return nil
	}
	return o.retryTimer.C
}

// stopNode stops a node the panel no longer binds. The service (if running)
// is cancelled and awaited; a node in backoff is simply forgotten so it can
// never come back on its own.
func (o *Orchestrator) stopNode(nodeID int) {
	o.mu.Lock()
	h, ok := o.nodes[nodeID]
	if !ok {
		o.mu.Unlock()
		return
	}
	delete(o.nodes, nodeID)
	o.mu.Unlock()

	o.unregisterNode(nodeID)

	nlog.Core().Info(fmt.Sprintf("machine: stopping node %d", nodeID))
	if h.state == nodeRunning && h.cancel != nil {
		h.cancel()
		<-h.done
	}
}

func (o *Orchestrator) stopAll() {
	o.mu.Lock()
	handles := make(map[int]*nodeHandle, len(o.nodes))
	for id, h := range o.nodes {
		handles[id] = h
	}
	o.nodes = make(map[int]*nodeHandle)
	o.mu.Unlock()

	for id, h := range handles {
		nlog.Core().Info(fmt.Sprintf("machine: stopping node %d", id))
		if h.state == nodeRunning && h.cancel != nil {
			h.cancel()
		}
	}
	for _, h := range handles {
		if h.state == nodeRunning && h.done != nil {
			<-h.done
		}
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

	wanted := make(map[int]panel.MachineNode, len(nodesResp.Nodes))
	for _, n := range nodesResp.Nodes {
		wanted[n.ID] = n
	}

	o.mu.Lock()
	var toRemove []int
	for id := range o.nodes {
		if _, ok := wanted[id]; !ok {
			toRemove = append(toRemove, id)
		}
	}
	o.mu.Unlock()

	// Unbound nodes go first so a port they held is free for their successor.
	for _, id := range toRemove {
		o.stopNode(id)
	}

	for _, n := range nodesResp.Nodes {
		o.startNode(ctx, n) // no-op if already running
	}
	o.scheduleRetryCheck()
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
		return
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
// sync.nodes is a machine-level event that is handed to the main loop for an
// immediate rediscovery, so discovery never runs on two goroutines at once.
func (o *Orchestrator) onWSEvent(event panel.WSEvent) {
	if event.Type == panel.WSEventSyncNodes {
		nlog.Core().Info("machine received sync.nodes, triggering immediate rediscovery")
		select {
		case o.rediscoverCh <- struct{}{}:
		default:
		}
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
		// A node in backoff has no mailbox; the push is a reason to try again
		// now instead of waiting for the retry timer.
		nlog.Core().Debug("machine ws event for node without a running service", "node_id", nodeID, "type", event.Type)
		select {
		case o.wakeCh <- nodeID:
		default:
		}
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

func (o *Orchestrator) registerNode(nodeID int, st chan<- controlplane.StatusChange) {
	o.eventsMu.Lock()
	o.statuses[nodeID] = st
	o.eventsMu.Unlock()
}

func (o *Orchestrator) unregisterNode(nodeID int) {
	o.eventsMu.Lock()
	delete(o.mailboxes, nodeID)
	delete(o.statuses, nodeID)
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
