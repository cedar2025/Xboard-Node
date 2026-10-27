package machine

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/panel"
)

// fakeRunner stands in for a node service. Run returns when the test sends
// on exit, or nil when its context is cancelled.
type fakeRunner struct {
	nodeID int
	exit   chan error
}

func (r *fakeRunner) Run(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return nil
	case err := <-r.exit:
		return err
	}
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type harness struct {
	o      *Orchestrator
	clock  *fakeClock
	starts chan *fakeRunner
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		o:      New(&config.Config{Machine: &config.MachineConfig{}}),
		clock:  &fakeClock{now: time.Unix(1_800_000_000, 0)},
		starts: make(chan *fakeRunner, 16),
	}
	h.o.now = h.clock.Now
	h.o.newRunner = func(mn panel.MachineNode, _ *controlplane.NodeMailbox) nodeRunner {
		r := &fakeRunner{nodeID: mn.ID, exit: make(chan error, 1)}
		h.starts <- r
		return r
	}
	t.Cleanup(h.o.stopAll)
	return h
}

func (h *harness) expectStart(t *testing.T, nodeID int) *fakeRunner {
	t.Helper()
	select {
	case r := <-h.starts:
		if r.nodeID != nodeID {
			t.Fatalf("started node %d, want %d", r.nodeID, nodeID)
		}
		return r
	case <-time.After(2 * time.Second):
		t.Fatalf("node %d was not started", nodeID)
		return nil
	}
}

func (h *harness) expectNoStart(t *testing.T) {
	t.Helper()
	select {
	case r := <-h.starts:
		t.Fatalf("node %d started unexpectedly", r.nodeID)
	default:
	}
}

func (h *harness) handle(nodeID int) *nodeHandle {
	h.o.mu.Lock()
	defer h.o.mu.Unlock()
	return h.o.nodes[nodeID]
}

// exit makes the running service of nodeID return err and waits until the
// orchestrator has processed the exit.
func (h *harness) exit(t *testing.T, r *fakeRunner, err error) {
	t.Helper()
	nh := h.handle(r.nodeID)
	if nh == nil {
		t.Fatalf("node %d has no handle", r.nodeID)
	}
	r.exit <- err
	select {
	case <-nh.done:
	case <-time.After(2 * time.Second):
		t.Fatalf("node %d did not exit", r.nodeID)
	}
}

func (h *harness) mailbox(nodeID int) *controlplane.NodeMailbox {
	h.o.eventsMu.RLock()
	defer h.o.eventsMu.RUnlock()
	return h.o.mailboxes[nodeID]
}

var hy2 = panel.MachineNode{ID: 517, Type: "hysteria", Name: "hy2"}

func TestExitedNodeIsRestartedByRediscover(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	h.o.reconcile(ctx, []panel.MachineNode{hy2})
	r := h.expectStart(t, hy2.ID)

	h.exit(t, r, errors.New("initial setup: no TLS certificate"))
	if h.handle(hy2.ID) != nil {
		t.Fatal("exited node still has a handle")
	}
	if h.mailbox(hy2.ID) != nil {
		t.Fatal("exited node still has a mailbox")
	}

	h.clock.Advance(restartBackoffInitial)
	h.o.reconcile(ctx, []panel.MachineNode{hy2})
	h.expectStart(t, hy2.ID)
	if h.handle(hy2.ID) == nil {
		t.Fatal("restarted node has no handle")
	}
	if h.mailbox(hy2.ID) == nil {
		t.Fatal("restarted node has no mailbox")
	}
}

func TestNodeReturningNilIsRestarted(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	h.o.reconcile(ctx, []panel.MachineNode{hy2})
	h.exit(t, h.expectStart(t, hy2.ID), nil)

	h.clock.Advance(restartBackoffInitial)
	h.o.reconcile(ctx, []panel.MachineNode{hy2})
	h.expectStart(t, hy2.ID)
}

func TestRestartBackoffIsRespected(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	fail := errors.New("start kernel")

	h.o.reconcile(ctx, []panel.MachineNode{hy2})
	h.exit(t, h.expectStart(t, hy2.ID), fail)

	// Before the first backoff elapses, rediscover leaves the node down.
	h.o.reconcile(ctx, []panel.MachineNode{hy2})
	h.expectNoStart(t)
	h.clock.Advance(restartBackoffInitial - time.Second)
	h.o.reconcile(ctx, []panel.MachineNode{hy2})
	h.expectNoStart(t)

	h.clock.Advance(time.Second)
	h.o.reconcile(ctx, []panel.MachineNode{hy2})
	h.exit(t, h.expectStart(t, hy2.ID), fail)

	// The second failure in a row doubles the wait.
	h.clock.Advance(restartBackoffInitial)
	h.o.reconcile(ctx, []panel.MachineNode{hy2})
	h.expectNoStart(t)
	h.clock.Advance(restartBackoffInitial)
	h.o.reconcile(ctx, []panel.MachineNode{hy2})
	h.expectStart(t, hy2.ID)
}

func TestRestartBackoffIsCapped(t *testing.T) {
	want := []time.Duration{
		restartBackoffInitial,
		2 * restartBackoffInitial,
		4 * restartBackoffInitial,
	}
	for i, d := range want {
		if got := restartBackoff(i + 1); got != d {
			t.Errorf("restartBackoff(%d) = %s, want %s", i+1, got, d)
		}
	}
	for _, failures := range []int{10, 64, 1000} {
		if got := restartBackoff(failures); got != restartBackoffMax {
			t.Errorf("restartBackoff(%d) = %s, want cap %s", failures, got, restartBackoffMax)
		}
	}
}

func TestLongRunBeforeExitResetsBackoff(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	fail := errors.New("boom")

	h.o.reconcile(ctx, []panel.MachineNode{hy2})
	h.exit(t, h.expectStart(t, hy2.ID), fail)
	h.clock.Advance(restartBackoffInitial)
	h.o.reconcile(ctx, []panel.MachineNode{hy2})
	r := h.expectStart(t, hy2.ID)

	// It ran fine for a long time, so this exit counts as a first failure.
	h.clock.Advance(restartResetAfter)
	h.exit(t, r, fail)
	h.clock.Advance(restartBackoffInitial)
	h.o.reconcile(ctx, []panel.MachineNode{hy2})
	h.expectStart(t, hy2.ID)
}

func TestStoppedNodeIsNotResurrected(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	h.o.reconcile(ctx, []panel.MachineNode{hy2})
	h.expectStart(t, hy2.ID)

	// The panel unbinds the node: rediscover stops it.
	h.o.reconcile(ctx, nil)
	if h.handle(hy2.ID) != nil {
		t.Fatal("stopped node still has a handle")
	}
	if h.mailbox(hy2.ID) != nil {
		t.Fatal("stopped node still has a mailbox")
	}

	h.clock.Advance(restartBackoffMax)
	h.o.reconcile(ctx, nil)
	h.expectNoStart(t)

	h.o.mu.Lock()
	_, pending := h.o.restarts[hy2.ID]
	h.o.mu.Unlock()
	if pending {
		t.Fatal("stopped node left a pending restart")
	}
}

func TestRebindAfterStopStartsImmediately(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	h.o.reconcile(ctx, []panel.MachineNode{hy2})
	h.exit(t, h.expectStart(t, hy2.ID), errors.New("boom"))

	// Unbinding a crashed node drops its backoff, so a rebind starts it now.
	h.o.reconcile(ctx, nil)
	h.o.reconcile(ctx, []panel.MachineNode{hy2})
	h.expectStart(t, hy2.ID)
}

func TestShutdownDoesNotScheduleRestart(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())

	h.o.reconcile(ctx, []panel.MachineNode{hy2})
	h.expectStart(t, hy2.ID)
	nh := h.handle(hy2.ID)
	cancel()
	<-nh.done

	h.o.mu.Lock()
	_, pending := h.o.restarts[hy2.ID]
	h.o.mu.Unlock()
	if pending {
		t.Fatal("shutdown scheduled a restart")
	}
}

func TestStaleExitDoesNotRemoveNewerHandle(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	h.o.reconcile(ctx, []panel.MachineNode{hy2})
	h.expectStart(t, hy2.ID)
	current := h.handle(hy2.ID)
	currentMailbox := h.mailbox(hy2.ID)

	// An exit report from an older generation of the same node id must not
	// tear down the one that is running now.
	stale := &nodeHandle{done: make(chan struct{}), mailbox: controlplane.NewNodeMailbox()}
	h.o.nodeExited(hy2.ID, stale, false, errors.New("old generation"))

	if h.handle(hy2.ID) != current {
		t.Fatal("stale exit replaced or removed the current handle")
	}
	if h.mailbox(hy2.ID) != currentMailbox {
		t.Fatal("stale exit removed the current mailbox")
	}
	h.o.mu.Lock()
	_, pending := h.o.restarts[hy2.ID]
	h.o.mu.Unlock()
	if pending {
		t.Fatal("stale exit scheduled a restart")
	}
}
