package machine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/panel"
)

// fakePanel is the subset of the machine API the orchestrator and its node
// services touch. The bound node list and the per-node configs are mutable so
// a test can rebind nodes between discoveries.
type fakePanel struct {
	mu                sync.Mutex
	nodes             []panel.MachineNode
	configs           map[int]map[string]any
	users             []map[string]any
	server            *httptest.Server
	discoveryFailures int
	discoveryRequests int
}

func newFakePanel(t *testing.T) *fakePanel {
	t.Helper()
	fp := &fakePanel{configs: map[int]map[string]any{}, users: []map[string]any{{"id": 1, "uuid": "aaaaaaaa-1111-2222-3333-444444444444"}}}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/server/machine/nodes", func(w http.ResponseWriter, r *http.Request) {
		fp.mu.Lock()
		fp.discoveryRequests++
		if fp.discoveryFailures > 0 {
			fp.discoveryFailures--
			fp.mu.Unlock()
			http.Error(w, "temporary panel outage", http.StatusBadGateway)
			return
		}
		nodes := append([]panel.MachineNode(nil), fp.nodes...)
		fp.mu.Unlock()
		writeJSON(w, map[string]any{"nodes": nodes, "base_config": map[string]any{"push_interval": 60, "pull_interval": 60}})
	})
	mux.HandleFunc("/api/v2/server/handshake", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"websocket": map[string]any{"enabled": false}, "settings": map[string]any{"push_interval": 60, "pull_interval": 60}})
	})
	mux.HandleFunc("/api/v2/server/config", func(w http.ResponseWriter, r *http.Request) {
		nodeID, _ := strconv.Atoi(r.URL.Query().Get("node_id"))
		fp.mu.Lock()
		cfg, ok := fp.configs[nodeID]
		fp.mu.Unlock()
		if !ok {
			http.Error(w, "unknown node", http.StatusNotFound)
			return
		}
		writeJSON(w, cfg)
	})
	mux.HandleFunc("/api/v2/server/user", func(w http.ResponseWriter, r *http.Request) {
		fp.mu.Lock()
		users := fp.users
		fp.mu.Unlock()
		writeJSON(w, map[string]any{"users": users})
	})
	mux.HandleFunc("/api/v2/server/report", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, map[string]any{}) })
	mux.HandleFunc("/api/v2/server/machine/status", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, map[string]any{}) })
	fp.server = httptest.NewServer(mux)
	t.Cleanup(fp.server.Close)
	return fp
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (fp *fakePanel) bind(nodes ...panel.MachineNode) {
	fp.mu.Lock()
	fp.nodes = nodes
	fp.mu.Unlock()
}

func (fp *fakePanel) setConfig(nodeID int, cfg map[string]any) {
	fp.mu.Lock()
	fp.configs[nodeID] = cfg
	fp.mu.Unlock()
}

func shadowsocksConfig(port int) map[string]any {
	return map[string]any{"protocol": "shadowsocks", "server_port": port, "cipher": "aes-128-gcm", "listen_ip": "0.0.0.0"}
}

func newTestOrchestrator(t *testing.T, fp *fakePanel) *Orchestrator {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		InstanceID: "machine-test",
		Panel:      config.PanelConfig{URL: fp.server.URL},
		Machine:    &config.MachineConfig{MachineID: 11, Token: "machine-token"},
		Kernel:     config.KernelConfig{Type: "singbox", ConfigDir: dir, LogLevel: "error"},
		Cert:       config.CertConfig{CertDir: dir + "/certs", HTTPPort: 80},
		Node:       config.NodeConfig{TrackInterval: 60, DeviceReportInterval: 60},
		WS:         config.WSConfig{DiscoveryInterval: 300, StatusInterval: 10, HandshakeTimeout: 15, BackoffInitial: 1, BackoffMax: 60},
	}
	o := New(cfg)
	o.retryDelayFn = func(int) time.Duration { return 20 * time.Millisecond }
	return o
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func accepts(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func (o *Orchestrator) handleState(id int) (nodeState, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	h, ok := o.nodes[id]
	if !ok {
		return 0, false
	}
	return h.state, true
}

func (o *Orchestrator) handleAttempts(id int) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	if h, ok := o.nodes[id]; ok {
		return h.attempts
	}
	return 0
}

func runOrchestrator(t *testing.T, o *Orchestrator) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- o.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("orchestrator exited with error: %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Errorf("orchestrator did not stop")
		}
	})
	return cancel
}

// The incident's rebinding: the machine ran node 5; the panel rebinds it to
// node 7 on the same port. Node 5 must stop, node 7 must take over the port,
// and node 5 must never come back.
func TestRebindStopsOldNodeAndStartsNewOne(t *testing.T) {
	fp := newFakePanel(t)
	port := freePort(t)
	fp.setConfig(5, shadowsocksConfig(port))
	fp.setConfig(7, shadowsocksConfig(port))
	fp.bind(panel.MachineNode{ID: 5, Type: "shadowsocks", Name: "old"})

	o := newTestOrchestrator(t, fp)
	runOrchestrator(t, o)
	waitFor(t, 15*time.Second, "node 5 listening", func() bool { return accepts(fmt.Sprintf("127.0.0.1:%d", port)) })

	fp.bind(panel.MachineNode{ID: 7, Type: "shadowsocks", Name: "new"})
	o.rediscoverCh <- struct{}{}

	waitFor(t, 15*time.Second, "node 7 running", func() bool {
		st, ok := o.handleState(7)
		_, oldPresent := o.handleState(5)
		return ok && st == nodeRunning && !oldPresent
	})
	waitFor(t, 15*time.Second, "node 7 listening", func() bool { return accepts(fmt.Sprintf("127.0.0.1:%d", port)) })
	if _, present := o.handleState(5); present {
		t.Fatal("unbound node 5 came back")
	}
}

// A node whose service exits while the panel still binds it is restarted with
// backoff; the handle never claims it is running while nothing runs.
func TestExitedServiceIsRestartedWithBackoff(t *testing.T) {
	fp := newFakePanel(t)
	fp.bind(panel.MachineNode{ID: 5, Type: "shadowsocks", Name: "crashy"})
	o := newTestOrchestrator(t, fp)

	var runs int
	var mu sync.Mutex
	o.newRunner = func(cfg *config.Config, cp controlplane.ControlPlane) nodeRunner {
		return runnerFunc(func(ctx context.Context) error {
			mu.Lock()
			runs++
			n := runs
			mu.Unlock()
			if n <= 3 {
				return errors.New("initial setup: protocol \"hysteria\" requires TLS certificate files")
			}
			<-ctx.Done()
			return nil
		})
	}
	runOrchestrator(t, o)

	waitFor(t, 10*time.Second, "fourth run", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return runs >= 4
	})
	waitFor(t, 5*time.Second, "node marked running", func() bool {
		st, ok := o.handleState(5)
		return ok && st == nodeRunning
	})
	if o.handleAttempts(5) != 3 {
		t.Fatalf("attempts = %d, want 3", o.handleAttempts(5))
	}
}

// An unbound node in backoff is forgotten, not restarted, and a new node's
// failure never resurrects it.
func TestUnboundNodeIsNeverResurrected(t *testing.T) {
	fp := newFakePanel(t)
	fp.bind(panel.MachineNode{ID: 5, Type: "shadowsocks", Name: "old"})
	o := newTestOrchestrator(t, fp)
	o.retryDelayFn = func(int) time.Duration { return time.Hour }

	var mu sync.Mutex
	runs := map[int]int{}
	o.newRunner = func(cfg *config.Config, cp controlplane.ControlPlane) nodeRunner {
		id := cfg.Panel.NodeID
		return runnerFunc(func(ctx context.Context) error {
			mu.Lock()
			runs[id]++
			mu.Unlock()
			if id == 5 {
				<-ctx.Done()
				return nil
			}
			return errors.New("node 7 cannot start")
		})
	}
	runOrchestrator(t, o)
	waitFor(t, 5*time.Second, "node 5 running", func() bool { st, ok := o.handleState(5); return ok && st == nodeRunning })

	fp.bind(panel.MachineNode{ID: 7, Type: "hysteria", Name: "new"})
	o.rediscoverCh <- struct{}{}
	waitFor(t, 5*time.Second, "node 7 in backoff", func() bool { st, ok := o.handleState(7); return ok && st == nodeBackoff })
	if _, present := o.handleState(5); present {
		t.Fatal("node 5 still registered after being unbound")
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if runs[5] != 1 {
		t.Fatalf("node 5 ran %d times, want exactly 1", runs[5])
	}
}

// A panel push for a node in backoff wakes it immediately instead of waiting
// for the retry timer.
func TestPanelEventWakesNodeInBackoff(t *testing.T) {
	fp := newFakePanel(t)
	fp.bind(panel.MachineNode{ID: 7, Type: "hysteria", Name: "new"})
	o := newTestOrchestrator(t, fp)
	o.retryDelayFn = func(int) time.Duration { return time.Hour }

	var mu sync.Mutex
	runs := 0
	o.newRunner = func(cfg *config.Config, cp controlplane.ControlPlane) nodeRunner {
		return runnerFunc(func(ctx context.Context) error {
			mu.Lock()
			runs++
			n := runs
			mu.Unlock()
			if n == 1 {
				return errors.New("first attempt fails")
			}
			<-ctx.Done()
			return nil
		})
	}
	runOrchestrator(t, o)
	waitFor(t, 5*time.Second, "node 7 in backoff", func() bool { st, ok := o.handleState(7); return ok && st == nodeBackoff })

	o.onWSEvent(panel.WSEvent{Type: panel.WSEventSyncConfig, NodeID: 7, Config: &panel.NodeConfig{Protocol: "hysteria", Version: 2, ServerPort: 54433}})
	waitFor(t, 5*time.Second, "node 7 running again", func() bool { st, ok := o.handleState(7); return ok && st == nodeRunning })
	mu.Lock()
	defer mu.Unlock()
	if runs != 2 {
		t.Fatalf("runs = %d, want 2", runs)
	}
}

// A late exit notification from a replaced service generation must not touch
// the handle of its successor.
func TestStaleExitIsIgnored(t *testing.T) {
	fp := newFakePanel(t)
	fp.bind(panel.MachineNode{ID: 5, Type: "shadowsocks", Name: "n"})
	o := newTestOrchestrator(t, fp)
	release := make(chan struct{})
	o.newRunner = func(cfg *config.Config, cp controlplane.ControlPlane) nodeRunner {
		return runnerFunc(func(ctx context.Context) error {
			select {
			case <-ctx.Done():
			case <-release:
			}
			return nil
		})
	}
	runOrchestrator(t, o)
	waitFor(t, 5*time.Second, "running", func() bool { st, ok := o.handleState(5); return ok && st == nodeRunning })

	o.mu.Lock()
	gen := o.nodes[5].gen
	o.mu.Unlock()
	o.nodeExits <- nodeExit{id: 5, gen: gen - 1, err: errors.New("stale")}
	time.Sleep(50 * time.Millisecond)
	if st, _ := o.handleState(5); st != nodeRunning {
		t.Fatal("a stale exit changed the handle state")
	}
	close(release)
}

type runnerFunc func(ctx context.Context) error

func (f runnerFunc) Run(ctx context.Context) error { return f(ctx) }

func TestMachineBootstrapRetriesBeforeStartingBoundNodes(t *testing.T) {
	fp := newFakePanel(t)
	port := freePort(t)
	fp.setConfig(5, shadowsocksConfig(port))
	fp.bind(panel.MachineNode{ID: 5, Type: "shadowsocks", Name: "retry-test"})
	fp.mu.Lock()
	fp.discoveryFailures = 2
	fp.mu.Unlock()
	o := newTestOrchestrator(t, fp)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- o.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("shutdown: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("machine did not stop")
		}
	})
	waitFor(t, 3*time.Second, "listener after initial panel recovery", func() bool { return accepts(fmt.Sprintf("127.0.0.1:%d", port)) })
	fp.mu.Lock()
	requests := fp.discoveryRequests
	fp.mu.Unlock()
	if requests < 3 {
		t.Fatalf("discovery attempts=%d, want at least 3", requests)
	}
}
