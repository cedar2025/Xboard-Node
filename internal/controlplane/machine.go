package controlplane

import (
	"context"
	"fmt"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/nlog"
	"github.com/cedar2025/xboard-node/internal/panel"
)

// MachinePanelControlPlane implements ControlPlane for a single node running
// under the machine orchestrator. REST calls go through a per-node panel.Client
// with machine-level auth; WS events are delivered via an externally-managed
// PushClient supplied by the machine WS mux.
type MachinePanelControlPlane struct {
	client *panel.Client
	kcfg   config.KernelConfig
	push   PushClient // virtual push client from WS mux (may be nil)

	registerFn func(statuses chan<- StatusChange) *NodeMailbox
}

// NewMachinePanelControlPlane creates a per-node control plane for machine mode.
// push may be nil if WS is unavailable.
// registerFn is called during Initial() to wire machine mailbox access and status
// updates into the service loop. It may be nil when WS is not used.
func NewMachinePanelControlPlane(
	client *panel.Client,
	kcfg config.KernelConfig,
	push PushClient,
	registerFn func(statuses chan<- StatusChange) *NodeMailbox,
) *MachinePanelControlPlane {
	return &MachinePanelControlPlane{
		client:     client,
		kcfg:       kcfg,
		push:       push,
		registerFn: registerFn,
	}
}

func (p *MachinePanelControlPlane) SupportsPolling() bool       { return true }
func (p *MachinePanelControlPlane) SupportsDiscovery() bool     { return false }
func (p *MachinePanelControlPlane) SupportsReporting() bool     { return true }
func (p *MachinePanelControlPlane) SupportsDeviceReports() bool { return p.push != nil }
func (p *MachinePanelControlPlane) ResetCache()                 { p.client.ResetETags() }

func (p *MachinePanelControlPlane) Initial(
	ctx context.Context,
	metricsFn func() map[string]interface{},
	events chan<- Event,
	statuses chan<- StatusChange,
) (Bootstrap, error) {
	// In machine mode the orchestrator handles the shared WS handshake, but each
	// node service still needs one initial REST snapshot so newly discovered nodes
	// can start immediately instead of waiting for a subsequent WS full-sync.
	hs, err := p.client.Handshake()
	if err != nil {
		nlog.Core().Debug("machine node handshake skipped, using REST", "error", err)
	}

	bootstrap := Bootstrap{}
	if hs != nil {
		bootstrap.PushInterval = hs.Settings.PushInterval
		bootstrap.PullInterval = hs.Settings.PullInterval
	}

	configSnapshot, err := p.client.GetConfig()
	if err != nil {
		return Bootstrap{}, fmt.Errorf("machine initial config: %w", err)
	}
	if configSnapshot == nil {
		return Bootstrap{}, fmt.Errorf("machine initial config is nil")
	}
	users, err := p.client.GetUsers()
	if err != nil {
		return Bootstrap{}, fmt.Errorf("machine initial users: %w", err)
	}
	bootstrap.Config, err = model.NodeSpecFromPanelValidated(configSnapshot, p.kcfg)
	if err != nil {
		return Bootstrap{}, fmt.Errorf("machine initial config normalize: %w", err)
	}
	bootstrap.Users = model.UserSpecsFromPanel(users)

	// Register mailbox access after the initial snapshot is prepared, so the
	// Service can start the kernel immediately and only then drain coalesced WS
	// state from the machine mailbox.
	if p.push != nil {
		if p.registerFn != nil {
			bootstrap.Mailbox = p.registerFn(statuses)
		}
		bootstrap.Push = p.push
	}

	return bootstrap, nil
}

func (p *MachinePanelControlPlane) Poll(ctx context.Context) (Snapshot, error) {
	configSnapshot, err := p.client.GetConfig()
	if err != nil {
		return Snapshot{}, fmt.Errorf("machine poll config: %w", err)
	}
	users, err := p.client.GetUsers()
	if err != nil {
		return Snapshot{}, fmt.Errorf("machine poll users: %w", err)
	}
	select {
	case <-ctx.Done():
		return Snapshot{}, ctx.Err()
	default:
	}
	nodeSpec, err := model.NodeSpecFromPanelValidated(configSnapshot, p.kcfg)
	if err != nil {
		return Snapshot{}, fmt.Errorf("machine poll normalize: %w", err)
	}
	return Snapshot{Config: nodeSpec, Users: model.UserSpecsFromPanel(users)}, nil
}

func (p *MachinePanelControlPlane) Discover(
	ctx context.Context,
	metricsFn func() map[string]interface{},
	events chan<- Event,
	statuses chan<- StatusChange,
) (PushClient, error) {
	return nil, nil
}

func (p *MachinePanelControlPlane) Report(payload ReportPayload) error {
	return p.client.Report(
		payload.Traffic, payload.Alive, payload.Online,
		payload.CPU, payload.Mem, payload.Swap, payload.Disk,
		payload.Metrics,
	)
}

func (p *MachinePanelControlPlane) ReportDevices(push PushClient, devices map[int][]string) {
	if push != nil {
		push.SendDeviceReport(devices)
	}
}

func (p *MachinePanelControlPlane) Metrics() APIMetrics {
	api := p.client.SnapshotMetrics()
	return APIMetrics{Success: api.Success, Failure: api.Failure}
}
