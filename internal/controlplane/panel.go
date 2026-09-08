package controlplane

import (
	"context"
	"fmt"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/nlog"
	"github.com/cedar2025/xboard-node/internal/panel"
)

type PanelControlPlane struct {
	cfg    config.PanelConfig
	wsCfg  config.WSConfig
	kcfg   config.KernelConfig
	client *panel.Client
}

type panelPushClient struct {
	inner *panel.WSClient
}

func NewPanelControlPlane(panelCfg config.PanelConfig, wsCfg config.WSConfig, kcfg config.KernelConfig) *PanelControlPlane {
	return &PanelControlPlane{
		cfg:    panelCfg,
		wsCfg:  wsCfg,
		kcfg:   kcfg,
		client: panel.NewClient(panelCfg),
	}
}

func (p *PanelControlPlane) SupportsPolling() bool       { return true }
func (p *PanelControlPlane) SupportsDiscovery() bool     { return true }
func (p *PanelControlPlane) SupportsReporting() bool     { return true }
func (p *PanelControlPlane) SupportsDeviceReports() bool { return true }
func (p *PanelControlPlane) ResetCache()                 { p.client.ResetETags() }

func (p *PanelControlPlane) Initial(ctx context.Context, metricsFn func() map[string]interface{}, events chan<- Event, statuses chan<- StatusChange) (Bootstrap, error) {
	hs, err := p.client.Handshake()
	if err != nil {
		return Bootstrap{}, fmt.Errorf("handshake: %w", err)
	}

	bootstrap := Bootstrap{PushInterval: hs.Settings.PushInterval, PullInterval: hs.Settings.PullInterval}
	if hs.WebSocket.Enabled && hs.WebSocket.WSURL != "" {
		bootstrap.Push = p.newPushClient(metricsFn, events, statuses, hs.WebSocket.WSURL)
		return bootstrap, nil
	}

	nlog.Core().Info("websocket disabled, using REST API")
	configSnapshot, err := p.client.GetConfig()
	if err != nil {
		return Bootstrap{}, fmt.Errorf("initial config fetch: %w", err)
	}
	if configSnapshot == nil {
		return Bootstrap{}, fmt.Errorf("initial config is nil")
	}
	users, err := p.client.GetUsers()
	if err != nil {
		return Bootstrap{}, fmt.Errorf("initial user fetch: %w", err)
	}
	bootstrap.Config, err = model.NodeSpecFromPanelValidated(configSnapshot, p.kcfg)
	if err != nil {
		return Bootstrap{}, fmt.Errorf("initial config normalize: %w", err)
	}
	bootstrap.Users = model.UserSpecsFromPanel(users)
	return bootstrap, nil
}

func (p *PanelControlPlane) Poll(ctx context.Context) (Snapshot, error) {
	configSnapshot, err := p.client.GetConfig()
	if err != nil {
		return Snapshot{}, fmt.Errorf("poll config: %w", err)
	}
	users, err := p.client.GetUsers()
	if err != nil {
		return Snapshot{}, fmt.Errorf("poll users: %w", err)
	}
	select {
	case <-ctx.Done():
		return Snapshot{}, ctx.Err()
	default:
	}
	nodeSpec, err := model.NodeSpecFromPanelValidated(configSnapshot, p.kcfg)
	if err != nil {
		return Snapshot{}, fmt.Errorf("poll config normalize: %w", err)
	}
	return Snapshot{Config: nodeSpec, Users: model.UserSpecsFromPanel(users)}, nil
}

func (p *PanelControlPlane) Discover(ctx context.Context, metricsFn func() map[string]interface{}, events chan<- Event, statuses chan<- StatusChange) (PushClient, error) {
	hs, err := p.client.Handshake()
	if err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if hs.WebSocket.Enabled && hs.WebSocket.WSURL != "" {
		return p.newPushClient(metricsFn, events, statuses, hs.WebSocket.WSURL), nil
	}
	return nil, nil
}

func (p *PanelControlPlane) Report(payload ReportPayload) error {
	return p.client.Report(payload.Traffic, payload.Alive, payload.Online, payload.CPU, payload.Mem, payload.Swap, payload.Disk, payload.Metrics)
}

func (p *PanelControlPlane) ReportDevices(push PushClient, devices map[int][]string) {
	if push != nil {
		push.SendDeviceReport(devices)
	}
}

func (p *PanelControlPlane) Metrics() APIMetrics {
	api := p.client.SnapshotMetrics()
	return APIMetrics{Success: api.Success, Failure: api.Failure}
}

func (p *PanelControlPlane) newPushClient(metricsFn func() map[string]interface{}, events chan<- Event, statuses chan<- StatusChange, wsURL string) PushClient {
	cfg := panel.WSClientConfig{
		StatusInterval:   time.Duration(p.wsCfg.StatusInterval) * time.Second,
		HandshakeTimeout: time.Duration(p.wsCfg.HandshakeTimeout) * time.Second,
		BackoffInitial:   time.Duration(p.wsCfg.BackoffInitial) * time.Second,
		BackoffMax:       time.Duration(p.wsCfg.BackoffMax) * time.Second,
	}
	inner := panel.NewWSClient(
		wsURL,
		p.cfg.Token,
		p.cfg.NodeID,
		cfg,
		func(event panel.WSEvent) {
			translated, err := TranslateWSEvent(event, p.kcfg)
			if err != nil {
				nlog.Core().Warn("invalid ws event config, dropping event", "type", event.Type, "error", err)
				return
			}
			select {
			case events <- translated:
			default:
				nlog.Core().Warn("ws event channel full, dropping event", "type", translated.Type)
				select {
				case statuses <- StatusChange{Connected: true, NeedsResync: true}:
				default:
				}
			}
		},
		func(status panel.WSStatusChange) {
			select {
			case statuses <- StatusChange{Connected: status.Connected}:
			default:
			}
		},
		metricsFn,
	)
	return &panelPushClient{inner: inner}
}

func TranslateWSEvent(event panel.WSEvent, kcfg config.KernelConfig) (Event, error) {
	translated := Event{Type: EventType(event.Type), DeltaAction: event.DeltaAction, DeviceUsers: event.DeviceUsers}
	if event.Config != nil {
		var err error
		translated.Config, err = model.NodeSpecFromPanelValidated(event.Config, kcfg)
		if err != nil {
			return Event{}, fmt.Errorf("translate node config: %w", err)
		}
	}
	if event.Users != nil {
		translated.Users = model.UserSpecsFromPanel(event.Users)
	}
	if event.DeltaUsers != nil {
		translated.DeltaUsers = model.UserSpecsFromPanel(event.DeltaUsers)
	}
	return translated, nil
}

func (p *panelPushClient) Run(ctx context.Context) { p.inner.Run(ctx) }
func (p *panelPushClient) IsConnected() bool       { return p.inner.IsConnected() }
func (p *panelPushClient) SendDeviceReport(devices map[int][]string) {
	p.inner.SendDeviceReport(devices)
}
