package controlplane

import (
	"context"
	"fmt"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
)

type LocalControlPlane struct {
	cfg *config.Config
}

func NewLocalControlPlane(cfg *config.Config) *LocalControlPlane { return &LocalControlPlane{cfg: cfg} }
func (l *LocalControlPlane) SupportsPolling() bool               { return false }
func (l *LocalControlPlane) SupportsDiscovery() bool             { return false }
func (l *LocalControlPlane) SupportsReporting() bool             { return false }
func (l *LocalControlPlane) SupportsDeviceReports() bool         { return false }
func (l *LocalControlPlane) ResetCache()                         {}

func (l *LocalControlPlane) Initial(ctx context.Context, _ func() map[string]interface{}, _ chan<- Event, _ chan<- StatusChange) (Bootstrap, error) {
	select {
	case <-ctx.Done():
		return Bootstrap{}, ctx.Err()
	default:
	}
	nodeSpec, err := model.NodeSpecFromStandaloneValidated(l.cfg)
	if err != nil {
		return Bootstrap{}, fmt.Errorf("load standalone node config: %w", err)
	}
	return Bootstrap{
		PushInterval: l.cfg.Node.PushInterval,
		PullInterval: l.cfg.Node.PullInterval,
		Config:       nodeSpec,
		Users:        model.UserSpecsFromStandalone(l.cfg),
	}, nil
}

func (l *LocalControlPlane) Poll(ctx context.Context) (Snapshot, error) {
	select {
	case <-ctx.Done():
		return Snapshot{}, ctx.Err()
	default:
		return Snapshot{}, nil
	}
}

func (l *LocalControlPlane) Discover(ctx context.Context, _ func() map[string]interface{}, _ chan<- Event, _ chan<- StatusChange) (PushClient, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, nil
	}
}

func (l *LocalControlPlane) Report(payload ReportPayload) error { _ = payload; return nil }
func (l *LocalControlPlane) ReportDevices(push PushClient, devices map[int][]string) {
	_, _ = push, devices
}
func (l *LocalControlPlane) Metrics() APIMetrics { return APIMetrics{} }
