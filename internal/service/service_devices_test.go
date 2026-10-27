package service

import (
	"sync"
	"testing"

	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/tracker"
)

type recordingSink struct {
	mu      sync.Mutex
	reports []controlplane.ReportPayload
	devices []map[int][]string
}

func (r *recordingSink) Report(p controlplane.ReportPayload) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reports = append(r.reports, p)
	return nil
}

func (r *recordingSink) ReportDevices(_ controlplane.PushClient, devices map[int][]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.devices = append(r.devices, devices)
}

func (r *recordingSink) SupportsReporting() bool     { return true }
func (r *recordingSink) SupportsDeviceReports() bool { return true }

func newDeviceTestService(push controlplane.PushClient) (*Service, *recordingSink) {
	s := newTestService(&fakeKernel{})
	sink := &recordingSink{}
	s.sink = sink
	s.source = &countingSource{}
	s.tracker = tracker.New()
	s.wsClient = push
	s.tracker.Process(nil, map[int]map[string]bool{7: {"1.1.1.1": true}}, 1)
	return s, sink
}

// The panel forgets a node's devices five minutes after it last heard of
// them and only pushes global device state back after a device report, so a
// quiet node must keep reporting an unchanged device set.
func TestDeviceReportResendsUnchangedDevices(t *testing.T) {
	s, sink := newDeviceTestService(connectedPushClient{})

	s.reportDevices()
	s.reportDevices()

	if len(sink.devices) != 2 {
		t.Fatalf("device reports = %d, want 2", len(sink.devices))
	}
	for i, devices := range sink.devices {
		if len(devices[7]) != 1 || devices[7][0] != "1.1.1.1" {
			t.Fatalf("device report %d = %v", i, devices)
		}
	}
}

func TestReportLeavesDevicesToConnectedDeviceChannel(t *testing.T) {
	s, sink := newDeviceTestService(connectedPushClient{})

	s.pushReportSync()

	if len(sink.reports) != 1 {
		t.Fatalf("reports = %d, want 1", len(sink.reports))
	}
	if sink.reports[0].Alive != nil {
		t.Fatalf("report carried alive IPs %v while the WS device channel is connected", sink.reports[0].Alive)
	}
}

func TestReportCarriesDevicesWithoutDeviceChannel(t *testing.T) {
	for name, push := range map[string]controlplane.PushClient{"rest": nil, "ws down": disconnectedPushClient{}} {
		t.Run(name, func(t *testing.T) {
			s, sink := newDeviceTestService(push)

			s.pushReportSync()
			s.pushReportSync()

			if len(sink.reports) != 2 {
				t.Fatalf("reports = %d, want 2", len(sink.reports))
			}
			for i, report := range sink.reports {
				if len(report.Alive[7]) != 1 {
					t.Fatalf("report %d alive = %v, want user 7's device", i, report.Alive)
				}
			}
		})
	}
}
