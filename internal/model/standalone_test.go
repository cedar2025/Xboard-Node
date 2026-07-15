package model

import (
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
)

func TestNodeSpecFromStandalone(t *testing.T) {
	cfg := &config.Config{
		Kernel: config.KernelConfig{LogLevel: "info"},
		Standalone: &config.StandaloneConfig{
			Enabled: true,
			Node: config.StandaloneNodeConfig{
				Protocol:            "vless",
				ListenIP:            "::",
				ServerPort:          8443,
				Network:             "ws",
				NetworkSettings:     map[string]any{"path": "/ws"},
				TLS:                 1,
				Host:                "node.example.com",
				ServerName:          "node.example.com",
				AcceptProxyProtocol: true,
				PaddingScheme:       "stop=8\n0=30-30",
				Routes:              []config.StandaloneRouteRule{{ID: 1, Match: []string{"example.com"}, Action: "direct"}},
				Multiplex:           &config.StandaloneMultiplexConfig{Enabled: true, Protocol: "smux", MaxConnections: 4},
			},
			Users: []config.StandaloneUser{{ID: 7, UUID: "11111111-1111-1111-1111-111111111111", SpeedLimit: 50, DeviceLimit: 2}},
		},
	}

	nc := NodeSpecFromStandalone(cfg)
	users := UserSpecsFromStandalone(cfg)
	if nc.Protocol != "vless" || nc.ServerPort != 8443 {
		t.Fatalf("unexpected node spec: %#v", nc)
	}
	if nc.NetworkSettings["path"] != "/ws" {
		t.Fatalf("network_settings.path: got %v", nc.NetworkSettings["path"])
	}
	if nc.PaddingScheme != "stop=8\n0=30-30" {
		t.Fatalf("padding_scheme: got %q", nc.PaddingScheme)
	}
	if nc.Multiplex == nil || !nc.Multiplex.Enabled {
		t.Fatal("expected multiplex config to be copied")
	}
	if len(users) != 1 || users[0].DeviceLimit != 2 {
		t.Fatalf("users: %#v", users)
	}
}
