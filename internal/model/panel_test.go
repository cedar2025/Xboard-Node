package model

import (
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/panel"
)

func TestNodeSpecFromPanelValidated(t *testing.T) {
	t.Run("valid custom outbounds and route targets", func(t *testing.T) {
		node, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
			Protocol:   "shadowsocks",
			ServerPort: 8388,
			CustomOutbounds: []panel.OutboundConfig{
				{Tag: "warp", Protocol: "wireguard", Settings: map[string]any{"server": "1.1.1.1", "server_port": 2408, "private_key": "pk"}},
				{Tag: "proxy", Protocol: "socks", ProxyTag: "warp", Settings: map[string]any{"server": "2.2.2.2", "server_port": 1080}},
			},
			CustomRouteRules: []panel.CustomRouteRule{{
				Action: panel.RouteAction{Type: "route", Target: "proxy"},
				Match:  panel.RouteMatch{DomainSuffixes: []string{"example.com"}},
			}},
		}, config.KernelConfig{Type: "singbox"})
		if err != nil {
			t.Fatalf("NodeSpecFromPanelValidated: %v", err)
		}
		if node == nil || len(node.CustomOutbounds) != 2 {
			t.Fatalf("unexpected node spec: %#v", node)
		}
	})

	t.Run("invalid custom outbounds", func(t *testing.T) {
		_, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
			Protocol:   "shadowsocks",
			ServerPort: 8388,
			CustomOutbounds: []panel.OutboundConfig{{
				Tag: "proxy", Protocol: "socks", ProxyTag: "missing", Settings: map[string]any{"server": "2.2.2.2", "server_port": 1080},
			}},
		}, config.KernelConfig{Type: "singbox"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), `custom_outbounds[0].proxy_tag references unknown outbound "missing"`) {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("accept outbound protocol another kernel can run", func(t *testing.T) {
		// Normalisation is kernel independent: the kernel is selected per
		// target later, so a hysteria2 outbound must survive even when the
		// configured kernel is xray (SelectKernel moves the node to sing-box).
		node, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
			Protocol:   "shadowsocks",
			ServerPort: 8388,
			CustomOutbounds: []panel.OutboundConfig{{
				Tag: "hy2", Protocol: "hysteria2", Settings: map[string]any{"server": "2.2.2.2", "server_port": 8443},
			}},
		}, config.KernelConfig{Type: "xray"})
		if err != nil {
			t.Fatalf("NodeSpecFromPanelValidated: %v", err)
		}
		if err := ValidateNodeSpec(node, config.KernelConfig{Type: "xray"}); err == nil || !strings.Contains(err.Error(), `protocol "hysteria2" is not supported by kernel "xray"`) {
			t.Fatalf("kernel-specific validation must still reject it for xray: %v", err)
		}
	})

	t.Run("reject outbound protocol no kernel supports", func(t *testing.T) {
		_, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
			Protocol:   "shadowsocks",
			ServerPort: 8388,
			CustomOutbounds: []panel.OutboundConfig{{
				Tag: "x", Protocol: "carrier-pigeon", Settings: map[string]any{"server": "2.2.2.2", "server_port": 8443},
			}},
		}, config.KernelConfig{Type: "xray"})
		if err == nil || !strings.Contains(err.Error(), `custom_outbounds[0].protocol "carrier-pigeon" is not supported by any kernel`) {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("reject missing protocol and bad port", func(t *testing.T) {
		if _, err := NodeSpecFromPanelValidated(&panel.NodeConfig{ServerPort: 8388}, config.KernelConfig{Type: "singbox"}); err == nil {
			t.Fatal("expected error for missing protocol")
		}
		if _, err := NodeSpecFromPanelValidated(&panel.NodeConfig{Protocol: "vmess", ServerPort: 70000}, config.KernelConfig{Type: "singbox"}); err == nil {
			t.Fatal("expected error for port out of range")
		}
	})

	t.Run("reject unknown route target", func(t *testing.T) {
		_, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
			Protocol:   "shadowsocks",
			ServerPort: 8388,
			CustomOutbounds: []panel.OutboundConfig{{
				Tag: "warp", Protocol: "wireguard", Settings: map[string]any{"server": "1.1.1.1", "server_port": 2408, "private_key": "pk"},
			}},
			CustomRouteRules: []panel.CustomRouteRule{{
				Action: panel.RouteAction{Type: "route", Target: "missing"},
				Match:  panel.RouteMatch{DomainSuffixes: []string{"example.com"}},
			}},
		}, config.KernelConfig{Type: "singbox"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), `custom_route_rules[0].action.target references unknown outbound "missing"`) {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
