package model

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/panel"
)

func TestNodeSpecFromPanelValidated_AllowsTargetsFromCustomConfigOutbounds(t *testing.T) {
	dir := t.TempDir()
	customConfigPath := filepath.Join(dir, "custom.json")
	if err := os.WriteFile(customConfigPath, []byte(`{"outbounds":[{"tag":"wg-exit","protocol":"wireguard"}]}`), 0o644); err != nil {
		t.Fatalf("write custom config: %v", err)
	}

	_, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
		Protocol:   "shadowsocks",
		ServerPort: 8388,
		CustomOutbounds: []panel.OutboundConfig{{
			Tag:      "proxy",
			Protocol: "socks",
			ProxyTag: "wg-exit",
			Settings: map[string]any{"server": "2.2.2.2", "server_port": 1080},
		}},
		CustomRouteRules: []panel.CustomRouteRule{{
			Action: panel.RouteAction{Type: "route", Target: "wg-exit"},
			Match:  panel.RouteMatch{DomainSuffixes: []string{"example.com"}},
		}},
	}, config.KernelConfig{CustomConfig: customConfigPath})
	if err != nil {
		t.Fatalf("expected custom_config outbound tags to be available, got %v", err)
	}
}

func TestNodeSpecFromPanelValidated_RejectsDuplicateTagsAcrossSources(t *testing.T) {
	dir := t.TempDir()
	customConfigPath := filepath.Join(dir, "custom.yaml")
	if err := os.WriteFile(customConfigPath, []byte("outbounds:\n  - tag: warp\n    protocol: wireguard\n"), 0o644); err != nil {
		t.Fatalf("write custom config: %v", err)
	}

	_, err := NodeSpecFromPanelValidated(&panel.NodeConfig{
		Protocol:   "shadowsocks",
		ServerPort: 8388,
		CustomOutbounds: []panel.OutboundConfig{{
			Tag:      "warp",
			Protocol: "socks",
			Settings: map[string]any{"server": "2.2.2.2", "server_port": 1080},
		}},
	}, config.KernelConfig{
		CustomConfig: customConfigPath,
		CustomOutbound: []map[string]any{{
			"tag":      "proxy",
			"protocol": "socks",
		}},
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), `custom_outbounds[0].tag duplicates "warp" from kernel.custom_config.outbounds[0]`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateOutboundTagCollisions_RejectsDuplicateRawSources(t *testing.T) {
	err := validateOutboundTagCollisions(nil, []outboundTagSource{
		{Tag: "warp", Source: "kernel.custom_outbound[0]"},
		{Tag: "warp", Source: "kernel.custom_config.outbounds[0]"},
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), `kernel.custom_config.outbounds[0].tag duplicates "warp" from kernel.custom_outbound[0]`) {
		t.Fatalf("unexpected error: %v", err)
	}
}
