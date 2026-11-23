package model

import (
	"strings"
	"testing"
)

func TestValidateCustomOutbounds(t *testing.T) {
	tests := []struct {
		name      string
		outbounds []OutboundConfig
		kernel    string
		wantErr   string
	}{
		{
			name: "valid chain",
			outbounds: []OutboundConfig{
				{Tag: "warp", Protocol: "wireguard", Settings: map[string]any{"server": "1.1.1.1", "server_port": 2408, "private_key": "pk"}},
				{Tag: "proxy", Protocol: "socks", ProxyTag: "warp", Settings: map[string]any{"server": "2.2.2.2", "server_port": 1080}},
			},
			kernel: "xray",
		},
		{
			name:      "valid native vmess settings preserved",
			outbounds: []OutboundConfig{{Tag: "vmess-native", Protocol: "vmess", Settings: map[string]any{"vnext": []any{map[string]any{"address": "1.1.1.1", "port": 443}}}}},
			kernel:    "xray",
		},
		{
			name:      "missing tag",
			outbounds: []OutboundConfig{{Protocol: "socks", Settings: map[string]any{"server": "2.2.2.2", "server_port": 1080}}},
			wantErr:   "custom_outbounds[0].tag is required",
		},
		{
			name:      "missing protocol",
			outbounds: []OutboundConfig{{Tag: "proxy", Settings: map[string]any{"server": "2.2.2.2", "server_port": 1080}}},
			wantErr:   "custom_outbounds[0].protocol is required",
		},
		{
			name: "duplicate tag",
			outbounds: []OutboundConfig{
				{Tag: "proxy", Protocol: "socks", Settings: map[string]any{"server": "2.2.2.2", "server_port": 1080}},
				{Tag: "proxy", Protocol: "http", Settings: map[string]any{"server": "3.3.3.3", "server_port": 8080}},
			},
			wantErr: `custom_outbounds[1].tag duplicates "proxy"`,
		},
		{
			name:      "self proxy tag",
			outbounds: []OutboundConfig{{Tag: "proxy", Protocol: "socks", ProxyTag: "proxy", Settings: map[string]any{"server": "2.2.2.2", "server_port": 1080}}},
			wantErr:   "custom_outbounds[0].proxy_tag must not reference itself",
		},
		{
			name:      "unknown proxy tag",
			outbounds: []OutboundConfig{{Tag: "proxy", Protocol: "socks", ProxyTag: "missing", Settings: map[string]any{"server": "2.2.2.2", "server_port": 1080}}},
			wantErr:   `custom_outbounds[0].proxy_tag references unknown outbound "missing"`,
		},
		{
			name:      "built-in proxy tag allowed",
			outbounds: []OutboundConfig{{Tag: "proxy", Protocol: "socks", ProxyTag: "direct", Settings: map[string]any{"server": "2.2.2.2", "server_port": 1080}}},
		},
		{
			name:      "unsupported protocol for kernel",
			outbounds: []OutboundConfig{{Tag: "hy2", Protocol: "hysteria2", Settings: map[string]any{"server": "2.2.2.2", "server_port": 8443}}},
			kernel:    "xray",
			wantErr:   `custom_outbounds[0].protocol "hysteria2" is not supported by kernel "xray"`,
		},
		{
			name:      "missing settings",
			outbounds: []OutboundConfig{{Tag: "proxy", Protocol: "socks"}},
			wantErr:   "custom_outbounds[0].settings is required",
		},
		{
			name:      "reserved snake case key in settings",
			outbounds: []OutboundConfig{{Tag: "proxy", Protocol: "socks", Settings: map[string]any{"proxy_tag": "bad", "server": "2.2.2.2", "server_port": 1080}}},
			wantErr:   "custom_outbounds[0].settings.proxy_tag is reserved",
		},
		{
			name:      "reserved camel case key in settings",
			outbounds: []OutboundConfig{{Tag: "proxy", Protocol: "socks", Settings: map[string]any{"proxyTag": "bad", "server": "2.2.2.2", "server_port": 1080}}},
			wantErr:   "custom_outbounds[0].settings.proxyTag is reserved",
		},
		{
			name:      "invalid server_port",
			outbounds: []OutboundConfig{{Tag: "proxy", Protocol: "socks", Settings: map[string]any{"server": "2.2.2.2", "server_port": 70000}}},
			wantErr:   "custom_outbounds[0].settings.server_port must be between 1 and 65535",
		},
		{
			name:      "invalid camel case serverPort",
			outbounds: []OutboundConfig{{Tag: "proxy", Protocol: "socks", Settings: map[string]any{"server": "2.2.2.2", "serverPort": 70000}}},
			wantErr:   "custom_outbounds[0].settings.serverPort must be between 1 and 65535",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCustomOutboundsForKernel(tc.outbounds, tc.kernel, nil)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if tc.wantErr != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}
