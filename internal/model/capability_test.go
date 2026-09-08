package model

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
)

// The capability / TLS-policy table is the contract the apply pipeline relies
// on. Every row below was checked against the sing-box and xray config
// builders of this build (singbox.buildInbound / xray.buildInbound): a kernel
// is "supported" only when its builder actually emits the field on the wire.
func TestResolveTLSRequirementTable(t *testing.T) {
	cases := []struct {
		name string
		spec NodeSpec
		want TLSRequirement
		err  string
	}{
		{"hysteria v2", NodeSpec{Protocol: "hysteria", Version: 2}, TLSRequired, ""},
		{"hysteria v1", NodeSpec{Protocol: "hysteria", Version: 1}, TLSRequired, ""},
		{"hysteria2 alias", NodeSpec{Protocol: "hysteria2", Version: 2}, TLSRequired, ""},
		{"tuic", NodeSpec{Protocol: "tuic"}, TLSRequired, ""},
		{"anytls", NodeSpec{Protocol: "anytls"}, TLSRequired, ""},
		{"trojan plain", NodeSpec{Protocol: "trojan"}, TLSRequired, ""},
		{"trojan tls", NodeSpec{Protocol: "trojan", TLS: 1}, TLSRequired, ""},
		{"trojan reality", NodeSpec{Protocol: "trojan", TLS: 2}, TLSReality, ""},
		{"vless plain", NodeSpec{Protocol: "vless"}, TLSOff, ""},
		{"vless tls", NodeSpec{Protocol: "vless", TLS: 1}, TLSRequested, ""},
		{"vless reality", NodeSpec{Protocol: "vless", TLS: 2}, TLSReality, ""},
		{"vmess plain", NodeSpec{Protocol: "vmess"}, TLSOff, ""},
		{"vmess tls", NodeSpec{Protocol: "vmess", TLS: 1}, TLSRequested, ""},
		{"vmess reality rejected", NodeSpec{Protocol: "vmess", TLS: 2}, "", "does not support reality"},
		{"http plain", NodeSpec{Protocol: "http"}, TLSOff, ""},
		{"http tls", NodeSpec{Protocol: "http", TLS: 1}, TLSRequested, ""},
		{"naive plain", NodeSpec{Protocol: "naive"}, TLSOff, ""},
		{"naive tls", NodeSpec{Protocol: "naive", TLS: 1}, TLSRequested, ""},
		{"socks plain", NodeSpec{Protocol: "socks"}, TLSNotUsed, ""},
		{"socks tls flag", NodeSpec{Protocol: "socks", TLS: 1}, TLSRequested, ""},
		{"shadowsocks ignores tls", NodeSpec{Protocol: "shadowsocks", TLS: 1}, TLSNotUsed, ""},
		{"mieru", NodeSpec{Protocol: "mieru"}, TLSNotUsed, ""},
		{"unknown", NodeSpec{Protocol: "wireguard"}, "", "unknown protocol"},
		{"empty", NodeSpec{}, "", "protocol is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveTLSRequirement(&tc.spec)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("err = %v, want containing %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("requirement = %q, want %q", got, tc.want)
			}
		})
	}
}

func reality(spec NodeSpec) NodeSpec {
	spec.TLS = 2
	spec.TLSSettings = map[string]any{"private_key": "k", "server_name": "www.example.com", "short_id": "ab"}
	return spec
}

// TestKernelCompatibilityTable enumerates the protocol × version × transport ×
// TLS combinations the panel can produce and pins which kernel may run each.
func TestKernelCompatibilityTable(t *testing.T) {
	cases := []struct {
		name    string
		spec    NodeSpec
		singbox bool
		xray    bool
	}{
		// Protocol coverage per kernel.
		{"shadowsocks", NodeSpec{Protocol: "shadowsocks", Cipher: "aes-128-gcm"}, true, true},
		{"shadowsocks plugin unsupported everywhere", NodeSpec{Protocol: "shadowsocks", Cipher: "aes-128-gcm", Plugin: "obfs"}, false, false},
		{"vmess tcp", NodeSpec{Protocol: "vmess"}, true, true},
		{"vmess ws tls", NodeSpec{Protocol: "vmess", Network: "ws", TLS: 1}, true, true},
		{"vmess grpc", NodeSpec{Protocol: "vmess", Network: "grpc"}, true, true},
		{"vmess httpupgrade", NodeSpec{Protocol: "vmess", Network: "httpupgrade"}, true, true},
		{"vmess h2", NodeSpec{Protocol: "vmess", Network: "h2", TLS: 1}, true, true},
		{"vmess xhttp needs xray", NodeSpec{Protocol: "vmess", Network: "xhttp"}, false, true},
		{"vless splithttp needs xray", NodeSpec{Protocol: "vless", Network: "splithttp", TLS: 1}, false, true},
		{"vless kcp xray only", NodeSpec{Protocol: "vless", Network: "kcp"}, false, true},
		{"vless unknown transport", NodeSpec{Protocol: "vless", Network: "carrier-pigeon"}, false, false},
		{"vless reality vision", reality(NodeSpec{Protocol: "vless", Flow: "xtls-rprx-vision"}), true, true},
		{"vless reality missing key", NodeSpec{Protocol: "vless", TLS: 2, TLSSettings: map[string]any{"server_name": "x"}}, false, false},
		{"vless encryption needs xray", NodeSpec{Protocol: "vless", Decryption: "mlkem768x25519plus.native.600s.abc"}, false, true},
		{"vless multiplex needs singbox", NodeSpec{Protocol: "vless", Multiplex: &MultiplexConfig{Enabled: true}}, true, false},
		{"vless multiplex disabled is fine", NodeSpec{Protocol: "vless", Multiplex: &MultiplexConfig{Enabled: false}}, true, true},
		{"vmess multiplex with xhttp: nobody", NodeSpec{Protocol: "vmess", Network: "xhttp", Multiplex: &MultiplexConfig{Enabled: true}}, false, false},
		{"trojan tls", NodeSpec{Protocol: "trojan", TLS: 1, ServerName: "t.example.com"}, true, true},
		{"trojan reality", reality(NodeSpec{Protocol: "trojan"}), true, true},
		{"trojan ws", NodeSpec{Protocol: "trojan", Network: "ws", TLS: 1}, true, true},
		{"hysteria v2", NodeSpec{Protocol: "hysteria", Version: 2}, true, true},
		{"hysteria v2 obfs needs singbox", NodeSpec{Protocol: "hysteria", Version: 2, Obfs: "salamander", ObfsPassword: "p"}, true, false},
		{"hysteria v1 singbox only", NodeSpec{Protocol: "hysteria", Version: 1, Obfs: "x"}, true, false},
		{"hysteria v1 no obfs singbox only", NodeSpec{Protocol: "hysteria", Version: 1}, true, false},
		{"hysteria version missing", NodeSpec{Protocol: "hysteria"}, false, false},
		{"hysteria v3", NodeSpec{Protocol: "hysteria", Version: 3}, false, false},
		{"tuic singbox only", NodeSpec{Protocol: "tuic", Version: 5, CongestionControl: "bbr"}, true, false},
		{"anytls singbox only", NodeSpec{Protocol: "anytls", PaddingScheme: "stop=8"}, true, false},
		{"naive singbox only", NodeSpec{Protocol: "naive", TLS: 1}, true, false},
		{"mieru singbox only", NodeSpec{Protocol: "mieru", Transport: "TCP"}, true, false},
		{"socks plain", NodeSpec{Protocol: "socks"}, true, true},
		{"socks tls flag unsupported everywhere", NodeSpec{Protocol: "socks", TLS: 1}, false, false},
		{"http plain", NodeSpec{Protocol: "http"}, true, true},
		{"http tls", NodeSpec{Protocol: "http", TLS: 1}, true, true},
		{"proxy protocol vmess needs xray", NodeSpec{Protocol: "vmess", AcceptProxyProtocol: true}, false, true},
		{"proxy protocol via network settings needs xray", NodeSpec{Protocol: "vless", NetworkSettings: map[string]any{"acceptProxyProtocol": true}}, false, true},
		{"proxy protocol shadowsocks: nobody", NodeSpec{Protocol: "shadowsocks", Cipher: "aes-128-gcm", AcceptProxyProtocol: true}, false, false},
		{"unknown protocol", NodeSpec{Protocol: "wireguard"}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotSingbox := KernelCompatibility(KernelSingbox, &tc.spec) == nil
			gotXray := KernelCompatibility(KernelXray, &tc.spec) == nil
			if gotSingbox != tc.singbox || gotXray != tc.xray {
				t.Fatalf("compat singbox=%v xray=%v, want singbox=%v xray=%v (singbox err: %v; xray err: %v)",
					gotSingbox, gotXray, tc.singbox, tc.xray,
					KernelCompatibility(KernelSingbox, &tc.spec), KernelCompatibility(KernelXray, &tc.spec))
			}
		})
	}
}

func TestSelectKernelHonoursPreferenceAndFallsBack(t *testing.T) {
	kcfg := config.KernelConfig{}

	sel, err := SelectKernel(&NodeSpec{Protocol: "vmess", ServerPort: 443}, KernelSingbox, kcfg)
	if err != nil || sel.Kernel != KernelSingbox || sel.Reason != "" {
		t.Fatalf("preferred singbox for vmess: %+v, %v", sel, err)
	}

	sel, err = SelectKernel(&NodeSpec{Protocol: "vmess", ServerPort: 443}, KernelXray, kcfg)
	if err != nil || sel.Kernel != KernelXray || sel.Reason != "" {
		t.Fatalf("preferred xray for vmess: %+v, %v", sel, err)
	}

	sel, err = SelectKernel(&NodeSpec{Protocol: "vless", Network: "xhttp", ServerPort: 443}, KernelSingbox, kcfg)
	if err != nil || sel.Kernel != KernelXray || !strings.Contains(sel.Reason, "xhttp") {
		t.Fatalf("xhttp must fall back to xray with a reason: %+v, %v", sel, err)
	}

	sel, err = SelectKernel(&NodeSpec{Protocol: "hysteria", Version: 2, ServerPort: 443}, KernelXray, kcfg)
	if err != nil || sel.Kernel != KernelXray {
		t.Fatalf("hysteria v2 on preferred xray stays on xray: %+v, %v", sel, err)
	}
	if sel.TLS != TLSRequired {
		t.Fatalf("selection must carry the tls requirement, got %q", sel.TLS)
	}

	sel, err = SelectKernel(&NodeSpec{Protocol: "tuic", ServerPort: 443}, KernelXray, kcfg)
	if err != nil || sel.Kernel != KernelSingbox || sel.Reason == "" {
		t.Fatalf("tuic on preferred xray must fall back to singbox: %+v, %v", sel, err)
	}

	_, err = SelectKernel(&NodeSpec{Protocol: "vmess", Network: "xhttp", Multiplex: &MultiplexConfig{Enabled: true}, ServerPort: 443}, KernelSingbox, kcfg)
	if err == nil || !strings.Contains(err.Error(), "singbox:") || !strings.Contains(err.Error(), "xray:") {
		t.Fatalf("an impossible combination must name both kernels' reasons, got %v", err)
	}

	// Custom outbounds are part of the decision: a hysteria2 outbound is a
	// sing-box feature even when xray is preferred.
	sel, err = SelectKernel(&NodeSpec{
		Protocol: "vmess", ServerPort: 443,
		CustomOutbounds: []OutboundConfig{{Tag: "hy2", Protocol: "hysteria2", Settings: map[string]any{"server": "1.1.1.1", "server_port": 443, "password": "p"}}},
	}, KernelXray, kcfg)
	if err != nil || sel.Kernel != KernelSingbox {
		t.Fatalf("hysteria2 custom outbound must move the node to singbox: %+v, %v", sel, err)
	}
}

func TestSelectKernelIgnoresPreviousSelection(t *testing.T) {
	// The preference is the operator's configuration; a node that once ran on
	// xray because of xhttp goes back to the preferred kernel as soon as the
	// target allows it.
	kcfg := config.KernelConfig{}
	first, err := SelectKernel(&NodeSpec{Protocol: "vless", Network: "xhttp", ServerPort: 443}, KernelSingbox, kcfg)
	if err != nil || first.Kernel != KernelXray {
		t.Fatalf("first: %+v %v", first, err)
	}
	second, err := SelectKernel(&NodeSpec{Protocol: "vless", Network: "ws", ServerPort: 443}, KernelSingbox, kcfg)
	if err != nil || second.Kernel != KernelSingbox {
		t.Fatalf("second: %+v %v", second, err)
	}
}

func TestLocalCustomConfigCompatible(t *testing.T) {
	xrayOutbound := map[string]any{"protocol": "freedom", "tag": "x"}
	singboxOutbound := map[string]any{"type": "direct", "tag": "s"}
	ambiguous := map[string]any{"tag": "a"}

	if err := LocalCustomConfigCompatible(KernelSingbox, config.KernelConfig{CustomOutbound: []map[string]any{singboxOutbound, ambiguous}}); err != nil {
		t.Fatalf("singbox-native outbound must be fine on singbox: %v", err)
	}
	if err := LocalCustomConfigCompatible(KernelXray, config.KernelConfig{CustomOutbound: []map[string]any{singboxOutbound}}); err == nil {
		t.Fatal("singbox-native outbound must block xray")
	}
	if err := LocalCustomConfigCompatible(KernelSingbox, config.KernelConfig{CustomOutbound: []map[string]any{xrayOutbound}}); err == nil {
		t.Fatal("xray-native outbound must block singbox")
	}
	if err := LocalCustomConfigCompatible(KernelSingbox, config.KernelConfig{CustomRoute: []map[string]any{{"type": "field", "outboundTag": "x"}}}); err == nil {
		t.Fatal("xray-native route must block singbox")
	}
	if err := LocalCustomConfigCompatible(KernelXray, config.KernelConfig{CustomRoute: []map[string]any{{"outbound": "direct", "domain": []string{"a"}}}}); err == nil {
		t.Fatal("singbox-native route must block xray")
	}

	dir := t.TempDir()
	singboxFile := filepath.Join(dir, "sb.json")
	if err := os.WriteFile(singboxFile, []byte(`{"route":{"rules":[]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	xrayFile := filepath.Join(dir, "xray.json")
	if err := os.WriteFile(xrayFile, []byte(`{"routing":{"rules":[]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := LocalCustomConfigCompatible(KernelXray, config.KernelConfig{CustomConfig: singboxFile}); err == nil {
		t.Fatal("singbox custom_config must block xray")
	}
	if err := LocalCustomConfigCompatible(KernelSingbox, config.KernelConfig{CustomConfig: xrayFile}); err == nil {
		t.Fatal("xray custom_config must block singbox")
	}
	if err := LocalCustomConfigCompatible(KernelSingbox, config.KernelConfig{CustomConfig: singboxFile}); err != nil {
		t.Fatalf("matching custom_config: %v", err)
	}
	if err := LocalCustomConfigCompatible(KernelXray, config.KernelConfig{CustomConfig: filepath.Join(dir, "missing.json")}); err != nil {
		t.Fatalf("missing custom_config never blocks: %v", err)
	}

	// A sing-box native local config pins the kernel: an xhttp node then has
	// no kernel at all instead of silently losing the operator's config.
	_, err := SelectKernel(&NodeSpec{Protocol: "vless", Network: "xhttp", ServerPort: 443}, KernelSingbox, config.KernelConfig{CustomConfig: singboxFile})
	if err == nil {
		t.Fatal("xhttp with a sing-box custom_config must be rejected")
	}
}

func TestSupportedProtocolsTable(t *testing.T) {
	rows := SupportedProtocols()
	got := map[string]string{}
	for _, row := range rows {
		got[row.Protocol] = strings.Join(row.Kernels, ",")
	}
	want := map[string]string{
		"anytls":      "singbox",
		"http":        "singbox,xray",
		"hysteria":    "singbox,xray",
		"mieru":       "singbox",
		"naive":       "singbox",
		"shadowsocks": "singbox,xray",
		"socks":       "singbox,xray",
		"trojan":      "singbox,xray",
		"tuic":        "singbox",
		"vless":       "singbox,xray",
		"vmess":       "singbox,xray",
	}
	if len(got) != len(want) {
		t.Fatalf("rows = %v, want %v", got, want)
	}
	for protocol, kernels := range want {
		if got[protocol] != kernels {
			t.Fatalf("%s: kernels = %q, want %q", protocol, got[protocol], kernels)
		}
	}
}

func TestCloneNodeSpecIsDeep(t *testing.T) {
	spec := &NodeSpec{
		Protocol:        "vless",
		TLSSettings:     map[string]any{"private_key": "k"},
		NetworkSettings: map[string]any{"path": "/p"},
		CertConfig:      &config.CertConfig{CertMode: "self", DNSEnv: map[string]string{"A": "1"}},
		Multiplex:       &MultiplexConfig{Enabled: true, Brutal: &BrutalConfig{Enabled: true}},
		CustomOutbounds: []OutboundConfig{{Tag: "t", Settings: map[string]any{"server": "s"}}},
		Routes:          []RouteRule{{Match: []string{"a"}}},
	}
	clone := CloneNodeSpec(spec)
	clone.TLSSettings["private_key"] = "changed"
	clone.NetworkSettings["path"] = "/changed"
	clone.CertConfig.CertMode = "none"
	clone.CertConfig.DNSEnv["A"] = "2"
	clone.Multiplex.Brutal.Enabled = false
	clone.CustomOutbounds[0].Settings["server"] = "changed"
	clone.Routes[0].Match[0] = "changed"
	if spec.TLSSettings["private_key"] != "k" || spec.NetworkSettings["path"] != "/p" || spec.CertConfig.CertMode != "self" ||
		spec.CertConfig.DNSEnv["A"] != "1" || !spec.Multiplex.Brutal.Enabled || spec.CustomOutbounds[0].Settings["server"] != "s" || spec.Routes[0].Match[0] != "a" {
		t.Fatalf("clone shares memory with the original: %+v", spec)
	}
}
