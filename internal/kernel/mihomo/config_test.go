package mihomo

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/panel"
)

var testUsersPanel = []panel.User{
	{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444", SpeedLimit: 0, DeviceLimit: 0},
	{ID: 2, UUID: "bbbbbbbb-5555-6666-7777-888888888888", SpeedLimit: 3, DeviceLimit: 2},
}

var testUsers = model.UserSpecsFromPanel(testUsersPanel)

func testNodeSpec(nc *panel.NodeConfig) *model.NodeSpec {
	return model.NodeSpecFromPanel(nc)
}

// assertJSON is a helper that checks a JSON string contains the expected
// key-value pair. It uses simple string matching which is sufficient for
// tests since json.Marshal output is deterministic.
func assertJSON(t *testing.T, jsonStr, key, value string) {
	t.Helper()
	// Match "key":value or "key": value (json.Marshal uses "key":<space>value)
	if !strings.Contains(jsonStr, `"`+key+`":`+value) &&
		!strings.Contains(jsonStr, `"`+key+`": `+value) {
		t.Errorf("expected JSON to contain %q: %q, got:\n%s", key, value, jsonStr)
	}
}

func assertContains(t *testing.T, s, substr string) {
	t.Helper()
	if !strings.Contains(s, substr) {
		t.Errorf("expected JSON to contain %q, got:\n%s", substr, s)
	}
}

// prettyJSON marshals with indent for readable test output.
func prettyJSON(t *testing.T, data []byte) string {
	t.Helper()
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return string(data)
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func TestBuildConfig_VMess(t *testing.T) {
	nc := testNodeSpec(&panel.NodeConfig{
		Protocol:   "vmess",
		ListenIP:   "0.0.0.0",
		ServerPort: 443,
	})
	raw, _, err := buildMihomoConfig(nc, testUsers, kernel.TLSCert{}, t.TempDir())
	if err != nil {
		t.Fatalf("buildMihomoConfig() error = %v", err)
	}
	s := string(raw)
	assertJSON(t, s, "type", `"vmess"`)
	assertJSON(t, s, "port", "443")
	assertJSON(t, s, "udp", "true")
	assertContains(t, s, `"username":"uid_1"`)
	assertContains(t, s, `"uuid":"aaaaaaaa-1111-2222-3333-444444444444"`)
	assertContains(t, s, `"username":"uid_2"`)
	assertContains(t, s, "MATCH,DIRECT")
}

func TestBuildConfig_VLess(t *testing.T) {
	nc := testNodeSpec(&panel.NodeConfig{
		Protocol:   "vless",
		ListenIP:   "0.0.0.0",
		ServerPort: 443,
		TLS:        1,
		Flow:       "xtls-rprx-vision",
	})
	raw, _, err := buildMihomoConfig(nc, testUsers, kernel.TLSCert{
		CertPEM: []byte("test-cert"),
		KeyPEM:  []byte("test-key"),
	}, t.TempDir())
	if err != nil {
		t.Fatalf("buildMihomoConfig() error = %v", err)
	}
	s := string(raw)
	assertJSON(t, s, "type", `"vless"`)
	assertJSON(t, s, "flow", `"xtls-rprx-vision"`)
	assertContains(t, s, `"certificate":`)
	assertContains(t, s, `"private-key":`)
}

func TestBuildConfig_Trojan(t *testing.T) {
	nc := testNodeSpec(&panel.NodeConfig{
		Protocol:   "trojan",
		ListenIP:   "0.0.0.0",
		ServerPort: 8443,
	})
	raw, _, err := buildMihomoConfig(nc, testUsers, kernel.TLSCert{
		CertPEM: []byte("test-cert"),
		KeyPEM:  []byte("test-key"),
	}, t.TempDir())
	if err != nil {
		t.Fatalf("buildMihomoConfig() error = %v", err)
	}
	s := string(raw)
	assertJSON(t, s, "type", `"trojan"`)
	assertContains(t, s, `"password":"aaaaaaaa-1111-2222-3333-444444444444"`)
}

func TestBuildConfig_Shadowsocks(t *testing.T) {
	nc := testNodeSpec(&panel.NodeConfig{
		Protocol:   "shadowsocks",
		ListenIP:   "0.0.0.0",
		ServerPort: 8388,
		Cipher:     "aes-256-gcm",
	})
	raw, _, err := buildMihomoConfig(nc, testUsers, kernel.TLSCert{}, t.TempDir())
	if err != nil {
		t.Fatalf("buildMihomoConfig() error = %v", err)
	}
	s := string(raw)
	assertJSON(t, s, "type", `"shadowsocks"`)
	assertJSON(t, s, "cipher", `"aes-256-gcm"`)
}

func TestBuildConfig_Hysteria2(t *testing.T) {
	nc := testNodeSpec(&panel.NodeConfig{
		Protocol:   "hysteria2",
		ListenIP:   "0.0.0.0",
		ServerPort: 443,
		UpMbps:     100,
		DownMbps:   200,
	})
	raw, _, err := buildMihomoConfig(nc, testUsers, kernel.TLSCert{
		CertPEM: []byte("test-cert"),
		KeyPEM:  []byte("test-key"),
	}, t.TempDir())
	if err != nil {
		t.Fatalf("buildMihomoConfig() error = %v", err)
	}
	s := string(raw)
	assertJSON(t, s, "type", `"hysteria2"`)
	assertJSON(t, s, "up", `"100 Mbps"`)
	assertJSON(t, s, "down", `"200 Mbps"`)
	assertContains(t, s, `"uid_1":`)
}

func TestBuildConfig_VMess_WithWS(t *testing.T) {
	nc := testNodeSpec(&panel.NodeConfig{
		Protocol:   "vmess",
		ListenIP:   "0.0.0.0",
		ServerPort: 443,
		Network:    "ws",
		NetworkSettings: map[string]any{
			"path": "/ws",
			"headers": map[string]any{
				"Host": "example.com",
			},
		},
	})
	raw, _, err := buildMihomoConfig(nc, testUsers, kernel.TLSCert{}, t.TempDir())
	if err != nil {
		t.Fatalf("buildMihomoConfig() error = %v", err)
	}
	s := string(raw)
	assertJSON(t, s, "ws-path", `"/ws"`)
	assertContains(t, s, `"Host":`)
	assertContains(t, s, `"example.com"`)
}

func TestBuildConfig_Outbounds(t *testing.T) {
	nc := testNodeSpec(&panel.NodeConfig{
		Protocol:   "vmess",
		ServerPort: 443,
	})
	raw, _, err := buildMihomoConfig(nc, testUsers, kernel.TLSCert{}, t.TempDir())
	if err != nil {
		t.Fatalf("buildMihomoConfig() error = %v", err)
	}
	s := string(raw)
	assertContains(t, s, `"name":"direct"`)
	assertContains(t, s, `"type":"direct"`)
	assertContains(t, s, `"name":"block"`)
	assertContains(t, s, `"type":"block"`)
}

func TestBuildConfig_RouteRules(t *testing.T) {
	nc := testNodeSpec(&panel.NodeConfig{
		Protocol:   "vmess",
		ServerPort: 443,
		Routes: []panel.RouteRule{
			{Match: []string{"DOMAIN-SUFFIX,google.com"}, Action: "route", ActionValue: "proxy"},
		},
		CustomRouteRules: []panel.CustomRouteRule{
			{
				Name: "block-ads",
				Match: panel.RouteMatch{
					DomainSuffixes: []string{"ads.example.com"},
				},
				Action: panel.RouteAction{Type: "block"},
			},
		},
	})
	raw, _, err := buildMihomoConfig(nc, testUsers, kernel.TLSCert{}, t.TempDir())
	if err != nil {
		t.Fatalf("buildMihomoConfig() error = %v", err)
	}
	s := string(raw)
	assertContains(t, s, "DOMAIN-SUFFIX,google.com,proxy")
	assertContains(t, s, "DOMAIN-SUFFIX,ads.example.com,REJECT")
	assertContains(t, s, "MATCH,DIRECT")
}

func TestBuildConfig_JSONValidity(t *testing.T) {
	protocols := []string{"vmess", "vless", "trojan", "shadowsocks", "hysteria2", "tuic"}
	for _, proto := range protocols {
		t.Run(proto, func(t *testing.T) {
			nc := testNodeSpec(&panel.NodeConfig{
				Protocol:   proto,
				ListenIP:   "0.0.0.0",
				ServerPort: 443,
				Cipher:     "aes-256-gcm",
			})
			raw, _, err := buildMihomoConfig(nc, testUsers, kernel.TLSCert{}, t.TempDir())
			if err != nil {
				t.Fatalf("buildMihomoConfig() error = %v", err)
			}
			var v interface{}
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Fatalf("invalid JSON output: %v\n%s", err, string(raw))
			}
		})
	}
}

// ─── Identity / interface tests ─────────────────────────────────────

func TestMihomoCapabilities(t *testing.T) {
	m := New(config.KernelConfig{Type: "mihomo"})
	caps := m.Capabilities()
	if !caps.BuiltInTrafficStats {
		t.Fatal("expected BuiltInTrafficStats=true")
	}
	if !caps.AliveIPTracking {
		t.Fatal("expected AliveIPTracking=true")
	}
	if !caps.ForceCloseConnection {
		t.Fatal("expected ForceCloseConnection=true")
	}
	if !caps.ForceCloseUser {
		t.Fatal("expected ForceCloseUser=true")
	}
	if caps.PerUserSpeedLimit {
		t.Fatal("expected PerUserSpeedLimit=false")
	}
	if caps.DeviceLimit {
		t.Fatal("expected DeviceLimit=false")
	}
}

func TestMihomoProtocols(t *testing.T) {
	m := New(config.KernelConfig{Type: "mihomo"})
	protocols := m.Protocols()
	for _, want := range []string{"vmess", "vless", "trojan", "shadowsocks", "hysteria2", "tuic"} {
		found := false
		for _, p := range protocols {
			if p == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Protocols() missing %q", want)
		}
	}
}

func TestMihomoName(t *testing.T) {
	m := New(config.KernelConfig{Type: "mihomo"})
	if m.Name() != "mihomo" {
		t.Fatalf("Name() = %q, want %q", m.Name(), "mihomo")
	}
}

func TestMihomoIsRunningInitiallyFalse(t *testing.T) {
	m := New(config.KernelConfig{Type: "mihomo"})
	if m.IsRunning() {
		t.Fatal("expected IsRunning()=false for new kernel")
	}
}

func TestUserUID(t *testing.T) {
	if got := userUID(model.UserSpec{ID: 42}); got != "uid_42" {
		t.Fatalf("userUID(42) = %q, want %q", got, "uid_42")
	}
	if got := userUID(model.UserSpec{ID: 0}); got != "uid_0" {
		t.Fatalf("userUID(0) = %q, want %q", got, "uid_0")
	}
}

func TestBuildConfig_AnyTLS(t *testing.T) {
	nc := testNodeSpec(&panel.NodeConfig{
		Protocol:   "anytls",
		ListenIP:   "0.0.0.0",
		ServerPort: 443,
	})
	raw, _, err := buildMihomoConfig(nc, testUsers, kernel.TLSCert{
		CertPEM: []byte("test-cert"),
		KeyPEM:  []byte("test-key"),
	}, t.TempDir())
	if err != nil {
		t.Fatalf("buildMihomoConfig() error = %v", err)
	}
	s := string(raw)
	assertJSON(t, s, "type", `"anytls"`)
	assertContains(t, s, `"name":"uid_1"`)
	assertContains(t, s, `"certificate":`)
	assertContains(t, s, `"private-key":`)
}

func TestBuildConfig_Mieru(t *testing.T) {
	nc := testNodeSpec(&panel.NodeConfig{
		Protocol:       "mieru",
		ListenIP:       "0.0.0.0",
		ServerPort:     443,
		Transport:      "TCP",
		TrafficPattern: "constant:1000,100",
	})
	raw, _, err := buildMihomoConfig(nc, testUsers, kernel.TLSCert{}, t.TempDir())
	if err != nil {
		t.Fatalf("buildMihomoConfig() error = %v", err)
	}
	s := string(raw)
	assertJSON(t, s, "type", `"mieru"`)
	assertJSON(t, s, "transport", `"TCP"`)
	assertContains(t, s, `"traffic_pattern":`)
	assertContains(t, s, `"name":"uid_1"`)
}

func TestBuildConfig_TrustTunnel(t *testing.T) {
	nc := testNodeSpec(&panel.NodeConfig{
		Protocol:                    "trusttunnel",
		ListenIP:                    "0.0.0.0",
		ServerPort:                  443,
		TrustTunnelNetwork:          []string{"tcp", "udp"},
		TrustTunnelCongestionController: "bbr",
		TrustTunnelCWND:             100,
		TrustTunnelBBRProfile:       "default",
	})
	raw, _, err := buildMihomoConfig(nc, testUsers, kernel.TLSCert{
		CertPEM: []byte("test-cert"),
		KeyPEM:  []byte("test-key"),
	}, t.TempDir())
	if err != nil {
		t.Fatalf("buildMihomoConfig() error = %v", err)
	}
	s := string(raw)
	assertJSON(t, s, "type", `"trusttunnel"`)
	assertContains(t, s, `"tcp"`)
	assertContains(t, s, `"udp"`)
	assertJSON(t, s, "congestion-controller", `"bbr"`)
	assertJSON(t, s, "cwnd", "100")
	assertJSON(t, s, "bbr-profile", `"default"`)
	assertContains(t, s, `"name":"uid_1"`)
	assertContains(t, s, `"certificate":`)
	assertContains(t, s, `"private-key":`)
}

func TestBuildConfig_Sudoku(t *testing.T) {
	paddingMin := 10
	paddingMax := 100
	nc := testNodeSpec(&panel.NodeConfig{
		Protocol:   "sudoku",
		ListenIP:   "0.0.0.0",
		ServerPort: 443,
		ServerKey:  "my-secret-key",
		SudokuConfig: &panel.SudokuConfig{
			AEADMethod:   "aes-256-gcm",
			PaddingMin:   &paddingMin,
			PaddingMax:   &paddingMax,
			TableType:    "prefer_ascii",
			HTTPMaskMode: "auto",
		},
	})
	raw, _, err := buildMihomoConfig(nc, testUsers, kernel.TLSCert{}, t.TempDir())
	if err != nil {
		t.Fatalf("buildMihomoConfig() error = %v", err)
	}
	s := string(raw)
	assertJSON(t, s, "type", `"sudoku"`)
	assertJSON(t, s, "key", `"my-secret-key"`)
	assertJSON(t, s, "aead-method", `"aes-256-gcm"`)
	assertJSON(t, s, "padding-min", "10")
	assertJSON(t, s, "padding-max", "100")
	assertJSON(t, s, "table-type", `"prefer_ascii"`)
	assertJSON(t, s, "http-mask-mode", `"auto"`)
}
