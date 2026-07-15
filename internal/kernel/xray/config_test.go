package xray

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/panel"
)

var testKernelCfg = config.KernelConfig{
	Type:     "xray",
	LogLevel: "warn",
}

var testUsersPanel = []panel.User{
	{ID: 1, UUID: "279d4f89-3a2c-488d-a67c-2d39a72acdde"},
	{ID: 5, UUID: "4d5965c8-a60c-452a-a943-af83ec0bb0db"},
}

var testUsers = model.UserSpecsFromPanel(testUsersPanel)

func testNodeSpec(nc *panel.NodeConfig) *model.NodeSpec { return model.NodeSpecFromPanel(nc) }

func testRouteRules(r []panel.RouteRule) []model.RouteRule {
	if r == nil {
		return nil
	}
	return model.NodeSpecFromPanel(&panel.NodeConfig{Routes: r}).Routes
}

func TestBuildConfig_OutboundPriority(t *testing.T) {
	kcfg := config.KernelConfig{
		LogLevel: "info",
		CustomOutbound: []map[string]any{
			{"tag": "block", "protocol": "dns"}, // Local static override
		},
	}
	nc := &panel.NodeConfig{
		Protocol:   "shadowsocks",
		ServerPort: 111,
		Cipher:     "aes-128-gcm",
		CustomOutbounds: []panel.OutboundConfig{
			{Tag: "direct", Protocol: "socks", Settings: map[string]any{"address": "1.2.3.4"}}, // Panel override
		},
	}

	cfg := buildConfig(kcfg, testNodeSpec(nc), testUsers, kernel.TLSCert{})
	outbounds := cfg["outbounds"].([]M)

	// Since we overrode both 'direct' and 'block', the result should contain
	// exactly these two custom outbounds, without auto-generated defaults.
	if len(outbounds) != 2 {
		t.Errorf("outbounds: got %d, want 2", len(outbounds))
	}

	foundDirect := false
	foundBlock := false

	for _, o := range outbounds {
		tag := o["tag"].(string)
		if tag == "direct" {
			foundDirect = true
			if o["protocol"] != "socks" {
				t.Errorf("expected 'direct' protocol to be 'socks' (panel priority), got %v", o["protocol"])
			}
		}
		if tag == "block" {
			foundBlock = true
			if o["protocol"] != "dns" {
				t.Errorf("expected 'block' protocol to be 'dns' (static config priority), got %v", o["protocol"])
			}
		}
	}

	if !foundDirect || !foundBlock {
		t.Errorf("missing outbounds: direct=%v, block=%v", foundDirect, foundBlock)
	}
}

func TestBuildConfig_AllProtocols_ValidJSON(t *testing.T) {
	protocols := []struct {
		name string
		nc   panel.NodeConfig
	}{
		{
			name: "vmess",
			nc: panel.NodeConfig{
				Protocol:   "vmess",
				ServerPort: 10086,
				Network:    "ws",
				TLS:        1,
				NetworkSettings: map[string]interface{}{
					"path": "/vmess",
					"host": "example.com",
				},
			},
		},
		{
			name: "vless",
			nc: panel.NodeConfig{
				Protocol:   "vless",
				ServerPort: 443,
				Network:    "tcp",
				TLS:        2,
				Flow:       "xtls-rprx-vision",
				TLSSettings: map[string]interface{}{
					"private_key": "test-pk",
					"short_id":    "abcd",
					"server_name": "www.example.com",
					"dest":        "www.example.com:443",
				},
			},
		},
		{
			name: "trojan",
			nc: panel.NodeConfig{
				Protocol:   "trojan",
				ServerPort: 443,
				Network:    "grpc",
				TLS:        1,
				ServerName: "example.com",
				NetworkSettings: map[string]interface{}{
					"service_name": "trojan-grpc",
				},
			},
		},
		{
			name: "shadowsocks-aes",
			nc: panel.NodeConfig{
				Protocol:   "shadowsocks",
				ServerPort: 8388,
				Cipher:     "aes-128-gcm",
			},
		},
		{
			name: "shadowsocks-2022",
			nc: panel.NodeConfig{
				Protocol:   "shadowsocks",
				ServerPort: 8388,
				Cipher:     "2022-blake3-aes-128-gcm",
				ServerKey:  "test-server-key",
			},
		},
		{
			name: "socks",
			nc: panel.NodeConfig{
				Protocol:   "socks",
				ServerPort: 1080,
			},
		},
		{
			name: "http",
			nc: panel.NodeConfig{
				Protocol:   "http",
				ServerPort: 8080,
			},
		},
	}

	for _, tc := range protocols {
		t.Run(tc.name, func(t *testing.T) {
			cfg := buildConfig(testKernelCfg, testNodeSpec(&tc.nc), testUsers, kernel.TLSCert{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")})

			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}

			var parsed map[string]interface{}
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}

			// Check required top-level fields
			for _, key := range []string{"log", "stats", "policy", "outbounds", "routing"} {
				if _, ok := parsed[key]; !ok {
					t.Errorf("missing top-level key: %s", key)
				}
			}

			if _, ok := parsed["inbounds"]; !ok {
				t.Error("missing inbounds")
			}

			t.Logf("config size: %d bytes", len(data))
		})
	}
}

func TestBuildConfig_VMess_Users(t *testing.T) {
	nc := panel.NodeConfig{
		Protocol:   "vmess",
		ServerPort: 10086,
	}
	cfg := buildConfig(testKernelCfg, testNodeSpec(&nc), testUsers, kernel.TLSCert{})
	data, _ := json.Marshal(cfg)

	var parsed map[string]interface{}
	json.Unmarshal(data, &parsed)

	inbounds := parsed["inbounds"].([]interface{})
	ib := inbounds[0].(map[string]interface{})

	if ib["protocol"] != "vmess" {
		t.Errorf("expected protocol vmess, got %v", ib["protocol"])
	}

	settings := ib["settings"].(map[string]interface{})
	clients := settings["clients"].([]interface{})

	if len(clients) != 2 {
		t.Fatalf("expected 2 clients, got %d", len(clients))
	}

	c1 := clients[0].(map[string]interface{})
	if c1["email"] != "user@1" {
		t.Errorf("expected email user@1, got %v", c1["email"])
	}
	if c1["id"] != "279d4f89-3a2c-488d-a67c-2d39a72acdde" {
		t.Errorf("unexpected UUID: %v", c1["id"])
	}
}

func TestBuildConfig_VLESS_Flow(t *testing.T) {
	nc := panel.NodeConfig{
		Protocol:   "vless",
		ServerPort: 443,
		Flow:       "xtls-rprx-vision",
		TLS:        2,
		TLSSettings: map[string]interface{}{
			"private_key": "pk",
			"server_name": "example.com",
		},
	}
	cfg := buildConfig(testKernelCfg, testNodeSpec(&nc), testUsers, kernel.TLSCert{})
	data, _ := json.Marshal(cfg)

	var parsed map[string]interface{}
	json.Unmarshal(data, &parsed)

	inbounds := parsed["inbounds"].([]interface{})
	ib := inbounds[0].(map[string]interface{})
	settings := ib["settings"].(map[string]interface{})
	clients := settings["clients"].([]interface{})
	c1 := clients[0].(map[string]interface{})

	if c1["flow"] != "xtls-rprx-vision" {
		t.Errorf("expected flow xtls-rprx-vision, got %v", c1["flow"])
	}

	ss := ib["streamSettings"].(map[string]interface{})
	if ss["security"] != "reality" {
		t.Errorf("expected security reality, got %v", ss["security"])
	}
}

func TestBuildRouting_Default(t *testing.T) {
	routing := buildRouting(nil, nil, nil)
	rules := routing["rules"].([]M)

	if len(rules) != 1 {
		t.Fatalf("expected 1 default rule, got %d", len(rules))
	}

	if rules[0]["outboundTag"] != "block" {
		t.Errorf("expected block outbound, got %v", rules[0]["outboundTag"])
	}
	ips := rules[0]["ip"].([]string)
	if len(ips) < 5 {
		t.Errorf("expected multiple private CIDRs, got %d", len(ips))
	}
}

func TestBuildRouting_WithRules(t *testing.T) {
	rules := []panel.RouteRule{
		{
			ID:     1,
			Match:  []string{"*.baidu.com", "*.qq.com", "10.0.0.0/8"},
			Action: "block",
		},
		{
			ID:     2,
			Match:  []string{"*.google.com"},
			Action: "direct",
		},
	}

	routing := buildRouting(testRouteRules(rules), nil, nil)
	xrayRules := routing["rules"].([]M)

	// 1 default + 2 domain rules + 1 IP rule = 4
	if len(xrayRules) != 4 {
		t.Fatalf("expected 4 rules, got %d", len(xrayRules))
	}

	// Rule 1: domains block
	r1 := xrayRules[1]
	domains := r1["domain"].([]string)
	if len(domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(domains))
	}
	if domains[0] != "domain:baidu.com" || domains[1] != "domain:qq.com" {
		t.Errorf("unexpected domains: %v", domains)
	}
	if r1["outboundTag"] != "block" {
		t.Errorf("expected block, got %v", r1["outboundTag"])
	}

	// Rule 2: IP block
	r2 := xrayRules[2]
	ips := r2["ip"].([]string)
	if len(ips) != 1 || ips[0] != "10.0.0.0/8" {
		t.Errorf("unexpected IPs: %v", ips)
	}

	// Rule 3: direct
	r3 := xrayRules[3]
	if r3["outboundTag"] != "direct" {
		t.Errorf("expected direct, got %v", r3["outboundTag"])
	}
}

func TestBuildRouting_WithCustomRouteRules(t *testing.T) {
	customRules := []model.CustomRouteRule{
		{
			Name: "proxy-web",
			Match: model.RouteMatch{
				Domains:        []string{"full.example.com"},
				DomainSuffixes: []string{"example.org"},
				Ports:          []string{"80", "443-445"},
				Networks:       []string{"tcp", "udp"},
				SourceCIDRs:    []string{"192.168.1.0/24"},
				SourcePorts:    []string{"1000-1002"},
			},
			Action: model.RouteAction{Type: "route", Target: "warp-jp"},
		},
	}

	routing := buildRouting(nil, customRules, nil)
	xrayRules := routing["rules"].([]M)
	if len(xrayRules) != 6 {
		t.Fatalf("expected 6 rules, got %d", len(xrayRules))
	}
	if xrayRules[0]["outboundTag"] != "warp-jp" {
		t.Fatalf("expected first custom outbound warp-jp, got %v", xrayRules[0]["outboundTag"])
	}
	if got := xrayRules[0]["domain"].([]string); len(got) != 2 || got[0] != "full.example.com" || got[1] != "domain:example.org" {
		t.Fatalf("unexpected custom domains: %v", got)
	}
	if got := xrayRules[1]["port"]; got != "80,443-445" {
		t.Fatalf("unexpected port matcher: %v", got)
	}
	if got := xrayRules[2]["network"]; got != "tcp,udp" {
		t.Fatalf("unexpected network matcher: %v", got)
	}
	if got := xrayRules[3]["source"].([]string); len(got) != 1 || got[0] != "192.168.1.0/24" {
		t.Fatalf("unexpected source cidr matcher: %v", got)
	}
	if got := xrayRules[4]["sourcePort"]; got != "1000-1002" {
		t.Fatalf("unexpected source port matcher: %v", got)
	}
}

func TestBuildRouting_StructuredCustomRulesRemainFirst(t *testing.T) {
	raw := []map[string]any{{"type": "field", "domain": []string{"keyword:raw"}, "outboundTag": "raw-tag"}}
	custom := []model.CustomRouteRule{{
		Match:  model.RouteMatch{DomainSuffixes: []string{"structured.example"}},
		Action: model.RouteAction{Type: "direct"},
	}}
	routing := buildRouting(nil, custom, raw)
	xrayRules := routing["rules"].([]M)
	if xrayRules[0]["outboundTag"] != "direct" {
		t.Fatalf("expected structured rule first, got %v", xrayRules[0]["outboundTag"])
	}
	if xrayRules[1]["outboundTag"] != "raw-tag" {
		t.Fatalf("expected raw custom rule second, got %v", xrayRules[1]["outboundTag"])
	}
}

func TestBuildConfig_LogLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"debug", "debug"},
		{"info", "info"},
		{"warn", "warning"},
		{"error", "error"},
		{"", "warning"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := xrayLogLevel(tc.input)
			if result != tc.expected {
				t.Errorf("xrayLogLevel(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestBuildConfig_StatsEnabled(t *testing.T) {
	nc := panel.NodeConfig{
		Protocol:   "vmess",
		ServerPort: 10086,
	}
	cfg := buildConfig(testKernelCfg, testNodeSpec(&nc), testUsers, kernel.TLSCert{})
	data, _ := json.Marshal(cfg)

	var parsed map[string]interface{}
	json.Unmarshal(data, &parsed)

	// Verify stats is enabled
	if _, ok := parsed["stats"]; !ok {
		t.Error("stats not enabled")
	}

	// Verify policy enables user stats
	policy := parsed["policy"].(map[string]interface{})
	levels := policy["levels"].(map[string]interface{})
	level0 := levels["0"].(map[string]interface{})

	if v, ok := level0["statsUserUplink"]; !ok || v != true {
		t.Error("statsUserUplink not enabled")
	}
	if v, ok := level0["statsUserDownlink"]; !ok || v != true {
		t.Error("statsUserDownlink not enabled")
	}
}

func TestBuildConfig_Shadowsocks_MultiUserTraditional(t *testing.T) {
	nc := panel.NodeConfig{
		Protocol:   "shadowsocks",
		ServerPort: 8388,
		Cipher:     "aes-128-gcm",
	}
	cfg := buildConfig(testKernelCfg, testNodeSpec(&nc), testUsers, kernel.TLSCert{})
	data, _ := json.Marshal(cfg)

	var parsed map[string]interface{}
	json.Unmarshal(data, &parsed)

	inbounds := parsed["inbounds"].([]interface{})
	ib := inbounds[0].(map[string]interface{})
	settings := ib["settings"].(map[string]interface{})

	if settings["method"] != "aes-128-gcm" {
		t.Errorf("expected method aes-128-gcm, got %v", settings["method"])
	}
	clients := settings["clients"].([]interface{})
	if len(clients) != len(testUsers) {
		t.Fatalf("expected %d clients, got %d", len(testUsers), len(clients))
	}
	c0 := clients[0].(map[string]interface{})
	if c0["method"] != "aes-128-gcm" {
		t.Errorf("expected per-user method aes-128-gcm, got %v", c0["method"])
	}
	if c0["password"] != testUsers[0].UUID {
		t.Errorf("expected password %s, got %v", testUsers[0].UUID, c0["password"])
	}
}

func TestBuildConfig_Shadowsocks_MultiUser(t *testing.T) {
	nc := panel.NodeConfig{
		Protocol:   "shadowsocks",
		ServerPort: 8388,
		Cipher:     "2022-blake3-aes-128-gcm",
		ServerKey:  "c2VydmVyLWtleS0xMjM0NQ==",
	}
	cfg := buildConfig(testKernelCfg, testNodeSpec(&nc), testUsers, kernel.TLSCert{})
	data, _ := json.Marshal(cfg)

	var parsed map[string]interface{}
	json.Unmarshal(data, &parsed)

	inbounds := parsed["inbounds"].([]interface{})
	ib := inbounds[0].(map[string]interface{})
	settings := ib["settings"].(map[string]interface{})

	if settings["password"] != "c2VydmVyLWtleS0xMjM0NQ==" {
		t.Errorf("expected server key, got %v", settings["password"])
	}
	clients := settings["clients"].([]interface{})
	if len(clients) != 2 {
		t.Fatalf("expected 2 clients, got %d", len(clients))
	}
}

func TestBuildConfig_SocksStats(t *testing.T) {
	nc := panel.NodeConfig{
		Protocol:   "socks",
		ServerPort: 1080,
	}
	cfg := buildConfig(testKernelCfg, testNodeSpec(&nc), testUsers, kernel.TLSCert{})
	data, _ := json.Marshal(cfg)

	var parsed map[string]interface{}
	json.Unmarshal(data, &parsed)

	inbounds := parsed["inbounds"].([]interface{})
	ib := inbounds[0].(map[string]interface{})
	settings := ib["settings"].(map[string]interface{})
	accounts := settings["accounts"].([]interface{})

	if len(accounts) == 0 {
		t.Fatal("no accounts in socks config")
	}

	a1 := accounts[0].(map[string]interface{})
	if a1["email"] != "user@1" {
		t.Errorf("expected email user@1 for socks account, got %v", a1["email"])
	}
}

func TestEchPEMToBase64(t *testing.T) {
	// Valid ECH KEYS PEM
	rawBytes := []byte{0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x03, 0xCA, 0xFE, 0x00}
	pemBlock := &pem.Block{Type: "ECH KEYS", Bytes: rawBytes}
	pemStr := string(pem.EncodeToMemory(pemBlock))

	result := echPEMToBase64([]byte(pemStr))
	expected := base64.StdEncoding.EncodeToString(rawBytes)
	if result != expected {
		t.Errorf("echPEMToBase64 got %q, want %q", result, expected)
	}

	// Wrong PEM type should return empty
	wrongBlock := &pem.Block{Type: "ECH CONFIGS", Bytes: rawBytes}
	wrongPEM := string(pem.EncodeToMemory(wrongBlock))
	if got := echPEMToBase64([]byte(wrongPEM)); got != "" {
		t.Errorf("echPEMToBase64 should reject ECH CONFIGS, got %q", got)
	}

	// Invalid PEM should return empty
	if got := echPEMToBase64([]byte("-----BEGIN GARBAGE-----\nwhat\n-----END GARBAGE-----")); got != "" {
		t.Errorf("echPEMToBase64 should reject invalid PEM, got %q", got)
	}

	// Raw base64 passthrough
	raw := "AAQDQKDIAAMD"
	if got := echPEMToBase64([]byte(raw)); got != raw {
		t.Errorf("echPEMToBase64 raw passthrough: got %q, want %q", got, raw)
	}
}

func TestExtractECHServerKeys(t *testing.T) {
	rawBytes := []byte{0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x03, 0xCA, 0xFE, 0x00}
	pemBlock := &pem.Block{Type: "ECH KEYS", Bytes: rawBytes}
	pemStr := string(pem.EncodeToMemory(pemBlock))

	tests := []struct {
		name   string
		tls    map[string]interface{}
		expect string
	}{
		{"no ech", map[string]interface{}{}, ""},
		{"disabled", map[string]interface{}{"ech": map[string]interface{}{"enabled": false, "key": pemStr}}, ""},
		{"enabled with key", map[string]interface{}{"ech": map[string]interface{}{"enabled": true, "key": pemStr}}, base64.StdEncoding.EncodeToString(rawBytes)},
		{"enabled no key", map[string]interface{}{"ech": map[string]interface{}{"enabled": true}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractECHServerKeys(tt.tls)
			if got != tt.expect {
				t.Errorf("got %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestNormalizeSS2022Key(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		keySize int
		want    string // empty means expect same as raw
	}{
		{"valid base64 16 bytes", "c2VydmVyLWtleS0xMjM0NQ==", 16, ""},
		{"valid base64 32 bytes", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", 32, ""},
		{"raw string 16 bytes", "server-key-12345", 16, "c2VydmVyLWtleS0xMjM0NQ=="},
		{"short raw", "short", 16, "c2hvcnQAAAAAAAAAAAAAAA=="},
		{"empty string", "", 16, ""},
		{"hex key 16 bytes", "7365727665722d6b65792d3132333435", 16, "c2VydmVyLWtleS0xMjM0NQ=="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeSS2022Key(tt.raw, tt.keySize)
			expected := tt.want
			if expected == "" {
				expected = tt.raw
			}
			if got != expected {
				t.Errorf("normalizeSS2022Key(%q, %d) = %q, want %q", tt.raw, tt.keySize, got, expected)
			}
			// Verify result is valid base64 that decodes to correct length
			if got != "" {
				decoded, err := base64.StdEncoding.DecodeString(got)
				if err != nil {
					t.Errorf("result %q is not valid base64: %v", got, err)
				}
				if len(decoded) != tt.keySize {
					t.Errorf("decoded length = %d, want %d", len(decoded), tt.keySize)
				}
			}
		})
	}
}
