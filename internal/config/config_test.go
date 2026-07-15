package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_ValidConfig(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: "https://panel.example.com"
  token: "secret-token"
  node_id: 5
  node_type: "v2ray"
kernel:
  type: singbox
  log_level: warn
log:
  level: debug
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Panel.URL != "https://panel.example.com" {
		t.Errorf("url: got %q", cfg.Panel.URL)
	}
	if cfg.Panel.Token != "secret-token" {
		t.Errorf("token: got %q", cfg.Panel.Token)
	}
	if cfg.Panel.NodeID != 5 {
		t.Errorf("node_id: got %d", cfg.Panel.NodeID)
	}
	if cfg.Panel.NodeType != "v2ray" {
		t.Errorf("node_type: got %q", cfg.Panel.NodeType)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("log.level: got %q", cfg.Log.Level)
	}
}

func TestLoad_Defaults(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: "https://panel.example.com"
  token: "tok"
  node_id: 1
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// config_dir should default to the directory containing the config file.
	expectedDir := filepath.Dir(path)
	if cfg.Kernel.ConfigDir != expectedDir {
		t.Errorf("default config_dir: got %q, want %q", cfg.Kernel.ConfigDir, expectedDir)
	}
	if cfg.Kernel.LogLevel != "warn" {
		t.Errorf("default kernel log_level: got %q, want warn", cfg.Kernel.LogLevel)
	}
	if cfg.Log.Level != "info" {
		t.Errorf("default log.level: got %q, want info", cfg.Log.Level)
	}
	if cfg.Log.Output != "stdout" {
		t.Errorf("default log.output: got %q, want stdout", cfg.Log.Output)
	}
	if cfg.Cert.HTTPPort != 80 {
		t.Errorf("default http_port: got %d, want 80", cfg.Cert.HTTPPort)
	}
	expectedCertDir := filepath.Join(expectedDir, "certs")
	if cfg.Cert.CertDir != expectedCertDir {
		t.Errorf("default cert_dir: got %q, want %q", cfg.Cert.CertDir, expectedCertDir)
	}
}

func TestLoad_MissingURL(t *testing.T) {
	path := writeTemp(t, `
panel:
  token: "tok"
  node_id: 1
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing url")
	}
}

func TestLoad_MissingToken(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: "https://example.com"
  node_id: 1
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing token")
	}
}

func TestLoad_InvalidNodeID(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: "https://example.com"
  token: "tok"
  node_id: 0
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for node_id=0")
	}
}

func TestLoad_NegativeNodeID(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: "https://example.com"
  token: "tok"
  node_id: -1
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for negative node_id")
	}
}

func TestLoad_AutoTLS_NoDomain(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: "https://example.com"
  token: "tok"
  node_id: 1
cert:
  auto_tls: true
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for auto_tls without domain")
	}
}

func TestLoad_AutoTLS_WithDomain(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: "https://example.com"
  token: "tok"
  node_id: 1
cert:
  auto_tls: true
  domain: "node.example.com"
  email: "admin@example.com"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Cert.AutoTLS {
		t.Error("auto_tls should be true")
	}
	if cfg.Cert.Domain != "node.example.com" {
		t.Errorf("domain: got %q", cfg.Cert.Domain)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := writeTemp(t, "{{{{invalid yaml}}}")
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoad_CustomCert(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: "https://example.com"
  token: "tok"
  node_id: 1
cert:
  cert_file: "/custom/cert.pem"
  key_file: "/custom/key.pem"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Cert.CertFile != "/custom/cert.pem" {
		t.Errorf("cert_file: got %q", cfg.Cert.CertFile)
	}
	if cfg.Cert.KeyFile != "/custom/key.pem" {
		t.Errorf("key_file: got %q", cfg.Cert.KeyFile)
	}
}

func TestLoad_CustomIntervals(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: "https://example.com"
  token: "tok"
  node_id: 1
node:
  push_interval: 30
  pull_interval: 60
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Node.PushInterval != 30 {
		t.Errorf("push_interval: got %d", cfg.Node.PushInterval)
	}
	if cfg.Node.PullInterval != 60 {
		t.Errorf("pull_interval: got %d", cfg.Node.PullInterval)
	}
}

func TestLoad_StandaloneConfig(t *testing.T) {
	path := writeTemp(t, `
standalone:
  enabled: true
  node:
    protocol: "vless"
    server_port: 8443
    network: "ws"
    tls: 1
    network_settings:
      path: "/ws"
  users:
    - id: 1
      uuid: "11111111-1111-1111-1111-111111111111"
kernel:
  type: xray
cert:
  cert_mode: none
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.IsStandalone() {
		t.Fatal("expected standalone mode to be enabled")
	}
	if cfg.Standalone.Node.Protocol != "vless" {
		t.Errorf("standalone.node.protocol: got %q", cfg.Standalone.Node.Protocol)
	}
	if cfg.Standalone.Node.ServerPort != 8443 {
		t.Errorf("standalone.node.server_port: got %d", cfg.Standalone.Node.ServerPort)
	}
	if len(cfg.Standalone.Users) != 1 {
		t.Fatalf("standalone.users: got %d", len(cfg.Standalone.Users))
	}
	if cfg.Standalone.Users[0].UUID != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("standalone.users[0].uuid: got %q", cfg.Standalone.Users[0].UUID)
	}
}

func TestLoad_StandaloneRequiresUsers(t *testing.T) {
	path := writeTemp(t, `
standalone:
  enabled: true
  node:
    protocol: "trojan"
    server_port: 443
kernel:
  type: singbox
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for standalone mode without users")
	}
}


func TestLoadRoot_LegacyConfigNormalizesToSingleInstance(t *testing.T) {
	path := writeTemp(t, `
panel:
  url: "https://panel.example.com"
  token: "tok"
  node_id: 1
`)
	root, err := LoadRoot(path)
	if err != nil {
		t.Fatalf("LoadRoot: %v", err)
	}
	instances, err := root.NormalizeInstances()
	if err != nil {
		t.Fatalf("NormalizeInstances: %v", err)
	}
	if len(instances) != 1 {
		t.Fatalf("instances: got %d, want 1", len(instances))
	}
	if instances[0].Panel.URL != "https://panel.example.com" {
		t.Errorf("instance url: got %q", instances[0].Panel.URL)
	}
	if instances[0].InstanceID == "" {
		t.Fatal("expected auto instance id")
	}
}

func TestLoadRoot_InstancesConfig(t *testing.T) {
	path := writeTemp(t, `
instances:
  - panel:
      url: "https://panel-a.example.com"
      token_env: "PANEL_A_TOKEN"
      node_id: 1
    kernel:
      type: singbox
  - panel:
      url: "https://panel-b.example.com"
    machine:
      machine_id: 2
      token_env: "PANEL_B_MACHINE_TOKEN"
    kernel:
      type: singbox
`)
	t.Setenv("PANEL_A_TOKEN", "token-a")
	t.Setenv("PANEL_B_MACHINE_TOKEN", "token-b")
	root, err := LoadRoot(path)
	if err != nil {
		t.Fatalf("LoadRoot: %v", err)
	}
	instances, err := root.NormalizeInstances()
	if err != nil {
		t.Fatalf("NormalizeInstances: %v", err)
	}
	if len(instances) != 2 {
		t.Fatalf("instances: got %d, want 2", len(instances))
	}
	if instances[0].Panel.Token != "token-a" {
		t.Errorf("panel a token: got %q", instances[0].Panel.Token)
	}
	if instances[1].Machine == nil || instances[1].Machine.Token != "token-b" {
		t.Fatalf("machine token: got %+v", instances[1].Machine)
	}
	if instances[0].InstanceID == instances[1].InstanceID {
		t.Fatal("expected unique instance ids")
	}
}

func TestConfig_AutoInstanceIDStable(t *testing.T) {
	cfg := &Config{Panel: PanelConfig{URL: "https://Panel.Example.com/", NodeID: 1, Token: "tok"}}
	cfg.setDefaultsFrom("/etc/xboard-node")
	id1, err := cfg.AutoInstanceID()
	if err != nil {
		t.Fatalf("AutoInstanceID: %v", err)
	}
	id2, err := cfg.AutoInstanceID()
	if err != nil {
		t.Fatalf("AutoInstanceID second: %v", err)
	}
	if id1 != id2 {
		t.Fatalf("ids differ: %q vs %q", id1, id2)
	}
}

func TestLoadRoot_InheritanceFromTopLevel(t *testing.T) {
	path := writeTemp(t, `
log:
  level: "debug"
  output: "stderr"
kernel:
  type: xray
  log_level: "error"
node:
  push_interval: 42
  pull_interval: 99
instances:
  - panel:
      url: "https://panel.example.com"
      token: "tok-a"
      node_id: 1
  - panel:
      url: "https://panel.example.com"
      token: "tok-b"
      node_id: 2
    log:
      level: "warn"
`)
	root, err := LoadRoot(path)
	if err != nil {
		t.Fatalf("LoadRoot: %v", err)
	}
	if len(root.Instances) != 2 {
		t.Fatalf("instances: got %d, want 2", len(root.Instances))
	}
	// Instance 0: inherits everything from top-level.
	inst0 := root.Instances[0]
	if inst0.Log.Level != "debug" {
		t.Errorf("inst0 log.level: got %q, want %q", inst0.Log.Level, "debug")
	}
	if inst0.Log.Output != "stderr" {
		t.Errorf("inst0 log.output: got %q, want %q", inst0.Log.Output, "stderr")
	}
	if inst0.Kernel.LogLevel != "error" {
		t.Errorf("inst0 kernel.log_level: got %q, want %q", inst0.Kernel.LogLevel, "error")
	}
	if inst0.Node.PushInterval != 42 {
		t.Errorf("inst0 push_interval: got %d, want 42", inst0.Node.PushInterval)
	}
	if inst0.Node.PullInterval != 99 {
		t.Errorf("inst0 pull_interval: got %d, want 99", inst0.Node.PullInterval)
	}
	// Instance 1: overrides log.level, inherits the rest.
	inst1 := root.Instances[1]
	if inst1.Log.Level != "warn" {
		t.Errorf("inst1 log.level: got %q, want %q", inst1.Log.Level, "warn")
	}
	if inst1.Log.Output != "stderr" {
		t.Errorf("inst1 log.output: got %q, want %q", inst1.Log.Output, "stderr")
	}
}

func TestLoadRoot_InstanceOrderDoesNotAffectConfigDir(t *testing.T) {
	yamlTmpl := func(first, second int) string {
		return fmt.Sprintf(`
instances:
  - panel:
      url: "https://panel.example.com"
      token: "tok-a"
      node_id: %d
  - panel:
      url: "https://panel.example.com"
      token: "tok-b"
      node_id: %d
`, first, second)
	}

	path1 := writeTemp(t, yamlTmpl(1, 2))
	path2 := writeTemp(t, yamlTmpl(2, 1))
	root1, err := LoadRoot(path1)
	if err != nil {
		t.Fatalf("LoadRoot order1: %v", err)
	}
	root2, err := LoadRoot(path2)
	if err != nil {
		t.Fatalf("LoadRoot order2: %v", err)
	}

	// Collect the config_dir suffix (relative to base) by InstanceID.
	suffix := func(instances []Config) map[string]string {
		m := map[string]string{}
		for _, inst := range instances {
			// The config_dir ends with .../{instanceID}, extract last component.
			m[inst.InstanceID] = filepath.Base(inst.Kernel.ConfigDir)
		}
		return m
	}
	dirs1 := suffix(root1.Instances)
	dirs2 := suffix(root2.Instances)

	for id, s1 := range dirs1 {
		s2, ok := dirs2[id]
		if !ok {
			t.Fatalf("instance %q missing in reversed order", id)
		}
		if s1 != s2 {
			t.Errorf("instance %q config_dir suffix differs: %q vs %q", id, s1, s2)
		}
	}
}

func TestInheritFrom_AutoTLSNotForcedWhenChildHasCertMode(t *testing.T) {
	parent := &Config{Cert: CertConfig{AutoTLS: true, Domain: "example.com"}}
	child := &Config{Cert: CertConfig{CertMode: "file", CertFile: "/etc/cert.pem"}}
	child.inheritFrom(parent)
	if child.Cert.AutoTLS {
		t.Error("auto_tls should NOT be inherited when child has explicit cert_mode")
	}
	if child.Cert.Domain != "example.com" {
		t.Errorf("domain: got %q, want %q", child.Cert.Domain, "example.com")
	}
}

func TestInheritFrom_AutoTLSInheritedWhenChildHasNoCertConfig(t *testing.T) {
	parent := &Config{Cert: CertConfig{AutoTLS: true, Domain: "example.com"}}
	child := &Config{}
	child.inheritFrom(parent)
	if !child.Cert.AutoTLS {
		t.Error("auto_tls should be inherited when child has no cert config")
	}
}
