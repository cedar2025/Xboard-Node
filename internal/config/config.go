package config

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/cedar2025/xboard-node/internal/nlog"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

type Config struct {
	InstanceID string `yaml:"-"`
	Panel   PanelConfig   `yaml:"panel"`
	Node    NodeConfig    `yaml:"node"`
	Kernel  KernelConfig  `yaml:"kernel"`
	Cert    CertConfig    `yaml:"cert"`
	Log     LogConfig     `yaml:"log"`
	Runtime RuntimeConfig `yaml:"runtime"`
	WS      WSConfig      `yaml:"ws"`
	// Standalone enables a local-only node that never contacts the panel.
	Standalone *StandaloneConfig `yaml:"standalone,omitempty"`
	// HealthPort enables a lightweight HTTP health-check endpoint on the
	// given port (e.g. 65530). 0 = disabled (default).
	HealthPort int `yaml:"health_port"`
	// Nodes enables multi-node mode. When set, Panel.NodeID is ignored and
	// one service instance is started per entry. All entries share the same
	// panel URL/token, log settings and runtime tuning.
	Nodes []NodeEntry `yaml:"nodes,omitempty"`

	// Machine enables machine mode: a single process manages all nodes
	// bound to this machine on the panel. Nodes are discovered dynamically
	// via GET /api/v2/server/machine/nodes. When set, Panel.NodeID, Nodes
	// and Panel.Token are ignored; the machine token is used instead.
	Machine *MachineConfig `yaml:"machine,omitempty"`
}

// MachineConfig identifies this process as a panel-managed machine that
// dynamically discovers and runs all nodes bound to it.
type MachineConfig struct {
	MachineID int    `yaml:"machine_id"`
	Token     string `yaml:"token"`
	TokenEnv  string `yaml:"token_env,omitempty"`
}

// NodeEntry describes a single node in multi-node mode.
type NodeEntry struct {
	NodeID   int    `yaml:"node_id"`
	NodeType string `yaml:"node_type,omitempty"`
	// Kernel allows per-node overrides (e.g. config_dir). nil = inherit global.
	Kernel *KernelOverride `yaml:"kernel,omitempty"`
	// Cert allows per-node certificate overrides. nil = inherit global.
	Cert *CertConfig `yaml:"cert,omitempty"`
}

// KernelOverride holds the subset of KernelConfig that is useful to override
// per-node. Only non-zero fields replace the global value.
type KernelOverride struct {
	ConfigDir    string `yaml:"config_dir,omitempty"`
	GeoDataDir   string `yaml:"geo_data_dir,omitempty"`
	LogLevel     string `yaml:"log_level,omitempty"`
	CustomConfig string `yaml:"custom_config,omitempty"`
}

// RuntimeConfig tunes Go runtime memory behaviour.
// These knobs let operators trade CPU against memory on constrained machines
// without recompiling.
//
// Example (config.yml):
//
//	runtime:
//	  gomemlimit: "30MiB"   # soft RSS cap; GC becomes more aggressive above this
//	  gogc: 50              # halve GC target → lower peak RSS, slightly more CPU
type RuntimeConfig struct {
	// GoMemLimit is a human-readable soft memory limit passed to runtime/debug.SetMemoryLimit.
	// Valid suffixes: B, KiB, MiB, GiB, TiB.  Empty = no limit (default).
	// Recommended starting point: set to ~80% of the machine's available RAM.
	GoMemLimit string `yaml:"gomemlimit"`

	// GoGCPercent overrides GOGC (default 100).
	// Lower values (e.g. 50) trigger GC more often → lower memory, slightly higher CPU.
	// 0 means "use the default (100)".
	GoGCPercent int `yaml:"gogc"`
}

type PanelConfig struct {
	URL       string `yaml:"url"`
	Token     string `yaml:"token"`
	TokenEnv  string `yaml:"token_env,omitempty"`
	NodeID    int    `yaml:"node_id"`
	NodeType  string `yaml:"node_type"`
	MachineID int    `yaml:"-"`
}

type NodeConfig struct {
	PushInterval         int `yaml:"push_interval"`
	PullInterval         int `yaml:"pull_interval"`
	TrackInterval        int `yaml:"track_interval"`         // sec, default 10
	DeviceReportInterval int `yaml:"device_report_interval"` // sec, default 30
}

// WSConfig holds WebSocket client tuning options.
type WSConfig struct {
	StatusInterval    int `yaml:"status_interval"`    // node.status interval (sec), default 10
	HandshakeTimeout  int `yaml:"handshake_timeout"`  // WS handshake timeout (sec), default 15
	BackoffInitial    int `yaml:"backoff_initial"`    // initial reconnect delay (sec), default 1
	BackoffMax        int `yaml:"backoff_max"`        // max reconnect delay (sec), default 60
	DiscoveryInterval int `yaml:"discovery_interval"` // WS discovery interval (sec), default 300
}

type KernelConfig struct {
	Type      string `yaml:"-"` // resolved at runtime from protocol (xray or singbox)
	ConfigDir string `yaml:"config_dir"`
	LogLevel  string `yaml:"log_level"`

	// GeoDataDir is the directory that contains GeoIP/GeoSite database files.
	// For sing-box: geoip.db and geosite.db (geoip2-format).
	// For xray:     geoip.dat and geosite.dat.
	// Defaults to config_dir when empty. You only need to set this if your
	// geo database files live somewhere other than config_dir.
	GeoDataDir string `yaml:"geo_data_dir"`

	// CustomOutbound adds outbound entries to the generated kernel config.
	// Each item is a raw kernel-native outbound object (sing-box or xray format).
	CustomOutbound []map[string]any `yaml:"custom_outbound"`

	// CustomRoute adds route rules to the generated kernel config.
	// Each item is a raw kernel-native route rule object.
	CustomRoute []map[string]any `yaml:"custom_route"`

	// CustomConfig is the path to a kernel-native config file (JSON or YAML)
	// that is deep-merged into the auto-generated config. This enables full
	// customization of dns, outbounds, endpoints, route, experimental, etc.
	// Compatible with V2bX OriginalPath format.
	CustomConfig string `yaml:"custom_config"`
}

type CertConfig struct {
	AutoTLS  bool   `yaml:"auto_tls"`
	Domain   string `yaml:"domain"`
	Email    string `yaml:"email"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CertDir  string `yaml:"cert_dir"`
	HTTPPort int    `yaml:"http_port"` // port for HTTP-01 challenge (default: 80)

	// CertMode selects the TLS certificate strategy:
	//   ""       - auto-detect: if CertFile is set → file; if AutoTLS → http; else none
	//   "http"   - ACME HTTP-01 challenge (requires port 80)
	//   "dns"    - ACME DNS-01 challenge (requires DNSProvider + DNSEnv)
	//   "self"   - generate a self-signed certificate (valid 10 years)
	//   "file"   - use manually provided CertFile/KeyFile paths
	//   "content"- cert/key PEM provided directly in CertContent/KeyContent
	//   "none"   - no TLS
	CertMode string `yaml:"cert_mode"`

	// DNSProvider specifies the DNS provider for DNS-01 challenge.
	// Supported: "cloudflare", "alidns"
	DNSProvider string `yaml:"dns_provider"`

	// DNSEnv passes credentials to the DNS provider as key=value pairs.
	// Example for cloudflare: {"CF_API_TOKEN": "xxxx"}
	DNSEnv map[string]string `yaml:"dns_env"`

	// CertContent / KeyContent hold PEM-encoded certificate and private key.
	// Used when CertMode == "content" (e.g. panel pushes a cert directly).
	// The values are written to CertDir and then referenced as files by the kernel.
	CertContent string `yaml:"cert_content,omitempty"`
	KeyContent  string `yaml:"key_content,omitempty"`
}

type LogConfig struct {
	Level  string `yaml:"level"`
	Output string `yaml:"output"`
}

type RootConfig struct {
	Instances []Config `yaml:"instances,omitempty"`
	Config    `yaml:",inline"`
}

func LoadRoot(path string) (*RootConfig, error) {
	rc := &RootConfig{}

	data, err := os.ReadFile(path)
	if err == nil {
		if err := yaml.Unmarshal(data, rc); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
		if len(rc.Instances) == 0 {
			legacy := &Config{}
			if err := yaml.Unmarshal(data, legacy); err != nil {
				return nil, fmt.Errorf("parse legacy config: %w", err)
			}
			rc.Config = *legacy
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	// In multi-instance mode, top-level settings (log, kernel, node, ws, etc.)
	// serve as defaults that each instance inherits. Instance-level settings
	// take precedence over top-level ones.
	if len(rc.Instances) > 0 {
		for i := range rc.Instances {
			rc.Instances[i].inheritFrom(&rc.Config)
		}
	}

	// Derive default base directory from the config file's location so that
	// data (certs, sing-box cache, …) lives next to the config file when
	// config_dir is not explicitly set. This makes non-root / dev deployments
	// work without any extra configuration.
	baseDir := configBaseDir(path)

	rc.applyEnvOverrides()
	rc.resolveEnvRefs()

	// Compute stable instance IDs early — they're content-based (derived from
	// panel URL + machine/node ID), so reordering instances in the YAML doesn't
	// cause data-directory mix-ups. Must run before setDefaultsFrom which uses
	// InstanceID to derive per-instance config_dir.
	if err := rc.assignInstanceIDs(); err != nil {
		return nil, err
	}

	rc.setDefaultsFrom(baseDir)

	if err := rc.validateRoot(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return rc, nil
}

func (rc *RootConfig) applyEnvOverrides() {
	if len(rc.Instances) == 0 {
		rc.Config.applyEnvOverrides()
		return
	}
	for i := range rc.Instances {
		rc.Instances[i].applyEnvOverrides()
	}
}

func (rc *RootConfig) resolveEnvRefs() {
	if len(rc.Instances) == 0 {
		rc.Config.resolveEnvRefs()
		return
	}
	for i := range rc.Instances {
		rc.Instances[i].resolveEnvRefs()
	}
}

func (rc *RootConfig) setDefaultsFrom(baseDir string) {
	if len(rc.Instances) == 0 {
		rc.Config.setDefaultsFrom(baseDir)
		return
	}
	for i := range rc.Instances {
		instBase := baseDir
		// When multiple instances share the same base dir, derive a unique
		// sub-directory per instance to avoid config_dir collisions.
		// InstanceID is always populated by assignInstanceIDs() before this runs.
		if len(rc.Instances) > 1 && rc.Instances[i].Kernel.ConfigDir == "" {
			instBase = filepath.Join(baseDir, rc.Instances[i].InstanceID)
		}
		rc.Instances[i].setDefaultsFrom(instBase)
	}
}

// assignInstanceIDs computes a stable, content-based InstanceID for each
// instance that doesn't already have one. The ID is derived from the panel URL
// and machine/node ID, so reordering instances in the YAML file doesn't cause
// data directories to swap.
func (rc *RootConfig) assignInstanceIDs() error {
	for i := range rc.Instances {
		if rc.Instances[i].InstanceID != "" {
			continue
		}
		id, err := rc.Instances[i].AutoInstanceID()
		if err != nil {
			return fmt.Errorf("instances[%d]: %w", i, err)
		}
		rc.Instances[i].InstanceID = id
	}
	return nil
}

// configBaseDir resolves the canonical base directory from the config file path.
// This directory is used as the default for config_dir when not explicitly set,
// so that data (certs, sing-box cache, …) lives next to the config file.
func configBaseDir(configPath string) string {
	abs, err := filepath.Abs(configPath)
	if err != nil {
		return "/etc/xboard-node"
	}
	return filepath.Dir(abs)
}

func (rc *RootConfig) validateRoot() error {
	if len(rc.Instances) == 0 {
		return rc.Config.validate()
	}
	seen := map[string]struct{}{}
	for i := range rc.Instances {
		// InstanceID is already computed by assignInstanceIDs().
		id := rc.Instances[i].InstanceID
		if err := rc.Instances[i].validate(); err != nil {
			return fmt.Errorf("instances[%d]: %w", i, err)
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("instances[%d]: duplicate instance id %q", i, id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func (rc *RootConfig) NormalizeInstances() ([]*Config, error) {
	if len(rc.Instances) == 0 {
		id, err := rc.Config.AutoInstanceID()
		if err != nil {
			return nil, err
		}
		rc.Config.InstanceID = id
		return []*Config{&rc.Config}, nil
	}
	out := make([]*Config, 0, len(rc.Instances))
	for i := range rc.Instances {
		cfg := rc.Instances[i]
		if cfg.InstanceID == "" {
			id, err := cfg.AutoInstanceID()
			if err != nil {
				return nil, err
			}
			cfg.InstanceID = id
		}
		out = append(out, &cfg)
	}
	return out, nil
}

// Load reads configuration from a YAML file, then applies environment variable
// overrides. If the config file does not exist, a config is built entirely from
// environment variables (useful for Docker deployment with -e flags).
func Load(path string) (*Config, error) {
	cfg := &Config{}

	data, err := os.ReadFile(path)
	if err == nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	baseDir := configBaseDir(path)

	cfg.applyEnvOverrides()
	cfg.resolveEnvRefs()
	cfg.setDefaultsFrom(baseDir)

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// envFirst returns the first non-empty value among the given env var names.
func envFirst(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

func (c *Config) applyEnvOverrides() {
	if v := envFirst("apiHost", "API_HOST"); v != "" {
		c.Panel.URL = v
	}
	if v := envFirst("apiKey", "API_KEY"); v != "" {
		c.Panel.Token = v
	}
	if v := envFirst("nodeID", "NODE_ID"); v != "" {
		if id, err := strconv.Atoi(v); err == nil {
			c.Panel.NodeID = id
		}
	}
	if v := envFirst("nodeType", "NODE_TYPE"); v != "" {
		c.Panel.NodeType = v
	}
	if v := envFirst("certFile", "CERT_FILE"); v != "" {
		c.Cert.CertFile = v
	}
	if v := envFirst("keyFile", "KEY_FILE"); v != "" {
		c.Cert.KeyFile = v
	}
	if v := envFirst("domain", "DOMAIN"); v != "" {
		c.Cert.Domain = v
		c.Cert.AutoTLS = true
	}
	if v := envFirst("logLevel", "LOG_LEVEL"); v != "" {
		c.Log.Level = v
	}
	if v := envFirst("MACHINE_ID"); v != "" {
		if id, err := strconv.Atoi(v); err == nil {
			if c.Machine == nil {
				c.Machine = &MachineConfig{}
			}
			c.Machine.MachineID = id
		}
	}
	if v := envFirst("MACHINE_TOKEN"); v != "" {
		if c.Machine == nil {
			c.Machine = &MachineConfig{}
		}
		c.Machine.Token = v
	}
}

func (c *Config) resolveEnvRefs() {
	if c.Panel.Token == "" && c.Panel.TokenEnv != "" {
		c.Panel.Token = os.Getenv(c.Panel.TokenEnv)
	}
	if c.Machine != nil && c.Machine.Token == "" && c.Machine.TokenEnv != "" {
		c.Machine.Token = os.Getenv(c.Machine.TokenEnv)
	}
}

// inheritFrom copies non-zero fields from the parent config into c when c's
// corresponding field is zero-valued. This lets top-level settings serve as
// defaults for each instance in multi-instance configs.
// Fields that must be unique per instance (config_dir, cert_dir, instance_id)
// are intentionally excluded.
func (c *Config) inheritFrom(parent *Config) {
	// Log
	if c.Log.Level == "" {
		c.Log.Level = parent.Log.Level
	}
	if c.Log.Output == "" {
		c.Log.Output = parent.Log.Output
	}
	// Node intervals
	if c.Node.PushInterval == 0 {
		c.Node.PushInterval = parent.Node.PushInterval
	}
	if c.Node.PullInterval == 0 {
		c.Node.PullInterval = parent.Node.PullInterval
	}
	if c.Node.TrackInterval == 0 {
		c.Node.TrackInterval = parent.Node.TrackInterval
	}
	if c.Node.DeviceReportInterval == 0 {
		c.Node.DeviceReportInterval = parent.Node.DeviceReportInterval
	}
	// WS
	if c.WS.StatusInterval == 0 {
		c.WS.StatusInterval = parent.WS.StatusInterval
	}
	if c.WS.HandshakeTimeout == 0 {
		c.WS.HandshakeTimeout = parent.WS.HandshakeTimeout
	}
	if c.WS.BackoffInitial == 0 {
		c.WS.BackoffInitial = parent.WS.BackoffInitial
	}
	if c.WS.BackoffMax == 0 {
		c.WS.BackoffMax = parent.WS.BackoffMax
	}
	if c.WS.DiscoveryInterval == 0 {
		c.WS.DiscoveryInterval = parent.WS.DiscoveryInterval
	}
	// Runtime
	if c.Runtime.GoGCPercent == 0 {
		c.Runtime.GoGCPercent = parent.Runtime.GoGCPercent
	}
	if c.Runtime.GoMemLimit == "" {
		c.Runtime.GoMemLimit = parent.Runtime.GoMemLimit
	}
	// Kernel (NOT config_dir — each instance needs unique dir)
	if c.Kernel.LogLevel == "" {
		c.Kernel.LogLevel = parent.Kernel.LogLevel
	}
	if c.Kernel.GeoDataDir == "" {
		c.Kernel.GeoDataDir = parent.Kernel.GeoDataDir
	}
	if c.Kernel.CustomConfig == "" {
		c.Kernel.CustomConfig = parent.Kernel.CustomConfig
	}
	if len(c.Kernel.CustomOutbound) == 0 {
		c.Kernel.CustomOutbound = parent.Kernel.CustomOutbound
	}
	if len(c.Kernel.CustomRoute) == 0 {
		c.Kernel.CustomRoute = parent.Kernel.CustomRoute
	}
	// Cert (NOT cert_dir — derived from config_dir later)
	if c.Cert.CertMode == "" {
		c.Cert.CertMode = parent.Cert.CertMode
	}
	if c.Cert.Domain == "" {
		c.Cert.Domain = parent.Cert.Domain
	}
	if c.Cert.Email == "" {
		c.Cert.Email = parent.Cert.Email
	}
	if c.Cert.CertFile == "" {
		c.Cert.CertFile = parent.Cert.CertFile
	}
	if c.Cert.KeyFile == "" {
		c.Cert.KeyFile = parent.Cert.KeyFile
	}
	if c.Cert.DNSProvider == "" {
		c.Cert.DNSProvider = parent.Cert.DNSProvider
	}
	if len(c.Cert.DNSEnv) == 0 {
		c.Cert.DNSEnv = parent.Cert.DNSEnv
	}
	if c.Cert.HTTPPort == 0 {
		c.Cert.HTTPPort = parent.Cert.HTTPPort
	}
	if c.Cert.CertContent == "" {
		c.Cert.CertContent = parent.Cert.CertContent
	}
	if c.Cert.KeyContent == "" {
		c.Cert.KeyContent = parent.Cert.KeyContent
	}
	// Only inherit AutoTLS when the child has no explicit cert configuration.
	// A child with cert_mode, cert_file, or cert_content explicitly chooses
	// its own cert strategy — inheriting auto_tls would override that choice.
	childHasCertConfig := c.Cert.CertMode != "" || c.Cert.CertFile != "" || c.Cert.CertContent != ""
	if !childHasCertConfig && !c.Cert.AutoTLS && parent.Cert.AutoTLS {
		c.Cert.AutoTLS = parent.Cert.AutoTLS
	}
}

func (c *Config) setDefaultsFrom(baseDir string) {
	if c.Kernel.ConfigDir == "" {
		c.Kernel.ConfigDir = baseDir
	}
	if c.Kernel.GeoDataDir == "" {
		c.Kernel.GeoDataDir = c.Kernel.ConfigDir
	}
	if c.Kernel.LogLevel == "" {
		c.Kernel.LogLevel = "warn"
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Output == "" {
		c.Log.Output = "stdout"
	}
	if c.Cert.CertDir == "" {
		c.Cert.CertDir = filepath.Join(c.Kernel.ConfigDir, "certs")
	}
	if c.Cert.HTTPPort == 0 {
		c.Cert.HTTPPort = 80
	}
	// WS defaults
	if c.WS.StatusInterval == 0 {
		c.WS.StatusInterval = 10
	}
	if c.WS.HandshakeTimeout == 0 {
		c.WS.HandshakeTimeout = 15
	}
	if c.WS.BackoffInitial == 0 {
		c.WS.BackoffInitial = 1
	}
	if c.WS.BackoffMax == 0 {
		c.WS.BackoffMax = 60
	}
	if c.WS.DiscoveryInterval == 0 {
		c.WS.DiscoveryInterval = 300
	}
	// Node defaults
	if c.Node.TrackInterval == 0 {
		c.Node.TrackInterval = 10
	}
	if c.Node.DeviceReportInterval == 0 {
		c.Node.DeviceReportInterval = 30
	}
}

func (c *Config) IsMachineMode() bool {
	return c.Machine != nil && c.Machine.MachineID > 0
}

func (c *Config) AutoInstanceID() (string, error) {
	mode := "node"
	target := "0"
	baseURL := strings.TrimSpace(c.Panel.URL)
	if c.IsStandalone() {
		mode = "standalone"
		target = "local"
		baseURL = "standalone"
	} else if c.IsMachineMode() {
		mode = "machine"
		target = strconv.Itoa(c.Machine.MachineID)
	} else if len(c.Nodes) > 0 {
		// Multi-node mode: include sorted node IDs in the hash to avoid collisions.
		ids := make([]string, len(c.Nodes))
		for i, n := range c.Nodes {
			ids[i] = strconv.Itoa(n.NodeID)
		}
		sort.Strings(ids)
		target = strings.Join(ids, ",")
	} else {
		target = strconv.Itoa(c.Panel.NodeID)
	}
	normalized, slug, err := normalizeBaseURL(baseURL)
	if err != nil {
		return "", err
	}
	key := normalized + "|" + mode + "|" + target
	sum := sha1.Sum([]byte(key))
	short := hex.EncodeToString(sum[:])[:6]
	return fmt.Sprintf("%s-%s-%s-%s", slug, mode, target, short), nil
}

func normalizeBaseURL(raw string) (string, string, error) {
	if raw == "standalone" {
		return raw, raw, nil
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", fmt.Errorf("invalid panel.url %q: %w", raw, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", "", fmt.Errorf("invalid panel.url %q", raw)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.RawQuery = ""
	u.Fragment = ""
	pathPart := strings.TrimSuffix(u.EscapedPath(), "/")
	normalized := u.Scheme + "://" + u.Host
	if pathPart != "" && pathPart != "/" {
		normalized += pathPart
	}
	slugBase := u.Host
	if pathPart != "" && pathPart != "/" {
		slugBase += "-" + strings.Trim(pathPart, "/")
	}
	slugBase = strings.ToLower(slugBase)
	var b strings.Builder
	lastDash := false
	for _, r := range slugBase {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		slug = "panel"
	}
	if len(slug) > 48 {
		slug = strings.Trim(slug[:48], "-")
	}
	return normalized, slug, nil
}

func (c *Config) validate() error {
	if c.IsStandalone() {
		if err := c.validateStandalone(); err != nil {
			return err
		}
	} else if c.IsMachineMode() {
		if c.Panel.URL == "" {
			return fmt.Errorf("panel.url is required")
		}
		if c.Machine.Token == "" {
			return fmt.Errorf("machine.token is required")
		}
		if len(c.Nodes) > 0 {
			return fmt.Errorf("machine mode and nodes: are mutually exclusive")
		}
	} else {
		if c.Panel.URL == "" {
			return fmt.Errorf("panel.url is required")
		}
		if c.Panel.Token == "" {
			return fmt.Errorf("panel.token is required")
		}
		// In multi-node mode panel.node_id is optional; validate each NodeEntry instead.
		if len(c.Nodes) == 0 && c.Panel.NodeID <= 0 {
			return fmt.Errorf("panel.node_id must be positive (or use 'nodes:' for multi-node)")
		}
		for i, n := range c.Nodes {
			if n.NodeID <= 0 {
				return fmt.Errorf("nodes[%d].node_id must be positive", i)
			}
		}
	}
	if c.Cert.AutoTLS && c.Cert.Domain == "" {
		return fmt.Errorf("cert.domain is required when cert.auto_tls is enabled")
	}
	if c.Node.PushInterval < 0 {
		return fmt.Errorf("node.push_interval must not be negative")
	}
	if c.Node.PullInterval < 0 {
		return fmt.Errorf("node.pull_interval must not be negative")
	}
	return nil
}

// ExpandNodes returns one *Config per node to run.
// Single-node mode (Nodes empty): returns a slice containing the receiver.
// Multi-node mode: returns one derived *Config per NodeEntry, each inheriting
// shared settings and applying per-node overrides.
func (c *Config) ExpandNodes() []*Config {
	if len(c.Nodes) == 0 {
		return []*Config{c}
	}

	result := make([]*Config, 0, len(c.Nodes))
	for _, entry := range c.Nodes {
		nodeCfg := *c // shallow copy — safe because slices/maps are not mutated
		nodeCfg.Nodes = nil
		nodeCfg.Panel.NodeID = entry.NodeID
		nodeCfg.Panel.NodeType = entry.NodeType

		// Per-node kernel overrides
		if entry.Kernel != nil {
			if entry.Kernel.ConfigDir != "" {
				nodeCfg.Kernel.ConfigDir = entry.Kernel.ConfigDir
				if nodeCfg.Kernel.GeoDataDir == c.Kernel.ConfigDir {
					// GeoDataDir was defaulted to ConfigDir — keep it pointing at
					// the new ConfigDir unless the user set it explicitly.
					nodeCfg.Kernel.GeoDataDir = entry.Kernel.ConfigDir
				}
			}
			if entry.Kernel.GeoDataDir != "" {
				nodeCfg.Kernel.GeoDataDir = entry.Kernel.GeoDataDir
			}
			if entry.Kernel.LogLevel != "" {
				nodeCfg.Kernel.LogLevel = entry.Kernel.LogLevel
			}
			if entry.Kernel.CustomConfig != "" {
				nodeCfg.Kernel.CustomConfig = entry.Kernel.CustomConfig
			}
		} else {
			// Auto-derive a unique config_dir per node to avoid conflicts.
			nodeCfg.Kernel.ConfigDir = fmt.Sprintf("%s/node-%d", c.Kernel.ConfigDir, entry.NodeID)
			if nodeCfg.Kernel.GeoDataDir == c.Kernel.ConfigDir {
				// Share the geo data dir with the base dir to avoid re-downloading.
				nodeCfg.Kernel.GeoDataDir = c.Kernel.GeoDataDir
			}
		}

		// Per-node cert overrides
		if entry.Cert != nil {
			nodeCfg.Cert = *entry.Cert
		}
		if nodeCfg.Cert.CertDir == "" {
			nodeCfg.Cert.CertDir = filepath.Join(nodeCfg.Kernel.ConfigDir, "certs")
		}

		result = append(result, &nodeCfg)
	}
	return result
}

func (c *Config) ExpandMachineNode(nodeID int, nodeType string) *Config {
	nodeCfg := *c
	nodeCfg.Nodes = nil
	nodeCfg.Panel.NodeID = nodeID
	nodeCfg.Panel.NodeType = nodeType
	nodeCfg.Panel.Token = c.Machine.Token
	nodeCfg.Panel.MachineID = c.Machine.MachineID

	nodeCfg.Kernel.ConfigDir = fmt.Sprintf("%s/node-%d", c.Kernel.ConfigDir, nodeID)
	if nodeCfg.Kernel.GeoDataDir == c.Kernel.ConfigDir {
		nodeCfg.Kernel.GeoDataDir = c.Kernel.GeoDataDir
	}
	nodeCfg.Cert.CertDir = filepath.Join(nodeCfg.Kernel.ConfigDir, "certs")

	return &nodeCfg
}

func InitLogger(cfg LogConfig) {
	var minLevel slog.Level
	switch cfg.Level {
	case "debug":
		minLevel = slog.LevelDebug
	case "warn":
		minLevel = slog.LevelWarn
	case "error":
		minLevel = slog.LevelError
	default:
		minLevel = slog.LevelInfo
	}

	var w io.Writer
	useColor := false
	switch cfg.Output {
	case "stdout", "":
		w = os.Stdout
		useColor = term.IsTerminal(int(os.Stdout.Fd()))
	case "stderr":
		w = os.Stderr
		useColor = term.IsTerminal(int(os.Stderr.Fd()))
	default:
		dir := filepath.Dir(cfg.Output)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "failed to create log dir, falling back to stdout: %v\n", err)
			w = os.Stdout
			useColor = term.IsTerminal(int(os.Stdout.Fd()))
		} else {
			f, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to open log file, falling back to stdout: %v\n", err)
				w = os.Stdout
				useColor = term.IsTerminal(int(os.Stdout.Fd()))
			} else {
				w = f
				useColor = false
			}
		}
	}

	nlog.Init(w, minLevel, useColor)
	// Application logging goes through nlog; silence slog.Default for stray library use.
	slog.SetDefault(slog.New(slog.DiscardHandler))
}

// ValidateStartupLayout checks that multiple instances do not conflict on
// health ports, kernel config directories, or node bindings.
func ValidateStartupLayout(instances []*Config) error {
	healthPorts := make(map[int]string)
	configDirs := make(map[string]string)
	nodeBindings := make(map[string]string)
	for _, instance := range instances {
		if instance == nil {
			continue
		}
		owner := instance.InstanceID
		if instance.HealthPort > 0 {
			if other, ok := healthPorts[instance.HealthPort]; ok {
				return fmt.Errorf("health_port %d is used by both %s and %s", instance.HealthPort, other, owner)
			}
			healthPorts[instance.HealthPort] = owner
		}
		if dir := strings.TrimSpace(instance.Kernel.ConfigDir); dir != "" {
			if other, ok := configDirs[dir]; ok && other != owner {
				return fmt.Errorf("kernel config_dir %q is shared by %s and %s", dir, other, owner)
			}
			configDirs[dir] = owner
		}
		// Machine mode discovers nodes dynamically — skip static binding check,
		// but still validate custom_config if set at the instance level.
		if instance.IsMachineMode() {
			if path := strings.TrimSpace(instance.Kernel.CustomConfig); path != "" {
				if _, err := os.Stat(path); err != nil {
					return fmt.Errorf("kernel.custom_config %q for %s: %w", path, owner, err)
				}
			}
			continue
		}
		for _, node := range instance.ExpandNodes() {
			binding := fmt.Sprintf("%s/%d", strings.TrimSpace(node.Panel.URL), node.Panel.NodeID)
			if other, ok := nodeBindings[binding]; ok {
				return fmt.Errorf("node binding %s is declared by both %s and %s", binding, other, owner)
			}
			nodeBindings[binding] = owner
			if path := strings.TrimSpace(node.Kernel.CustomConfig); path != "" {
				if _, err := os.Stat(path); err != nil {
					return fmt.Errorf("kernel.custom_config %q for %s: %w", path, owner, err)
				}
			}
		}
	}
	return nil
}
