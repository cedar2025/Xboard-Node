package config

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cedar2025/xboard-node/internal/nlog"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Panel   PanelConfig   `yaml:"panel"`
	Node    NodeConfig    `yaml:"node"`
	Kernel  KernelConfig  `yaml:"kernel"`
	Cert    CertConfig    `yaml:"cert"`
	Log     LogConfig     `yaml:"log"`
	Runtime RuntimeConfig `yaml:"runtime"`
	WS      WSConfig      `yaml:"ws"`
	// HealthPort enables a lightweight HTTP health-check endpoint on the
	// given port (e.g. 65530). 0 = disabled (default).
	HealthPort int `yaml:"health_port"`
	// Nodes enables multi-node mode. When set, Panel.NodeID is ignored and
	// one service instance is started per entry. All entries share the same
	// panel URL/token, kernel type, log settings and runtime tuning.
	Nodes []NodeEntry `yaml:"nodes,omitempty"`
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
	URL      string `yaml:"url"`
	Token    string `yaml:"token"`
	NodeID   int    `yaml:"node_id"`
	NodeType string `yaml:"node_type"`
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
	Type      string `yaml:"type"` // "singbox" or "xray"
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

	cfg.applyEnvOverrides()
	cfg.setDefaults()

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
		parts := strings.Split(v, ",")
		if len(parts) == 1 {
			if id, err := strconv.Atoi(strings.TrimSpace(parts[0])); err == nil {
				c.Panel.NodeID = id
			}
		} else {
			for _, p := range parts {
				if id, err := strconv.Atoi(strings.TrimSpace(p)); err == nil && id > 0 {
					c.Nodes = append(c.Nodes, NodeEntry{NodeID: id})
				}
			}
		}
	}
	if v := envFirst("nodeType", "NODE_TYPE"); v != "" {
		c.Panel.NodeType = v
	}
	if v := envFirst("kernel", "KERNEL_TYPE"); v != "" {
		c.Kernel.Type = v
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
}

func (c *Config) setDefaults() {
	if c.Kernel.Type == "" {
		c.Kernel.Type = "singbox"
	}
	if c.Kernel.ConfigDir == "" {
		c.Kernel.ConfigDir = "/etc/xboard-node"
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

func (c *Config) validate() error {
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
	switch c.Kernel.Type {
	case "singbox", "xray":
	default:
		return fmt.Errorf("kernel.type must be 'singbox' or 'xray', got '%s'", c.Kernel.Type)
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
