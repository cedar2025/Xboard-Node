package model

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/cedar2025/xboard-node/internal/config"
	"gopkg.in/yaml.v3"
)

// Kernel identifiers. They match config.KernelConfig.Type after normalisation.
const (
	KernelSingbox = "singbox"
	KernelXray    = "xray"
)

// KernelTypes lists every kernel this build can run, in the order used when a
// preferred kernel cannot serve a node and another one has to be tried.
var KernelTypes = []string{KernelSingbox, KernelXray}

// TLSRequirement classifies the certificate material a node needs.
//
// The classification is about the protocol on the wire, never about what the
// certificate manager happens to hold: a Hysteria node needs a certificate even
// when none is configured, and a plain Shadowsocks node needs none even when
// one is.
type TLSRequirement string

const (
	// TLSNotUsed means the protocol has no TLS layer in this node, so certificate
	// configuration is irrelevant and no issuance is ever started for it.
	TLSNotUsed TLSRequirement = "not_used"
	// TLSOff is a conditional-TLS protocol (vmess/vless/http/naive) that the panel
	// runs in plaintext (tls=0).
	TLSOff TLSRequirement = "off"
	// TLSRequested is a conditional-TLS protocol explicitly running with tls=1.
	// Missing certificates must not silently turn that listener into plaintext.
	TLSRequested TLSRequirement = "requested"
	// TLSRequired means the protocol cannot start without a certificate at all
	// (hysteria v1/v2, tuic, anytls, trojan without REALITY).
	TLSRequired TLSRequirement = "required"
	// TLSReality means the panel configured REALITY (tls=2); a REALITY key pair
	// replaces the certificate and no certificate is prepared.
	TLSReality TLSRequirement = "reality"
)

// NeedsCertificate reports whether certificate material is mandatory.
func (r TLSRequirement) NeedsCertificate() bool { return r == TLSRequired || r == TLSRequested }

// WantsCertificate reports whether certificate material is used when present.
func (r TLSRequirement) WantsCertificate() bool {
	return r == TLSRequired || r == TLSRequested
}

// NormalizeProtocol maps the panel's protocol spelling onto the canonical name
// used by the capability table.
func NormalizeProtocol(protocol string) string {
	p := strings.ToLower(strings.TrimSpace(protocol))
	switch p {
	case "ss":
		return "shadowsocks"
	case "hysteria2", "hy2":
		return "hysteria"
	default:
		return p
	}
}

// ResolveTLSRequirement classifies the TLS need of a node from the panel
// fields alone. It returns an error for combinations that no kernel can serve
// regardless of certificates (REALITY on a protocol that has no REALITY).
func ResolveTLSRequirement(spec *NodeSpec) (TLSRequirement, error) {
	if spec == nil {
		return "", fmt.Errorf("node spec is nil")
	}
	switch NormalizeProtocol(spec.Protocol) {
	case "hysteria", "tuic", "anytls":
		return TLSRequired, nil
	case "trojan":
		if spec.TLS == 2 {
			return TLSReality, nil
		}
		return TLSRequired, nil
	case "vless":
		switch spec.TLS {
		case 2:
			return TLSReality, nil
		case 1:
			return TLSRequested, nil
		default:
			return TLSOff, nil
		}
	case "vmess", "http", "naive":
		switch spec.TLS {
		case 2:
			return "", fmt.Errorf("protocol %q does not support reality (tls=2)", spec.Protocol)
		case 1:
			return TLSRequested, nil
		default:
			return TLSOff, nil
		}
	case "socks":
		switch spec.TLS {
		case 2:
			return "", fmt.Errorf("protocol %q does not support reality (tls=2)", spec.Protocol)
		case 1:
			// The panel exposes a tls flag for socks, but neither kernel in this
			// build terminates TLS in front of a socks inbound. Classified as
			// requested so the kernel compatibility check rejects it explicitly
			// instead of the flag being dropped.
			return TLSRequested, nil
		default:
			return TLSNotUsed, nil
		}
	case "shadowsocks", "mieru":
		return TLSNotUsed, nil
	case "":
		return "", fmt.Errorf("protocol is required")
	default:
		return "", fmt.Errorf("unknown protocol %q", spec.Protocol)
	}
}

// ValidateRealitySettings checks the REALITY fields a node must carry when the
// panel selected tls=2. It is kernel independent.
func ValidateRealitySettings(spec *NodeSpec) error {
	if spec == nil {
		return fmt.Errorf("node spec is nil")
	}
	if spec.TLSSettings == nil {
		return fmt.Errorf("reality tls requires tls_settings")
	}
	privateKey := strings.TrimSpace(stringValue(spec.TLSSettings["private_key"]))
	serverName := strings.TrimSpace(stringValue(spec.TLSSettings["server_name"]))
	dest := strings.TrimSpace(stringValue(spec.TLSSettings["dest"]))
	if privateKey == "" {
		return fmt.Errorf("reality tls requires tls_settings.private_key")
	}
	if serverName == "" && dest == "" {
		return fmt.Errorf("reality tls requires tls_settings.server_name or tls_settings.dest")
	}
	return nil
}

func stringValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// kernelProtocols is the protocol set each kernel's config builder can emit.
// It mirrors singbox.buildInbound / xray.buildInbound and must be changed with
// them.
var kernelProtocols = map[string]map[string]bool{
	KernelSingbox: {
		"vmess": true, "vless": true, "trojan": true, "shadowsocks": true,
		"hysteria": true, "tuic": true, "naive": true, "socks": true,
		"http": true, "anytls": true, "mieru": true,
	},
	KernelXray: {
		"vmess": true, "vless": true, "trojan": true, "shadowsocks": true,
		"hysteria": true, "socks": true, "http": true,
	},
}

// kernelTransports is the transport set each kernel's stream protocols
// (vmess/vless/trojan) accept. Other protocols ignore the network field.
var kernelTransports = map[string]map[string]bool{
	KernelSingbox: {
		"": true, "tcp": true, "ws": true, "grpc": true, "httpupgrade": true,
		"h2": true, "http": true, "quic": true,
	},
	KernelXray: {
		"": true, "tcp": true, "raw": true, "ws": true, "websocket": true,
		"grpc": true, "gun": true, "httpupgrade": true, "h2": true, "http": true,
		"xhttp": true, "splithttp": true, "kcp": true, "mkcp": true, "quic": true,
	},
}

var streamProtocols = map[string]bool{"vmess": true, "vless": true, "trojan": true}

// KernelCompatibility reports why kernelType cannot run spec, or nil when it
// can. Every field that changes the wire protocol is checked; a field a kernel
// would silently ignore is treated as unsupported rather than dropped.
func KernelCompatibility(kernelType string, spec *NodeSpec) error {
	kernelType, err := normalizeKernelType(kernelType)
	if err != nil {
		return err
	}
	if spec == nil {
		return fmt.Errorf("node spec is nil")
	}
	protocol := NormalizeProtocol(spec.Protocol)
	if !kernelProtocols[kernelType][protocol] {
		return fmt.Errorf("protocol %q is not supported by kernel %q", spec.Protocol, kernelType)
	}

	requirement, err := ResolveTLSRequirement(spec)
	if err != nil {
		return err
	}

	if streamProtocols[protocol] {
		network := strings.ToLower(strings.TrimSpace(spec.Network))
		if !kernelTransports[kernelType][network] {
			return fmt.Errorf("transport %q is not supported by kernel %q", spec.Network, kernelType)
		}
	}

	switch protocol {
	case "hysteria":
		switch spec.Version {
		case 1:
			if kernelType == KernelXray {
				return fmt.Errorf("hysteria v1 is not supported by kernel %q (xray runs hysteria v2 only)", kernelType)
			}
		case 2:
		default:
			return fmt.Errorf("hysteria version %d is not supported (expected 1 or 2)", spec.Version)
		}
		if strings.TrimSpace(spec.Obfs) != "" && kernelType == KernelXray {
			return fmt.Errorf("hysteria obfs %q is not supported by kernel %q", spec.Obfs, kernelType)
		}
	case "vless":
		if d := strings.ToLower(strings.TrimSpace(spec.Decryption)); d != "" && d != "none" && kernelType == KernelSingbox {
			return fmt.Errorf("vless encryption (decryption=%q) is not supported by kernel %q", spec.Decryption, kernelType)
		}
	case "shadowsocks":
		if strings.TrimSpace(spec.Plugin) != "" {
			return fmt.Errorf("shadowsocks plugin %q is not supported by kernel %q", spec.Plugin, kernelType)
		}
	case "socks":
		if requirement == TLSRequested {
			return fmt.Errorf("socks with tls=1 is not supported by kernel %q", kernelType)
		}
	}

	if requirement == TLSReality {
		if err := ValidateRealitySettings(spec); err != nil {
			return err
		}
	}

	if spec.Multiplex != nil && spec.Multiplex.Enabled {
		if kernelType != KernelSingbox {
			return fmt.Errorf("multiplex is not supported by kernel %q", kernelType)
		}
		if !streamProtocols[protocol] {
			return fmt.Errorf("multiplex is not supported for protocol %q", spec.Protocol)
		}
	}

	if spec.GetProxyProtocol() {
		if kernelType != KernelXray {
			return fmt.Errorf("accept_proxy_protocol is not supported by kernel %q", kernelType)
		}
		switch protocol {
		case "vmess", "vless", "trojan", "hysteria", "http":
		default:
			return fmt.Errorf("accept_proxy_protocol is not supported for protocol %q on kernel %q", spec.Protocol, kernelType)
		}
	}

	return nil
}

// KernelSelection is the outcome of choosing a kernel for a target node.
type KernelSelection struct {
	Kernel string
	// Reason is non-empty when the preferred kernel was not chosen.
	Reason string
	// TLS is the certificate requirement of the target.
	TLS TLSRequirement
}

// SelectKernel picks the kernel that can run spec. The preferred kernel (the
// operator's configured type) wins whenever it can serve the node; the other
// kernel is used only when the preferred one cannot. The choice depends solely
// on the target snapshot and the original configuration, never on what was
// selected for a previous target. When no kernel can run the node the error
// lists every kernel's reason.
func SelectKernel(spec *NodeSpec, preferred string, kcfg config.KernelConfig) (KernelSelection, error) {
	if spec == nil {
		return KernelSelection{}, fmt.Errorf("node spec is nil")
	}
	requirement, err := ResolveTLSRequirement(spec)
	if err != nil {
		return KernelSelection{}, err
	}
	preferredKernel, err := normalizeKernelType(preferred)
	if err != nil {
		preferredKernel = KernelSingbox
	}

	candidates := make([]string, 0, len(KernelTypes))
	candidates = append(candidates, preferredKernel)
	for _, k := range KernelTypes {
		if k != preferredKernel {
			candidates = append(candidates, k)
		}
	}

	var reasons []string
	for _, candidate := range candidates {
		if err := kernelCanRun(candidate, spec, kcfg); err != nil {
			reasons = append(reasons, fmt.Sprintf("%s: %v", candidate, err))
			continue
		}
		selection := KernelSelection{Kernel: candidate, TLS: requirement}
		if candidate != preferredKernel {
			selection.Reason = strings.Join(reasons, "; ")
		}
		return selection, nil
	}
	return KernelSelection{}, fmt.Errorf("no kernel can run protocol %q: %s", spec.Protocol, strings.Join(reasons, "; "))
}

// kernelCanRun combines the wire-level table with the structural validation of
// custom outbounds / routes and the operator's kernel-native local config.
func kernelCanRun(kernelType string, spec *NodeSpec, kcfg config.KernelConfig) error {
	if err := KernelCompatibility(kernelType, spec); err != nil {
		return err
	}
	candidateCfg := kcfg
	candidateCfg.Type = kernelType
	if err := ValidateNodeSpec(spec, candidateCfg); err != nil {
		return err
	}
	return LocalCustomConfigCompatible(kernelType, kcfg)
}

// LocalCustomConfigCompatible rejects a kernel whose native format does not
// match the operator's raw custom_outbound / custom_route entries or the
// custom_config file. Raw entries are kernel-native JSON, so a sing-box rule
// set cannot be handed to xray and vice versa. Entries that give no hint
// (empty, or a shape both kernels accept) never block a kernel.
func LocalCustomConfigCompatible(kernelType string, kcfg config.KernelConfig) error {
	kernelType, err := normalizeKernelType(kernelType)
	if err != nil {
		return err
	}
	for i, outbound := range kcfg.CustomOutbound {
		if hint := rawOutboundKernelHint(outbound); hint != "" && hint != kernelType {
			return fmt.Errorf("kernel.custom_outbound[%d] is written for kernel %q", i, hint)
		}
	}
	for i, route := range kcfg.CustomRoute {
		if hint := rawRouteKernelHint(route); hint != "" && hint != kernelType {
			return fmt.Errorf("kernel.custom_route[%d] is written for kernel %q", i, hint)
		}
	}
	hint, err := customConfigFileKernelHint(kcfg.CustomConfig)
	if err != nil {
		return err
	}
	if hint != "" && hint != kernelType {
		return fmt.Errorf("kernel.custom_config %q is written for kernel %q", kcfg.CustomConfig, hint)
	}
	return nil
}

func rawOutboundKernelHint(outbound map[string]any) string {
	_, hasType := outbound["type"]
	_, hasProtocol := outbound["protocol"]
	switch {
	case hasType && !hasProtocol:
		return KernelSingbox
	case hasProtocol && !hasType:
		return KernelXray
	default:
		return ""
	}
}

func rawRouteKernelHint(route map[string]any) string {
	_, hasOutboundTag := route["outboundTag"]
	_, hasOutbound := route["outbound"]
	switch {
	case hasOutboundTag && !hasOutbound:
		return KernelXray
	case hasOutbound && !hasOutboundTag:
		return KernelSingbox
	default:
		return ""
	}
}

// customConfigFileKernelHint inspects the top-level keys of a custom config
// file. sing-box uses "route" / "experimental" / "endpoints"; xray uses
// "routing" / "api" / "policy". Outbound entries settle ambiguous files.
func customConfigFileKernelHint(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read custom config %q: %w", path, err)
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return "", nil
	}
	decoded := map[string]any{}
	if strings.HasPrefix(trimmed, "{") {
		if err := json.Unmarshal(data, &decoded); err != nil {
			return "", fmt.Errorf("parse custom config %q: %w", path, err)
		}
	} else if err := yaml.Unmarshal(data, &decoded); err != nil {
		return "", fmt.Errorf("parse custom config %q: %w", path, err)
	}

	singboxKeys := []string{"route", "experimental", "endpoints"}
	xrayKeys := []string{"routing", "api", "policy", "transport"}
	for _, key := range singboxKeys {
		if _, ok := decoded[key]; ok {
			return KernelSingbox, nil
		}
	}
	for _, key := range xrayKeys {
		if _, ok := decoded[key]; ok {
			return KernelXray, nil
		}
	}
	if outbounds, ok := decoded["outbounds"].([]any); ok {
		for _, raw := range outbounds {
			entry, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if hint := rawOutboundKernelHint(entry); hint != "" {
				return hint, nil
			}
		}
	}
	return "", nil
}

// CapabilityRow is one line of the human-readable capability table used by
// documentation and tests.
type CapabilityRow struct {
	Protocol string
	Kernels  []string
}

// SupportedProtocols lists which kernels can emit each protocol, sorted by
// protocol name.
func SupportedProtocols() []CapabilityRow {
	set := map[string][]string{}
	for _, k := range KernelTypes {
		for protocol := range kernelProtocols[k] {
			set[protocol] = append(set[protocol], k)
		}
	}
	rows := make([]CapabilityRow, 0, len(set))
	for protocol, kernels := range set {
		sort.Strings(kernels)
		rows = append(rows, CapabilityRow{Protocol: protocol, Kernels: kernels})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Protocol < rows[j].Protocol })
	return rows
}
