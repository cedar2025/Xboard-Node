package model

import (
	"fmt"
	"strings"

	"github.com/cedar2025/xboard-node/internal/config"
)

// ValidateNodeSpec performs the full validation of a node against one specific
// kernel: structural checks plus everything that depends on the kernel type
// (custom outbound protocols, route matchers, transport support).
//
// Use it once the kernel for a target is known (see SelectKernel). Control
// planes that normalise panel snapshots before a kernel has been chosen must
// call ValidateNodeSpecShape instead, otherwise a legal target that needs the
// other kernel would be rejected by the previous one before it ever reaches
// the apply pipeline.
func ValidateNodeSpec(n *NodeSpec, kcfg config.KernelConfig) error {
	if n == nil {
		return nil
	}

	effectiveKernelType := strings.TrimSpace(kcfg.Type)
	if effectiveKernelType == "" {
		effectiveKernelType = strings.TrimSpace(n.KernelType)
	}
	kernelType, err := normalizeKernelType(effectiveKernelType)
	if err != nil {
		return fmt.Errorf("normalize kernel type: %w", err)
	}

	additionalOutboundSources, err := collectAdditionalOutboundTagSources(kcfg.CustomConfig, kcfg.CustomOutbound)
	if err != nil {
		return fmt.Errorf("collect additional outbound tags: %w", err)
	}
	if err := validateOutboundTagCollisions(n.CustomOutbounds, additionalOutboundSources); err != nil {
		return fmt.Errorf("validate outbound tags: %w", err)
	}
	additionalTags := additionalTagNames(additionalOutboundSources)
	availableTags := buildAvailableOutboundTags(n.CustomOutbounds, additionalTags)
	if err := ValidateCustomOutboundsForKernel(n.CustomOutbounds, kernelType, additionalTags); err != nil {
		return fmt.Errorf("validate custom outbounds: %w", err)
	}
	if err := ValidateCustomRouteRules(n.CustomRouteRules, kernelType, availableTags); err != nil {
		return fmt.Errorf("validate custom route rules: %w", err)
	}
	if err := validateTransportKernel(n.Network, kernelType); err != nil {
		return err
	}
	return nil
}

// ValidateNodeSpecShape performs the kernel-independent checks of a node
// snapshot: required fields, port range, custom outbound / route structure and
// tag references, and outbound protocols that no kernel in this build knows.
// Kernel-specific compatibility is decided later by SelectKernel.
func ValidateNodeSpecShape(n *NodeSpec, kcfg config.KernelConfig) error {
	if n == nil {
		return nil
	}
	if strings.TrimSpace(n.Protocol) == "" {
		return fmt.Errorf("protocol is required")
	}
	if n.ServerPort <= 0 || n.ServerPort > 65535 {
		return fmt.Errorf("server_port %d is out of range", n.ServerPort)
	}

	additionalOutboundSources, err := collectAdditionalOutboundTagSources(kcfg.CustomConfig, kcfg.CustomOutbound)
	if err != nil {
		return fmt.Errorf("collect additional outbound tags: %w", err)
	}
	if err := validateOutboundTagCollisions(n.CustomOutbounds, additionalOutboundSources); err != nil {
		return fmt.Errorf("validate outbound tags: %w", err)
	}
	additionalTags := additionalTagNames(additionalOutboundSources)
	availableTags := buildAvailableOutboundTags(n.CustomOutbounds, additionalTags)
	if err := ValidateCustomOutboundsForKernel(n.CustomOutbounds, "", additionalTags); err != nil {
		return fmt.Errorf("validate custom outbounds: %w", err)
	}
	for i, outbound := range n.CustomOutbounds {
		if !anyKernelSupportsOutbound(outbound.Protocol) {
			return fmt.Errorf("validate custom outbounds: custom_outbounds[%d].protocol %q is not supported by any kernel", i, outbound.Protocol)
		}
	}
	if err := ValidateCustomRouteRules(n.CustomRouteRules, "", availableTags); err != nil {
		return fmt.Errorf("validate custom route rules: %w", err)
	}
	return nil
}

func anyKernelSupportsOutbound(protocol string) bool {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	for _, support := range OutboundSupportMatrix() {
		for _, candidate := range support.Protocols {
			if strings.ToLower(candidate) == protocol {
				return true
			}
		}
	}
	return false
}

// singboxUnsupportedTransports lists transport types that sing-box does not support.
var singboxUnsupportedTransports = map[string]bool{
	"xhttp":     true,
	"splithttp": true,
}

func validateTransportKernel(network, kernelType string) error {
	net := strings.ToLower(strings.TrimSpace(network))
	if kernelType == "singbox" && singboxUnsupportedTransports[net] {
		return fmt.Errorf("transport %q is not supported by sing-box kernel; use xray kernel instead", net)
	}
	return nil
}

// ResolveKernelForTransport returns the kernel type required by the given
// transport. If the configured kernel cannot handle the transport, it returns
// the kernel that can. Otherwise it returns configuredKernel unchanged.
//
// Deprecated: SelectKernel evaluates the whole target (protocol, version,
// transport, TLS, custom config) and is what the service uses. This helper is
// kept for callers that only know the transport.
func ResolveKernelForTransport(network, configuredKernel string) string {
	net := strings.ToLower(strings.TrimSpace(network))
	if configuredKernel == "singbox" && singboxUnsupportedTransports[net] {
		return "xray"
	}
	return configuredKernel
}

func normalizeKernelType(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "singbox", "sing-box":
		return "singbox", nil
	case "xray":
		return "xray", nil
	default:
		return "", fmt.Errorf("unsupported kernel type %q", value)
	}
}

func buildAvailableOutboundTags(structured []OutboundConfig, rawTags []string) map[string]struct{} {
	available := map[string]struct{}{
		"direct": {},
		"block":  {},
	}
	for _, outbound := range structured {
		tag := strings.ToLower(strings.TrimSpace(outbound.Tag))
		if tag != "" {
			available[tag] = struct{}{}
		}
	}
	for _, tag := range rawTags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag != "" {
			available[tag] = struct{}{}
		}
	}
	return available
}
