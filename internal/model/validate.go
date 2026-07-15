package model

import (
	"fmt"
	"strings"

	"github.com/cedar2025/xboard-node/internal/config"
)

// ValidateNodeSpec validates the node spec, auto-resolving the kernel type
// from the node's protocol. Custom outbound and route validation uses the
// resolved kernel type to check protocol/rule compatibility.
func ValidateNodeSpec(n *NodeSpec, kcfg config.KernelConfig) error {
	if n == nil {
		return nil
	}

	kernelType := ResolveKernelType(n.Protocol)

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
// This is used in machine mode to auto-switch kernel per node.
func ResolveKernelForTransport(network, configuredKernel string) string {
	net := strings.ToLower(strings.TrimSpace(network))
	if configuredKernel == "singbox" && singboxUnsupportedTransports[net] {
		return "xray"
	}
	return configuredKernel
}

// xraySupportedProtocols lists protocols supported by the xray kernel.
var xraySupportedProtocols = map[string]bool{
	"vmess":       true,
	"vless":       true,
	"trojan":      true,
	"shadowsocks": true,
}

// ResolveKernelForProtocol returns the kernel type that supports the given
// protocol. If the configured kernel does not support the protocol, it
// switches to the other kernel. Default preference is xray; singbox is
// used only when xray cannot handle the protocol.
func ResolveKernelForProtocol(protocol, configuredKernel string) string {
	p := strings.ToLower(strings.TrimSpace(protocol))
	if configuredKernel == "xray" && !xraySupportedProtocols[p] {
		return "singbox"
	}
	return configuredKernel
}

// ResolveKernelType returns the kernel type ("xray" or "singbox") that
// natively supports the given protocol. xray is preferred; singbox is
// returned only for protocols xray does not support.
func ResolveKernelType(protocol string) string {
	p := strings.ToLower(strings.TrimSpace(protocol))
	if xraySupportedProtocols[p] {
		return "xray"
	}
	return "singbox"
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
