package model

import "github.com/cedar2025/xboard-node/internal/config"

type NodeSpec struct {
	Protocol        string
	ListenIP        string
	ServerPort      int
	Network         string
	NetworkSettings map[string]any
	Routes          []RouteRule

	KernelType       string
	KernelLogLevel   string
	CustomOutbounds  []OutboundConfig
	CustomRoutes     []map[string]any
	CustomRouteRules []CustomRouteRule
	CertConfig       *config.CertConfig
	AutoTLS          bool
	Domain           string

	Cipher    string
	Plugin    string
	PluginOpt string
	ServerKey string

	TLS         int
	Flow        string
	Decryption  string
	TLSSettings map[string]any

	Host       string
	ServerName string

	Version      int
	UpMbps       int
	DownMbps     int
	Obfs         string
	ObfsPassword string

	CongestionControl string
	PaddingScheme     string
	Transport         string
	TrafficPattern    string

	Multiplex           *MultiplexConfig
	AcceptProxyProtocol bool
}

type OutboundConfig struct {
	Tag      string
	Protocol string
	Settings map[string]any
	ProxyTag string
}

type RouteRule struct {
	ID          int
	Match       []string
	Action      string
	ActionValue string
}

type MultiplexConfig struct {
	Enabled        bool
	Protocol       string
	MaxConnections int
	MinStreams     int
	MaxStreams     int
	Padding        bool
	Brutal         *BrutalConfig
}

type BrutalConfig struct {
	Enabled  bool
	UpMbps   int
	DownMbps int
}

type UserSpec struct {
	ID          int
	UUID        string
	SpeedLimit  int
	DeviceLimit int
}

func (n *NodeSpec) GetProxyProtocol() bool {
	if n == nil {
		return false
	}
	if n.AcceptProxyProtocol {
		return true
	}
	if n.NetworkSettings != nil {
		if v, ok := n.NetworkSettings["acceptProxyProtocol"]; ok {
			if b, ok := v.(bool); ok {
				return b
			}
		}
	}
	return false
}

func cloneAnyMap(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func cloneMapSlice(src []map[string]any) []map[string]any {
	if len(src) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(src))
	for _, item := range src {
		out = append(out, cloneAnyMap(item))
	}
	return out
}

func cloneStringSlice(src []string) []string {
	if len(src) == 0 {
		return nil
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}

// The copy helpers below differ from the clone helpers above on purpose: the
// panel/standalone translators normalise empty containers to nil, whereas a
// snapshot copy must keep the exact JSON form of its original, because the
// configuration hash is computed from that form.

// copyAnyValue deep-copies the JSON-shaped values found in settings maps.
func copyAnyValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return copyAnyMap(t)
	case []any:
		if t == nil {
			return t
		}
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = copyAnyValue(item)
		}
		return out
	default:
		return v
	}
}

func copyAnyMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = copyAnyValue(v)
	}
	return out
}

func copyMapSlice(src []map[string]any) []map[string]any {
	if src == nil {
		return nil
	}
	out := make([]map[string]any, len(src))
	for i, item := range src {
		out[i] = copyAnyMap(item)
	}
	return out
}

func copyStrings(src []string) []string {
	if src == nil {
		return nil
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}

// CloneNodeSpec returns a deep copy of spec. Config generation and state
// bookkeeping work on copies so that a builder can never rewrite the desired
// or the applied snapshot. The copy serialises exactly like the original
// (nil and empty containers are kept apart, nested values are copied), so it
// has the same configuration hash.
func CloneNodeSpec(spec *NodeSpec) *NodeSpec {
	if spec == nil {
		return nil
	}
	clone := *spec
	clone.NetworkSettings = copyAnyMap(spec.NetworkSettings)
	clone.TLSSettings = copyAnyMap(spec.TLSSettings)
	if spec.Routes != nil {
		clone.Routes = make([]RouteRule, len(spec.Routes))
		for i, route := range spec.Routes {
			clone.Routes[i] = route
			clone.Routes[i].Match = copyStrings(route.Match)
		}
	}
	if spec.CustomOutbounds != nil {
		clone.CustomOutbounds = make([]OutboundConfig, len(spec.CustomOutbounds))
		for i, outbound := range spec.CustomOutbounds {
			clone.CustomOutbounds[i] = outbound
			clone.CustomOutbounds[i].Settings = copyAnyMap(outbound.Settings)
		}
	}
	clone.CustomRoutes = copyMapSlice(spec.CustomRoutes)
	if spec.CustomRouteRules != nil {
		clone.CustomRouteRules = make([]CustomRouteRule, len(spec.CustomRouteRules))
		for i, rule := range spec.CustomRouteRules {
			clone.CustomRouteRules[i] = rule
			clone.CustomRouteRules[i].Match = RouteMatch{
				Domains:        copyStrings(rule.Match.Domains),
				DomainSuffixes: copyStrings(rule.Match.DomainSuffixes),
				IPCIDRs:        copyStrings(rule.Match.IPCIDRs),
				Ports:          copyStrings(rule.Match.Ports),
				Networks:       copyStrings(rule.Match.Networks),
				SourceCIDRs:    copyStrings(rule.Match.SourceCIDRs),
				SourcePorts:    copyStrings(rule.Match.SourcePorts),
			}
		}
	}
	if spec.CertConfig != nil {
		certCopy := *spec.CertConfig
		if spec.CertConfig.DNSEnv != nil {
			certCopy.DNSEnv = make(map[string]string, len(spec.CertConfig.DNSEnv))
			for k, v := range spec.CertConfig.DNSEnv {
				certCopy.DNSEnv[k] = v
			}
		}
		clone.CertConfig = &certCopy
	}
	if spec.Multiplex != nil {
		muxCopy := *spec.Multiplex
		if spec.Multiplex.Brutal != nil {
			brutalCopy := *spec.Multiplex.Brutal
			muxCopy.Brutal = &brutalCopy
		}
		clone.Multiplex = &muxCopy
	}
	return &clone
}

// CloneUserSpecs returns a copy of users (nil stays nil).
func CloneUserSpecs(users []UserSpec) []UserSpec {
	if users == nil {
		return nil
	}
	out := make([]UserSpec, len(users))
	copy(out, users)
	return out
}
