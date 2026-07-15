package model

import "github.com/cedar2025/xboard-node/internal/config"

func NodeSpecFromStandalone(cfg *config.Config) *NodeSpec {
	sc := cfg.Standalone
	if sc == nil {
		return nil
	}

	routes := make([]RouteRule, 0, len(sc.Node.Routes))
	for _, route := range sc.Node.Routes {
		routes = append(routes, RouteRule{
			ID:          route.ID,
			Match:       cloneStringSlice(route.Match),
			Action:      route.Action,
			ActionValue: route.ActionValue,
		})
	}

	customRouteRules := make([]CustomRouteRule, 0, len(sc.Node.CustomRouteRules))
	for _, rule := range sc.Node.CustomRouteRules {
		customRouteRules = append(customRouteRules, CustomRouteRule{
			Name:     rule.Name,
			Disabled: rule.Disabled,
			Match: RouteMatch{
				Domains:        cloneStringSlice(rule.Match.Domains),
				DomainSuffixes: cloneStringSlice(rule.Match.DomainSuffixes),
				IPCIDRs:        cloneStringSlice(rule.Match.IPCIDRs),
				Ports:          cloneStringSlice(rule.Match.Ports),
				Networks:       cloneStringSlice(rule.Match.Networks),
				SourceCIDRs:    cloneStringSlice(rule.Match.SourceCIDRs),
				SourcePorts:    cloneStringSlice(rule.Match.SourcePorts),
			},
			Action: RouteAction{Type: rule.Action.Type, Target: rule.Action.Target},
		})
	}

	var multiplex *MultiplexConfig
	if sc.Node.Multiplex != nil {
		multiplex = &MultiplexConfig{
			Enabled:        sc.Node.Multiplex.Enabled,
			Protocol:       sc.Node.Multiplex.Protocol,
			MaxConnections: sc.Node.Multiplex.MaxConnections,
			MinStreams:     sc.Node.Multiplex.MinStreams,
			MaxStreams:     sc.Node.Multiplex.MaxStreams,
			Padding:        sc.Node.Multiplex.Padding,
		}
		if sc.Node.Multiplex.Brutal != nil {
			multiplex.Brutal = &BrutalConfig{
				Enabled:  sc.Node.Multiplex.Brutal.Enabled,
				UpMbps:   sc.Node.Multiplex.Brutal.UpMbps,
				DownMbps: sc.Node.Multiplex.Brutal.DownMbps,
			}
		}
	}

	return &NodeSpec{
		Protocol:            sc.Node.Protocol,
		ListenIP:            sc.Node.ListenIP,
		ServerPort:          sc.Node.ServerPort,
		Network:             sc.Node.Network,
		NetworkSettings:     cloneAnyMap(sc.Node.NetworkSettings),
		Routes:              routes,
		CustomRouteRules:    customRouteRules,
		KernelLogLevel:      cfg.Kernel.LogLevel,
		Cipher:              sc.Node.Cipher,
		Plugin:              sc.Node.Plugin,
		PluginOpt:           sc.Node.PluginOpt,
		ServerKey:           sc.Node.ServerKey,
		TLS:                 sc.Node.TLS,
		Flow:                sc.Node.Flow,
		Decryption:          sc.Node.Decryption,
		TLSSettings:         cloneAnyMap(sc.Node.TLSSettings),
		Host:                sc.Node.Host,
		ServerName:          sc.Node.ServerName,
		Version:             sc.Node.Version,
		UpMbps:              sc.Node.UpMbps,
		DownMbps:            sc.Node.DownMbps,
		Obfs:                sc.Node.Obfs,
		ObfsPassword:        sc.Node.ObfsPassword,
		CongestionControl:   sc.Node.CongestionControl,
		PaddingScheme:       sc.Node.PaddingScheme,
		Transport:           sc.Node.Transport,
		TrafficPattern:      sc.Node.TrafficPattern,
		Multiplex:           multiplex,
		AcceptProxyProtocol: sc.Node.AcceptProxyProtocol,
	}
}

func NodeSpecFromStandaloneValidated(cfg *config.Config) (*NodeSpec, error) {
	spec := NodeSpecFromStandalone(cfg)
	if err := ValidateNodeSpec(spec, cfg.Kernel); err != nil {
		return nil, err
	}
	return spec, nil
}

func UserSpecsFromStandalone(cfg *config.Config) []UserSpec {
	if cfg.Standalone == nil {
		return nil
	}
	users := make([]UserSpec, 0, len(cfg.Standalone.Users))
	for _, user := range cfg.Standalone.Users {
		users = append(users, UserSpec{ID: user.ID, UUID: user.UUID, SpeedLimit: user.SpeedLimit, DeviceLimit: user.DeviceLimit})
	}
	return users
}
