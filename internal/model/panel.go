package model

import (
	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/panel"
)

func NodeSpecFromPanel(nc *panel.NodeConfig) *NodeSpec {
	if nc == nil {
		return nil
	}

	var certCfg *config.CertConfig
	if nc.CertConfig != nil {
		certCfg = &config.CertConfig{
			CertMode:    nc.CertConfig.CertMode,
			Domain:      nc.CertConfig.Domain,
			Email:       nc.CertConfig.Email,
			DNSProvider: nc.CertConfig.DNSProvider,
			DNSEnv:      nc.CertConfig.DNSEnv,
			HTTPPort:    nc.CertConfig.HTTPPort,
			CertFile:    nc.CertConfig.CertFile,
			KeyFile:     nc.CertConfig.KeyFile,
			CertContent: nc.CertConfig.CertContent,
			KeyContent:  nc.CertConfig.KeyContent,
		}
	}

	var multiplex *MultiplexConfig
	if nc.Multiplex != nil {
		multiplex = &MultiplexConfig{
			Enabled:        nc.Multiplex.Enabled,
			Protocol:       nc.Multiplex.Protocol,
			MaxConnections: nc.Multiplex.MaxConnections,
			MinStreams:     nc.Multiplex.MinStreams,
			MaxStreams:     nc.Multiplex.MaxStreams,
			Padding:        nc.Multiplex.Padding,
		}
		if nc.Multiplex.Brutal != nil {
			multiplex.Brutal = &BrutalConfig{
				Enabled:  nc.Multiplex.Brutal.Enabled,
				UpMbps:   nc.Multiplex.Brutal.UpMbps,
				DownMbps: nc.Multiplex.Brutal.DownMbps,
			}
		}
	}

	routes := make([]RouteRule, 0, len(nc.Routes))
	for _, route := range nc.Routes {
		routes = append(routes, RouteRule{
			ID:          route.ID,
			Match:       route.Match,
			Action:      route.Action,
			ActionValue: route.ActionValue,
		})
	}

	outbounds := make([]OutboundConfig, 0, len(nc.CustomOutbounds))
	for _, outbound := range nc.CustomOutbounds {
		outbounds = append(outbounds, OutboundConfig{
			Tag:      outbound.Tag,
			Protocol: outbound.Protocol,
			Settings: outbound.Settings,
			ProxyTag: outbound.ProxyTag,
		})
	}

	customRouteRules := make([]CustomRouteRule, 0, len(nc.CustomRouteRules))
	for _, rule := range nc.CustomRouteRules {
		customRouteRules = append(customRouteRules, CustomRouteRule{
			Name:     rule.Name,
			Disabled: rule.Disabled,
			Match: RouteMatch{
				Domains:        rule.Match.Domains,
				DomainSuffixes: rule.Match.DomainSuffixes,
				IPCIDRs:        rule.Match.IPCIDRs,
				Ports:          rule.Match.Ports,
				Networks:       rule.Match.Networks,
				SourceCIDRs:    rule.Match.SourceCIDRs,
				SourcePorts:    rule.Match.SourcePorts,
			},
			Action: RouteAction{
				Type:   rule.Action.Type,
				Target: rule.Action.Target,
			},
		})
	}

	return &NodeSpec{
		Protocol:            nc.Protocol,
		ListenIP:            nc.ListenIP,
		ServerPort:          nc.ServerPort,
		Network:             nc.Network,
		NetworkSettings:     nc.NetworkSettings,
		Routes:              routes,
		KernelType:          nc.KernelType,
		KernelLogLevel:      nc.KernelLogLevel,
		CustomOutbounds:     outbounds,
		CustomRoutes:        nc.CustomRoutes,
		CustomRouteRules:    customRouteRules,
		CertConfig:          certCfg,
		AutoTLS:             nc.AutoTLS,
		Domain:              nc.Domain,
		Cipher:              nc.Cipher,
		Plugin:              nc.Plugin,
		PluginOpt:           nc.PluginOpt,
		ServerKey:           nc.ServerKey,
		TLS:                 nc.TLS,
		Flow:                nc.Flow,
		Decryption:          nc.Decryption,
		TLSSettings:         nc.TLSSettings,
		Host:                nc.Host,
		ServerName:          nc.ServerName,
		Version:             nc.Version,
		UpMbps:              nc.UpMbps,
		DownMbps:            nc.DownMbps,
		Obfs:                nc.Obfs,
		ObfsPassword:        nc.ObfsPassword,
		CongestionControl:   nc.CongestionControl,
		PaddingScheme:       string(nc.PaddingScheme),
		Transport:           nc.Transport,
		TrafficPattern:      nc.TrafficPattern,
		SudokuConfig:        sudokuConfigFromPanel(nc.SudokuConfig),
		TrustTunnelNetwork:              nc.TrustTunnelNetwork,
		TrustTunnelCongestionController: nc.TrustTunnelCongestionController,
		TrustTunnelCWND:                 nc.TrustTunnelCWND,
		TrustTunnelBBRProfile:           nc.TrustTunnelBBRProfile,
		Multiplex:           multiplex,
		AcceptProxyProtocol: nc.AcceptProxyProtocol,
	}
}

func NodeSpecFromPanelValidated(nc *panel.NodeConfig, kcfg config.KernelConfig) (*NodeSpec, error) {
	spec := NodeSpecFromPanel(nc)
	if err := ValidateNodeSpec(spec, kcfg); err != nil {
		return nil, err
	}
	return spec, nil
}

func sudokuConfigFromPanel(sc *panel.SudokuConfig) *SudokuConfig {
	if sc == nil {
		return nil
	}
	return &SudokuConfig{
		AEADMethod:         sc.AEADMethod,
		PaddingMin:         sc.PaddingMin,
		PaddingMax:         sc.PaddingMax,
		TableType:          sc.TableType,
		HandshakeTimeout:   sc.HandshakeTimeout,
		EnablePureDownlink: sc.EnablePureDownlink,
		CustomTable:        sc.CustomTable,
		CustomTables:       cloneStringSlice(sc.CustomTables),
		DisableHTTPMask:    sc.DisableHTTPMask,
		HTTPMaskMode:       sc.HTTPMaskMode,
		PathRoot:           sc.PathRoot,
		Fallback:           sc.Fallback,
	}
}

func UserSpecsFromPanel(users []panel.User) []UserSpec {
	if users == nil {
		return nil
	}
	out := make([]UserSpec, 0, len(users))
	for _, user := range users {
		out = append(out, UserSpec{ID: user.ID, UUID: user.UUID, SpeedLimit: user.SpeedLimit, DeviceLimit: user.DeviceLimit})
	}
	return out
}

func (n *NodeSpec) ToPanel() *panel.NodeConfig {
	if n == nil {
		return nil
	}

	var certCfg *panel.CertConfig
	if n.CertConfig != nil {
		certCfg = &panel.CertConfig{
			CertMode:    n.CertConfig.CertMode,
			Domain:      n.CertConfig.Domain,
			Email:       n.CertConfig.Email,
			DNSProvider: n.CertConfig.DNSProvider,
			DNSEnv:      n.CertConfig.DNSEnv,
			HTTPPort:    n.CertConfig.HTTPPort,
			CertFile:    n.CertConfig.CertFile,
			KeyFile:     n.CertConfig.KeyFile,
			CertContent: n.CertConfig.CertContent,
			KeyContent:  n.CertConfig.KeyContent,
		}
	}

	var multiplex *panel.MultiplexConfig
	if n.Multiplex != nil {
		multiplex = &panel.MultiplexConfig{
			Enabled:        n.Multiplex.Enabled,
			Protocol:       n.Multiplex.Protocol,
			MaxConnections: n.Multiplex.MaxConnections,
			MinStreams:     n.Multiplex.MinStreams,
			MaxStreams:     n.Multiplex.MaxStreams,
			Padding:        n.Multiplex.Padding,
		}
		if n.Multiplex.Brutal != nil {
			multiplex.Brutal = &panel.BrutalConfig{
				Enabled:  n.Multiplex.Brutal.Enabled,
				UpMbps:   n.Multiplex.Brutal.UpMbps,
				DownMbps: n.Multiplex.Brutal.DownMbps,
			}
		}
	}

	routes := make([]panel.RouteRule, 0, len(n.Routes))
	for _, route := range n.Routes {
		routes = append(routes, panel.RouteRule{
			ID:          route.ID,
			Match:       cloneStringSlice(route.Match),
			Action:      route.Action,
			ActionValue: route.ActionValue,
		})
	}

	outbounds := make([]panel.OutboundConfig, 0, len(n.CustomOutbounds))
	for _, outbound := range n.CustomOutbounds {
		outbounds = append(outbounds, panel.OutboundConfig{
			Tag:      outbound.Tag,
			Protocol: outbound.Protocol,
			Settings: cloneAnyMap(outbound.Settings),
			ProxyTag: outbound.ProxyTag,
		})
	}

	customRouteRules := make([]panel.CustomRouteRule, 0, len(n.CustomRouteRules))
	for _, rule := range n.CustomRouteRules {
		customRouteRules = append(customRouteRules, panel.CustomRouteRule{
			Name:     rule.Name,
			Disabled: rule.Disabled,
			Match: panel.RouteMatch{
				Domains:        cloneStringSlice(rule.Match.Domains),
				DomainSuffixes: cloneStringSlice(rule.Match.DomainSuffixes),
				IPCIDRs:        cloneStringSlice(rule.Match.IPCIDRs),
				Ports:          cloneStringSlice(rule.Match.Ports),
				Networks:       cloneStringSlice(rule.Match.Networks),
				SourceCIDRs:    cloneStringSlice(rule.Match.SourceCIDRs),
				SourcePorts:    cloneStringSlice(rule.Match.SourcePorts),
			},
			Action: panel.RouteAction{
				Type:   rule.Action.Type,
				Target: rule.Action.Target,
			},
		})
	}

	return &panel.NodeConfig{
		Protocol:            n.Protocol,
		ListenIP:            n.ListenIP,
		ServerPort:          n.ServerPort,
		Network:             n.Network,
		NetworkSettings:     cloneAnyMap(n.NetworkSettings),
		Routes:              routes,
		KernelType:          n.KernelType,
		KernelLogLevel:      n.KernelLogLevel,
		CustomOutbounds:     outbounds,
		CustomRoutes:        cloneMapSlice(n.CustomRoutes),
		CustomRouteRules:    customRouteRules,
		CertConfig:          certCfg,
		AutoTLS:             n.AutoTLS,
		Domain:              n.Domain,
		Cipher:              n.Cipher,
		Plugin:              n.Plugin,
		PluginOpt:           n.PluginOpt,
		ServerKey:           n.ServerKey,
		TLS:                 n.TLS,
		Flow:                n.Flow,
		Decryption:          n.Decryption,
		TLSSettings:         cloneAnyMap(n.TLSSettings),
		Host:                n.Host,
		ServerName:          n.ServerName,
		Version:             n.Version,
		UpMbps:              n.UpMbps,
		DownMbps:            n.DownMbps,
		Obfs:                n.Obfs,
		ObfsPassword:        n.ObfsPassword,
		CongestionControl:   n.CongestionControl,
		PaddingScheme:       panel.StringOrArray(n.PaddingScheme),
		Transport:           n.Transport,
		TrafficPattern:      n.TrafficPattern,
		SudokuConfig:        sudokuConfigToPanel(n.SudokuConfig),
		TrustTunnelNetwork:              n.TrustTunnelNetwork,
		TrustTunnelCongestionController: n.TrustTunnelCongestionController,
		TrustTunnelCWND:                 n.TrustTunnelCWND,
		TrustTunnelBBRProfile:           n.TrustTunnelBBRProfile,
		Multiplex:           multiplex,
		AcceptProxyProtocol: n.AcceptProxyProtocol,
	}
}

func sudokuConfigToPanel(sc *SudokuConfig) *panel.SudokuConfig {
	if sc == nil {
		return nil
	}
	return &panel.SudokuConfig{
		AEADMethod:         sc.AEADMethod,
		PaddingMin:         sc.PaddingMin,
		PaddingMax:         sc.PaddingMax,
		TableType:          sc.TableType,
		HandshakeTimeout:   sc.HandshakeTimeout,
		EnablePureDownlink: sc.EnablePureDownlink,
		CustomTable:        sc.CustomTable,
		CustomTables:       cloneStringSlice(sc.CustomTables),
		DisableHTTPMask:    sc.DisableHTTPMask,
		HTTPMaskMode:       sc.HTTPMaskMode,
		PathRoot:           sc.PathRoot,
		Fallback:           sc.Fallback,
	}
}

func UserSpecsToPanel(users []UserSpec) []panel.User {
	if users == nil {
		return nil
	}
	out := make([]panel.User, 0, len(users))
	for _, user := range users {
		out = append(out, panel.User{ID: user.ID, UUID: user.UUID, SpeedLimit: user.SpeedLimit, DeviceLimit: user.DeviceLimit})
	}
	return out
}
