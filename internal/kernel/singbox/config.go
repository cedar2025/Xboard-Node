package singbox

import (
	"encoding/base64"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/cedar2025/xboard-node/internal/nlog"
	"github.com/go-viper/mapstructure/v2"
)

// M is a shorthand for building JSON-like maps
type M = map[string]interface{}

// privateIPv4Cidrs lists private/reserved IPv4 ranges blocked to prevent SSRF.
var privateIPv4Cidrs = []string{
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
}

// privateIPv6Cidrs lists private/reserved IPv6 ranges blocked to prevent SSRF.
var privateIPv6Cidrs = []string{
	"fc00::/7",
	"fe80::/10",
	"::1/128",
}

func buildConfig(kcfg config.KernelConfig, nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	var outbounds []M
	tags := make(map[string]bool)

	// Panel-defined custom outbounds (structured, converted to sing-box native)
	for _, co := range nc.CustomOutbounds {
		outbounds = append(outbounds, outboundConfigToSingbox(co))
		tags[strings.ToLower(co.Tag)] = true
	}

	// Static outbounds from local config file
	for _, co := range kcfg.CustomOutbound {
		tag, _ := co["tag"].(string)
		if tag != "" {
			tags[strings.ToLower(tag)] = true
		}
		outbounds = append(outbounds, M(co))
	}

	// Add default outbounds only if not already defined
	if !tags["direct"] {
		outbounds = append([]M{{"type": "direct", "tag": "direct"}}, outbounds...)
	}
	if !tags["block"] {
		outbounds = append(outbounds, M{"type": "block", "tag": "block"})
	}

	cfg := M{
		"log": M{
			"level":     kcfg.LogLevel,
			"timestamp": true,
		},
		"outbounds": outbounds,
	}

	inbound := buildInbound(nc, users, tc)
	if inbound != nil {
		cfg["inbounds"] = []M{inbound}
	}

	// Merge panel routes and static config routes
	cfg["route"] = buildRoutes(nc.Routes, nc.CustomRouteRules, mergeRouteList(nc.CustomRoutes, kcfg.CustomRoute))

	// Automatically enable rule_set caching (cache_file) when panel routes
	// reference geoip:/geosite: entries so that the downloaded .srs rule_set
	// files survive across process restarts.
	if kernel.NeedsGeoIP(nc.Routes) || kernel.NeedsGeoSite(nc.Routes) || kernel.NeedsGeoIPRules(nc.CustomRouteRules) || kernel.NeedsGeoSiteRules(nc.CustomRouteRules) {
		cfg["experimental"] = M{
			"cache_file": M{
				"enabled": true,
				"path":    filepath.Join(kcfg.ConfigDir, "cache.db"),
			},
		}
	}

	mergeCustomSingbox(cfg, kcfg)
	return cfg
}

// outboundConfigToSingbox converts a structured OutboundConfig (from the panel)
// into a sing-box outbound object. sing-box uses a flat layout where all
// protocol-specific fields sit at the top level alongside "type" and "tag".
func outboundConfigToSingbox(oc model.OutboundConfig) M {
	m := M{
		"type": oc.Protocol,
		"tag":  oc.Tag,
	}

	// Transform common protocol keys to sing-box native format
	// WireGuard: secret_key -> private_key; peers: endpoint -> address+port
	if oc.Protocol == "wireguard" {
		if sk, ok := oc.Settings["secret_key"]; ok {
			m["private_key"] = sk
		}
		if peers, ok := oc.Settings["peers"].([]any); ok {
			var wgPeers []M
			for _, p := range peers {
				if peerMap, ok := p.(map[string]any); ok {
					newPeer := M{}
					for k, v := range peerMap {
						if k == "endpoint" {
							if ep, ok := v.(string); ok {
								host, portStr, err := net.SplitHostPort(ep)
								if err == nil {
									newPeer["address"] = host
									port, _ := strconv.Atoi(portStr)
									newPeer["port"] = port
								} else {
									newPeer["address"] = ep
								}
							}
						} else {
							newPeer[k] = v
						}
					}
					wgPeers = append(wgPeers, newPeer)
				}
			}
			m["peers"] = wgPeers
		}

		// Copy any other top-level settings not handled above
		for k, v := range oc.Settings {
			if k != "secret_key" && k != "peers" {
				m[k] = v
			}
		}
	} else {
		for k, v := range oc.Settings {
			m[k] = v
		}
	}

	if oc.ProxyTag != "" {
		m["proxy_tag"] = oc.ProxyTag
	}
	return m
}

func mergeRouteList(a, b []map[string]any) []map[string]any {
	res := make([]map[string]any, 0, len(a)+len(b))
	res = append(res, a...)
	res = append(res, b...)
	return res
}

func buildRoutes(panelRoutes []model.RouteRule, customRules []model.CustomRouteRule, custom []map[string]any) M {
	var rules []M

	// Structured custom routes now take the highest priority for panel-managed overrides.
	for _, rule := range customRules {
		if rule.Disabled {
			continue
		}
		rules = append(rules, compileCustomRouteRule(rule)...)
	}

	// Raw custom routes remain the escape hatch, but no longer outrank structured rules.
	for _, cr := range custom {
		rules = append(rules, M(cr))
	}

	// Standard blocks for private IPv4 and IPv6 ranges to prevent SSRF.
	rules = append(rules,
		M{
			"outbound": "block",
			"ip_cidr":  privateIPv4Cidrs,
		},
		M{
			"outbound": "block",
			"ip_cidr":  privateIPv6Cidrs,
		},
	)

	for _, pr := range panelRoutes {
		rules = append(rules, compilePanelRouteRule(pr)...)
	}

	return M{
		"final": "direct",
		"rules": rules,
	}
}

func compilePanelRouteRule(pr model.RouteRule) []M {
	if len(pr.Match) == 0 {
		return nil
	}

	var domains, cidrs []string
	for _, item := range pr.Match {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		item = strings.TrimPrefix(item, "*.")
		if strings.Contains(item, "/") {
			cidrs = append(cidrs, item)
			continue
		}
		domains = append(domains, item)
	}

	outbound := "block"
	switch pr.Action {
	case "direct":
		outbound = "direct"
	case "dns":
		if pr.ActionValue != "" {
			outbound = pr.ActionValue
		} else {
			outbound = "dns-out"
		}
	case "proxy":
		if pr.ActionValue != "" {
			outbound = pr.ActionValue
		}
	}

	var compiled []M
	if len(domains) > 0 {
		compiled = append(compiled, M{
			"domain_suffix": copyStrings(domains),
			"outbound":      outbound,
		})
	}
	if len(cidrs) > 0 {
		compiled = append(compiled, M{
			"ip_cidr":  copyStrings(cidrs),
			"outbound": outbound,
		})
	}
	return compiled
}

func compileCustomRouteRule(rule model.CustomRouteRule) []M {
	if rule.Disabled {
		return nil
	}

	outbound := singboxOutboundForAction(rule.Action)
	var compiled []M

	if len(rule.Match.Domains) > 0 {
		compiled = append(compiled, M{
			"domain":   copyStrings(rule.Match.Domains),
			"outbound": outbound,
		})
	}
	if len(rule.Match.DomainSuffixes) > 0 {
		compiled = append(compiled, M{
			"domain_suffix": copyStrings(rule.Match.DomainSuffixes),
			"outbound":      outbound,
		})
	}
	if len(rule.Match.IPCIDRs) > 0 {
		compiled = append(compiled, M{
			"ip_cidr":  copyStrings(rule.Match.IPCIDRs),
			"outbound": outbound,
		})
	}
	if len(rule.Match.Ports) > 0 {
		ports, portRanges := splitPorts(rule.Match.Ports)
		entry := M{"outbound": outbound}
		if len(ports) > 0 {
			entry["port"] = ports
		}
		if len(portRanges) > 0 {
			entry["port_range"] = portRanges
		}
		compiled = append(compiled, entry)
	}
	if len(rule.Match.Networks) > 0 {
		compiled = append(compiled, M{
			"network":  copyStrings(rule.Match.Networks),
			"outbound": outbound,
		})
	}
	if len(rule.Match.SourceCIDRs) > 0 {
		compiled = append(compiled, M{
			"source_ip_cidr": copyStrings(rule.Match.SourceCIDRs),
			"outbound":       outbound,
		})
	}
	if len(rule.Match.SourcePorts) > 0 {
		ports, portRanges := splitPorts(rule.Match.SourcePorts)
		entry := M{"outbound": outbound}
		if len(ports) > 0 {
			entry["source_port"] = ports
		}
		if len(portRanges) > 0 {
			entry["source_port_range"] = portRanges
		}
		compiled = append(compiled, entry)
	}
	return compiled
}

func singboxOutboundForAction(action model.RouteAction) string {
	switch action.Type {
	case "direct":
		return "direct"
	case "route":
		if action.Target != "" {
			return action.Target
		}
		return "block"
	default:
		return "block"
	}
}

func splitPorts(values []string) ([]int, []string) {
	var ports []int
	var ranges []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.ContainsAny(value, ":-") {
			ranges = append(ranges, strings.ReplaceAll(value, "-", ":"))
			continue
		}
		if port, err := strconv.Atoi(value); err == nil {
			ports = append(ports, port)
		}
	}
	return ports, ranges
}

func copyStrings(src []string) []string {
	if len(src) == 0 {
		return nil
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}

func mergeCustomSingbox(cfg M, kcfg config.KernelConfig) {
	custom, err := kernel.LoadCustomConfig(kcfg.CustomConfig)
	if err != nil {
		nlog.Core().Error("failed to load custom sing-box config", "error", err)
		return
	}
	if custom == nil {
		return
	}

	// dns — custom replaces
	if v, ok := custom["dns"]; ok {
		cfg["dns"] = v
	}

	// experimental — custom replaces
	if v, ok := custom["experimental"]; ok {
		cfg["experimental"] = v
	}

	// outbounds — append custom entries
	if v, ok := custom["outbounds"]; ok {
		if existing, ok := cfg["outbounds"].([]M); ok {
			cfg["outbounds"] = kernel.MergeAppendList(existing, v)
		}
	}

	// endpoints (sing-box 1.11+ wireguard etc.) — append
	if v, ok := custom["endpoints"]; ok {
		if existing, ok := cfg["endpoints"].([]M); ok {
			cfg["endpoints"] = kernel.MergeAppendList(existing, v)
		} else {
			if items := kernel.MergeAppendList(nil, v); len(items) > 0 {
				cfg["endpoints"] = items
			}
		}
	}

	// route — merge sub-fields
	if customRoute, ok := custom["route"]; ok {
		if customRouteMap, ok := customRoute.(map[string]any); ok {
			mergeCustomSingboxRoute(cfg, customRouteMap)
		}
	}
}

func mergeCustomSingboxRoute(cfg M, customRoute map[string]any) {
	route, ok := cfg["route"].(M)
	if !ok {
		route = M{}
		cfg["route"] = route
	}

	// rules — custom rules prepended (so they match before panel rules)
	if v, ok := customRoute["rules"]; ok {
		if existing, ok := route["rules"].([]M); ok {
			route["rules"] = kernel.MergePrependList(existing, v)
		}
	}

	// rule_set — custom rule_sets appended
	if v, ok := customRoute["rule_set"]; ok {
		if existing, ok := route["rule_set"].([]M); ok {
			route["rule_set"] = kernel.MergeAppendList(existing, v)
		} else {
			route["rule_set"] = kernel.MergeAppendList(nil, v)
		}
	}

	// final, auto_detect_interface, default_interface, etc. — custom overrides
	for k, v := range customRoute {
		if k == "rules" || k == "rule_set" {
			continue
		}
		route[k] = v
	}
}

func buildInbound(nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	base := M{
		"tag":         nc.Protocol + "-in",
		"listen":      "::",
		"listen_port": nc.ServerPort,
	}

	switch nc.Protocol {
	case "shadowsocks":
		return buildShadowsocks(base, nc, users)
	case "vmess":
		return buildVMess(base, nc, users, tc)
	case "vless":
		return buildVLESS(base, nc, users, tc)
	case "trojan":
		return buildTrojan(base, nc, users, tc)
	case "hysteria":
		return buildHysteria(base, nc, users, tc)
	case "tuic":
		return buildTUIC(base, nc, users, tc)
	case "anytls":
		return buildAnyTLS(base, nc, users, tc)
	case "naive":
		return buildNaive(base, nc, users, tc)
	case "socks":
		return buildSocks(base, users)
	case "http":
		return buildHTTP(base, nc, users, tc)
	case "mieru":
		return buildMieru(base, nc, users)
	default:
		return nil
	}
}

func buildMieru(base M, nc *model.NodeSpec, users []model.UserSpec) M {
	base["type"] = "mieru"
	if nc.Transport != "" {
		base["transport"] = nc.Transport
	}
	if nc.TrafficPattern != "" {
		base["traffic_pattern"] = nc.TrafficPattern
	}

	userList := make([]M, 0, len(users))
	for _, u := range users {
		userList = append(userList, M{
			"name":     u.UUID,
			"password": u.UUID,
		})
	}
	base["users"] = userList
	return base
}

type ss2022Config struct {
	method string
	size   int
}

var ss2022Methods = map[string]ss2022Config{
	"2022-blake3-aes-128-gcm":       {"2022-blake3-aes-128-gcm", 16},
	"2022-blake3-aes-256-gcm":       {"2022-blake3-aes-256-gcm", 32},
	"2022-blake3-chacha20-poly1305": {"2022-blake3-chacha20-poly1305", 32},
}

func buildShadowsocks(base M, nc *model.NodeSpec, users []model.UserSpec) M {
	base["type"] = "shadowsocks"
	base["method"] = nc.Cipher

	ss2022, isSS2022 := ss2022Methods[nc.Cipher]
	if isSS2022 {
		base["password"] = nc.ServerKey
	}

	userList := make([]M, len(users))
	var rawBuf []byte
	if isSS2022 {
		rawBuf = make([]byte, ss2022.size)
	}

	for i := range users {
		u := &users[i]
		user := M{
			"name":     u.UUID,
			"password": u.UUID,
		}

		if isSS2022 {
			// Reuse buffer and clear it to maintain SS2022 key integrity
			for j := range rawBuf {
				rawBuf[j] = 0
			}
			copy(rawBuf, u.UUID)
			user["password"] = base64.StdEncoding.EncodeToString(rawBuf)
		}
		userList[i] = user
	}
	base["users"] = userList

	if nc.Plugin != "" {
		nlog.Core().Warn("sing-box shadowsocks inbound does not support plugin, ignoring", "plugin", nc.Plugin)
	}

	return base
}

func buildVMess(base M, nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	base["type"] = "vmess"

	userList := make([]M, 0, len(users))
	for _, u := range users {
		userList = append(userList, M{
			"name":    u.UUID,
			"uuid":    u.UUID,
			"alterId": 0,
		})
	}
	base["users"] = userList

	applyTransport(base, nc)
	applyProxyProtocol(base, nc)
	applyMultiplex(base, nc)

	if nc.TLS == 1 {
		if tls := buildTLSConfig(nc, tc); tls != nil {
			base["tls"] = tls
		}
	}

	return base
}

func buildVLESS(base M, nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	if nc.Decryption != "" && nc.Decryption != "none" {
		nlog.Core().Warn("sing-box does not support VLESS encryption (decryption), use xray kernel for this feature")
	}

	base["type"] = "vless"

	userList := make([]M, 0, len(users))
	for _, u := range users {
		user := M{
			"name": u.UUID,
			"uuid": u.UUID,
		}
		if nc.Flow != "" {
			user["flow"] = nc.Flow
		}
		userList = append(userList, user)
	}
	base["users"] = userList

	applyTransport(base, nc)
	applyProxyProtocol(base, nc)
	applyMultiplex(base, nc)

	if nc.TLS == 1 {
		if tls := buildTLSConfig(nc, tc); tls != nil {
			base["tls"] = tls
		}
	} else if nc.TLS == 2 {
		base["tls"] = buildRealityConfig(nc)
	}

	return base
}

func buildTrojan(base M, nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	base["type"] = "trojan"

	userList := make([]M, len(users))
	for i := range users {
		u := &users[i]
		userList[i] = M{
			"name":     u.UUID,
			"password": u.UUID,
		}
	}
	base["users"] = userList

	applyTransport(base, nc)
	applyProxyProtocol(base, nc)
	applyMultiplex(base, nc)

	if nc.TLS == 1 {
		if tls := buildTLSConfig(nc, tc); tls != nil {
			base["tls"] = tls
		}
	} else if nc.TLS == 2 {
		base["tls"] = buildRealityConfig(nc)
	}

	// If still no TLS/Reality but cert paths exist, enable TLS (panel may omit tls=1).
	if _, ok := base["tls"]; !ok {
		if tls := buildTLSConfig(nc, tc); tls != nil {
			base["tls"] = tls
		}
	}

	if base["tls"] == nil {
		nlog.Core().Warn("trojan inbound has no TLS (no certificate paths and no Reality); sing-box may refuse to start until cert_mode provides cert/key or Reality is configured")
	}

	return base
}

func buildHysteria(base M, nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	if nc.Version == 2 {
		base["type"] = "hysteria2"

		userList := make([]M, 0, len(users))
		for _, u := range users {
			userList = append(userList, M{
				"name":     u.UUID,
				"password": u.UUID,
			})
		}
		base["users"] = userList

		if nc.Obfs != "" {
			base["obfs"] = M{
				"type":     nc.Obfs,
				"password": nc.ObfsPassword,
			}
		}
	} else {
		base["type"] = "hysteria"

		userList := make([]M, 0, len(users))
		for _, u := range users {
			userList = append(userList, M{
				"name":     u.UUID,
				"auth_str": u.UUID,
			})
		}
		base["users"] = userList
		base["up_mbps"] = nc.UpMbps
		base["down_mbps"] = nc.DownMbps

		if nc.Obfs != "" {
			base["obfs"] = nc.Obfs
		}
	}

	tls := buildTLSConfig(nc, tc)
	if tls == nil {
		nlog.Core().Warn("hysteria requires TLS certificate files on disk; configure cert_mode (self, file, http, dns, or content). Sing-box will not start this inbound without tls.")
		return base
	}
	// Hysteria/Hysteria2 uses QUIC and requires ALPN; default to h3 if not set.
	if _, ok := tls["alpn"]; !ok {
		tls["alpn"] = []string{"h3"}
	}
	base["tls"] = tls
	return base
}

func buildTUIC(base M, nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	base["type"] = "tuic"

	userList := make([]M, 0, len(users))
	for _, u := range users {
		userList = append(userList, M{
			"name":     u.UUID,
			"uuid":     u.UUID,
			"password": u.UUID,
		})
	}
	base["users"] = userList

	if nc.CongestionControl != "" {
		base["congestion_control"] = nc.CongestionControl
	}

	tls := buildTLSConfig(nc, tc)
	if tls == nil {
		nlog.Core().Warn("tuic requires TLS certificate files on disk; configure cert_mode (self, file, http, dns, or content). Sing-box will not start this inbound without tls.")
		return base
	}
	// TUIC requires ALPN for QUIC negotiation; default to h3 if not set by panel.
	if _, ok := tls["alpn"]; !ok {
		tls["alpn"] = []string{"h3"}
	}
	base["tls"] = tls
	return base
}

func buildAnyTLS(base M, nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	base["type"] = "anytls"

	userList := make([]M, 0, len(users))
	for _, u := range users {
		userList = append(userList, M{
			"name":     u.UUID,
			"password": u.UUID,
		})
	}
	base["users"] = userList

	if nc.PaddingScheme != "" {
		base["padding_scheme"] = nc.PaddingScheme
	}

	if tls := buildTLSConfig(nc, tc); tls != nil {
		base["tls"] = tls
	} else {
		nlog.Core().Warn("anytls requires TLS certificate files on disk; configure cert_mode (self, file, http, dns, or content). Sing-box will not start this inbound without tls.")
	}
	return base
}

func buildNaive(base M, nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	base["type"] = "naive"

	userList := make([]M, 0, len(users))
	for _, u := range users {
		userList = append(userList, M{
			"username": strconv.Itoa(u.ID),
			"password": u.UUID,
		})
	}
	base["users"] = userList

	if nc.TLS == 1 {
		if tls := buildTLSConfig(nc, tc); tls != nil {
			base["tls"] = tls
		}
	}
	return base
}

func buildSocks(base M, users []model.UserSpec) M {
	base["type"] = "socks"

	userList := make([]M, 0, len(users))
	for _, u := range users {
		userList = append(userList, M{
			"username": u.UUID,
			"password": u.UUID,
		})
	}
	base["users"] = userList
	return base
}

func buildHTTP(base M, nc *model.NodeSpec, users []model.UserSpec, tc kernel.TLSCert) M {
	base["type"] = "http"

	userList := make([]M, 0, len(users))
	for _, u := range users {
		userList = append(userList, M{
			"username": u.UUID,
			"password": u.UUID,
		})
	}
	base["users"] = userList

	applyProxyProtocol(base, nc)
	if nc.TLS == 1 {
		if tls := buildTLSConfig(nc, tc); tls != nil {
			base["tls"] = tls
		}
	}
	return base
}

func applyTransport(base M, nc *model.NodeSpec) {
	if nc.Network == "" || nc.Network == "tcp" {
		return
	}

	transport := M{"type": nc.Network}

	if nc.NetworkSettings != nil {
		switch nc.Network {
		case "ws":
			if v, ok := nc.NetworkSettings["path"]; ok {
				transport["path"] = v
			}
			if v, ok := nc.NetworkSettings["headers"]; ok {
				transport["headers"] = v
			}
			if v, ok := nc.NetworkSettings["host"]; ok {
				if transport["headers"] == nil {
					transport["headers"] = M{"Host": v}
				}
			}
			if v, ok := nc.NetworkSettings["max_early_data"]; ok {
				transport["max_early_data"] = v
			}
			if v, ok := nc.NetworkSettings["early_data_header_name"]; ok {
				transport["early_data_header_name"] = v
			}
		case "grpc":
			if v, ok := nc.NetworkSettings["serviceName"]; ok {
				transport["service_name"] = v
			} else if v, ok := nc.NetworkSettings["service_name"]; ok {
				transport["service_name"] = v
			}
		case "httpupgrade":
			if v, ok := nc.NetworkSettings["path"]; ok {
				transport["path"] = v
			}
			if v, ok := nc.NetworkSettings["host"]; ok {
				transport["host"] = v
			}
		case "h2", "http":
			transport["type"] = "http"
			if v, ok := nc.NetworkSettings["path"]; ok {
				transport["path"] = v
			}
			if v, ok := nc.NetworkSettings["host"]; ok {
				transport["host"] = v
			}
		}
	}

	base["transport"] = transport
}

// buildTLSConfig returns sing-box inbound TLS options when certificate material
// is available. Returns nil if no TLS material is provided.
func buildTLSConfig(nc *model.NodeSpec, tc kernel.TLSCert) M {
	if !tc.HasCert() {
		return nil
	}

	t := M{"enabled": true}

	serverName := nc.ServerName
	if serverName == "" && nc.Host != "" {
		serverName = nc.Host
	}
	if serverName != "" {
		t["server_name"] = serverName
	}

	if nc.TLSSettings != nil {
		if sn, ok := nc.TLSSettings["server_name"]; ok && sn != "" {
			t["server_name"] = sn
		}
		if alpn, ok := nc.TLSSettings["alpn"]; ok {
			t["alpn"] = alpn
		}
		// ECH server-side: only key/key_path needed for inbound
		if ech := extractECHInbound(nc.TLSSettings); ech != nil {
			t["ech"] = ech
		}
	}

	t["certificate"] = []string{string(tc.CertPEM)}
	t["key"] = []string{string(tc.KeyPEM)}

	return t
}

func buildRealityConfig(nc *model.NodeSpec) M {
	tls := M{"enabled": true}
	if nc.TLSSettings == nil {
		return tls
	}

	reality := M{"enabled": true}
	var settings struct {
		PrivateKey string `mapstructure:"private_key"`
		ShortID    any    `mapstructure:"short_id"`
		Dest       string `mapstructure:"dest"`
		ServerName string `mapstructure:"server_name"`
		ServerPort int    `mapstructure:"server_port"`
	}

	decoderConfig := &mapstructure.DecoderConfig{
		Metadata:         nil,
		Result:           &settings,
		WeaklyTypedInput: true,
	}
	decoder, _ := mapstructure.NewDecoder(decoderConfig)
	_ = decoder.Decode(nc.TLSSettings)

	if settings.PrivateKey != "" {
		reality["private_key"] = settings.PrivateKey
	}

	switch v := settings.ShortID.(type) {
	case string:
		reality["short_id"] = []string{v}
	case []any:
		ids := make([]string, 0, len(v))
		for _, item := range v {
			ids = append(ids, fmt.Sprintf("%v", item))
		}
		reality["short_id"] = ids
	case []string:
		reality["short_id"] = v
	}

	dest := settings.Dest
	if dest == "" {
		dest = settings.ServerName
	}

	if dest != "" {
		handshake := M{"server": dest, "server_port": 443}
		if parts := strings.SplitN(dest, ":", 2); len(parts) == 2 {
			handshake["server"] = parts[0]
			if p, err := strconv.Atoi(parts[1]); err == nil {
				handshake["server_port"] = p
			}
		} else if settings.ServerPort > 0 {
			handshake["server_port"] = settings.ServerPort
		}
		reality["handshake"] = handshake
	}

	if settings.ServerName != "" {
		tls["server_name"] = settings.ServerName
	}

	tls["reality"] = reality
	return tls
}

func applyMultiplex(base M, nc *model.NodeSpec) {
	if nc.Multiplex == nil || !nc.Multiplex.Enabled {
		return
	}

	mux := M{
		"enabled": true,
	}
	if nc.Multiplex.Padding {
		mux["padding"] = true
	}

	if nc.Multiplex.Brutal != nil && nc.Multiplex.Brutal.Enabled {
		brutal := M{
			"enabled": true,
		}
		if nc.Multiplex.Brutal.UpMbps > 0 {
			brutal["up_mbps"] = nc.Multiplex.Brutal.UpMbps
		}
		if nc.Multiplex.Brutal.DownMbps > 0 {
			brutal["down_mbps"] = nc.Multiplex.Brutal.DownMbps
		}
		mux["brutal"] = brutal
	}

	base["multiplex"] = mux
}

func applyProxyProtocol(base M, nc *model.NodeSpec) {
	// if !nc.GetProxyProtocol() {
	// 	return
	// }
	// base["proxy_protocol"] = true
}

// extractECHInbound extracts ECH config for sing-box server (inbound).
// sing-box InboundECHOptions needs: enabled, key (PEM array), key_path.
func extractECHInbound(tlsSettings map[string]interface{}) M {
	echRaw, ok := tlsSettings["ech"]
	if !ok {
		return nil
	}
	echMap, ok := echRaw.(map[string]interface{})
	if !ok {
		return nil
	}
	enabled, _ := echMap["enabled"].(bool)
	if !enabled {
		return nil
	}
	ech := M{"enabled": true}
	hasSource := false
	if key, _ := echMap["key"].(string); key != "" {
		ech["key"] = []string{key} // sing-box expects PEM as-is
		hasSource = true
	}
	if keyPath, _ := echMap["key_path"].(string); keyPath != "" {
		ech["key_path"] = keyPath
		hasSource = true
	}
	if !hasSource {
		nlog.Core().Warn("ECH enabled but no key or key_path provided")
	}
	return ech // let sing-box report a clear error if key is missing
}
