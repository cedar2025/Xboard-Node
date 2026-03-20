package singbox

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/panel"
	"github.com/go-viper/mapstructure/v2"
)

// M is a shorthand for building JSON-like maps
type M = map[string]interface{}

func buildConfig(kcfg config.KernelConfig, nc *panel.NodeConfig, users []panel.User, certFile, keyFile string) M {
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

	inbound := buildInbound(nc, users, certFile, keyFile)
	if inbound != nil {
		cfg["inbounds"] = []M{inbound}
	}

	// Merge panel routes and static config routes
	cfg["route"] = buildRoutes(nc.Routes, mergeRouteList(nc.CustomRoutes, kcfg.CustomRoute))

	// Automatically enable rule_set caching (cache_file) when panel routes
	// reference geoip:/geosite: entries so that the downloaded .srs rule_set
	// files survive across process restarts.
	if kernel.NeedsGeoIP(nc.Routes) || kernel.NeedsGeoSite(nc.Routes) {
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
func outboundConfigToSingbox(oc panel.OutboundConfig) M {
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

func buildRoutes(panelRoutes []panel.RouteRule, custom []map[string]any) M {
	var rules []M

	// Custom Routes (Panel-pushed or Local) go FIRST to have highest priority
	for _, cr := range custom {
		rules = append(rules, M(cr))
	}

	// Standard blocks for private/loopback
	rules = append(rules, M{
		"outbound": "block",
		"ip_cidr": []string{
			"10.0.0.0/8",
			"100.64.0.0/10",
			"127.0.0.0/8",
			"169.254.0.0/16",
			"172.16.0.0/12",
			"192.0.0.0/24",
			"192.168.0.0/16",
			"198.18.0.0/15",
			"fc00::/7",
			"fe80::/10",
			"::1/128",
		},
	}, M{
		"outbound": "block",
		"domain": []string{
			"geoip:private",
		},
	})

	// Panel-defined routes (usually specific blocks/proxies)
	for _, pr := range panelRoutes {
		if len(pr.Match) == 0 {
			continue
		}

		var domains, cidrs []string
		for _, m := range pr.Match {
			m = strings.TrimSpace(m)
			if m == "" {
				continue
			}
			// Strip leading wildcard for domain matching
			if strings.HasPrefix(m, "*.") {
				m = strings.TrimPrefix(m, "*.")
			}
			// Check if it's a CIDR block (contains /)
			if strings.Contains(m, "/") {
				cidrs = append(cidrs, m)
			} else {
				// Otherwise treat as domain
				domains = append(domains, m)
			}
		}

		// Determine outbound tag based on action
		outbound := "block"
		if pr.Action == "direct" {
			outbound = "direct"
		} else if pr.Action == "dns" {
			// Special case for sing-box DNS routing:
			// If action is "dns" and action_value is provided, we use it as the server name.
			// Otherwise it defaults to "dns-out".
			server := "dns-out"
			if pr.ActionValue != "" {
				server = pr.ActionValue
			}
			outbound = server
		} else if pr.Action == "proxy" {
			// If panel provides a specific outbound tag in action_value, use it.
			// This allows routing to WARP_JP etc. via normal routes.
			if pr.ActionValue != "" {
				outbound = pr.ActionValue
			}
		}

		// Create separate rule for domains
		if len(domains) > 0 {
			rule := M{
				"domain_suffix": domains,
				"outbound":      outbound,
			}
			rules = append(rules, rule)
		}

		// Create separate rule for CIDRs
		if len(cidrs) > 0 {
			rule := M{
				"ip_cidr":  cidrs,
				"outbound": outbound,
			}
			rules = append(rules, rule)
		}
	}

	return M{
		"final": "direct",
		"rules": rules,
	}
}

func mergeCustomSingbox(cfg M, kcfg config.KernelConfig) {
	custom, err := kernel.LoadCustomConfig(kcfg.CustomConfig)
	if err != nil {
		slog.Error("failed to load custom sing-box config", "error", err)
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

func buildInbound(nc *panel.NodeConfig, users []panel.User, certFile, keyFile string) M {
	base := M{
		"tag":         nc.Protocol + "-in",
		"listen":      "::",
		"listen_port": nc.ServerPort,
	}

	switch nc.Protocol {
	case "shadowsocks":
		return buildShadowsocks(base, nc, users)
	case "vmess":
		return buildVMess(base, nc, users, certFile, keyFile)
	case "vless":
		return buildVLESS(base, nc, users, certFile, keyFile)
	case "trojan":
		return buildTrojan(base, nc, users, certFile, keyFile)
	case "hysteria":
		return buildHysteria(base, nc, users, certFile, keyFile)
	case "tuic":
		return buildTUIC(base, nc, users, certFile, keyFile)
	case "anytls":
		return buildAnyTLS(base, nc, users, certFile, keyFile)
	case "naive":
		return buildNaive(base, nc, users, certFile, keyFile)
	case "socks":
		return buildSocks(base, users)
	case "http":
		return buildHTTP(base, nc, users, certFile, keyFile)
	case "mieru":
		return buildMieru(base, nc, users)
	default:
		return nil
	}
}

func buildMieru(base M, nc *panel.NodeConfig, users []panel.User) M {
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

func buildShadowsocks(base M, nc *panel.NodeConfig, users []panel.User) M {
	base["type"] = "shadowsocks"
	base["method"] = nc.Cipher

	is2022 := strings.HasPrefix(nc.Cipher, "2022-blake3-")
	if is2022 {
		base["password"] = nc.ServerKey
	}

	// For SS2022 ciphers, the per-user key must be base64-encoded to match
	// the panel's Helper::uuidToBase64(uuid, keySize) output.
	// AES-256 requires 32-byte keys, AES-128 requires 16-byte keys.
	keySize := 32
	if nc.Cipher == "2022-blake3-aes-128-gcm" {
		keySize = 16
	}

	userList := make([]M, 0, len(users))
	for _, u := range users {
		password := u.UUID
		if is2022 {
			raw := u.UUID
			if len(raw) > keySize {
				raw = raw[:keySize]
			}
			password = base64.StdEncoding.EncodeToString([]byte(raw))
		}
		userList = append(userList, M{
			"name":     u.UUID,
			"password": password,
		})
	}
	base["users"] = userList

	if nc.Plugin != "" {
		slog.Warn("sing-box shadowsocks inbound does not support plugin, ignoring", "plugin", nc.Plugin)
	}

	return base
}

func buildVMess(base M, nc *panel.NodeConfig, users []panel.User, certFile, keyFile string) M {
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
	applyMultiplex(base, nc)

	if nc.TLS == 1 {
		base["tls"] = buildTLSConfig(nc, certFile, keyFile)
	}

	return base
}

func buildVLESS(base M, nc *panel.NodeConfig, users []panel.User, certFile, keyFile string) M {
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
	applyMultiplex(base, nc)

	if nc.TLS == 1 {
		base["tls"] = buildTLSConfig(nc, certFile, keyFile)
	} else if nc.TLS == 2 {
		base["tls"] = buildRealityConfig(nc)
	}

	return base
}

func buildTrojan(base M, nc *panel.NodeConfig, users []panel.User, certFile, keyFile string) M {
	base["type"] = "trojan"

	userList := make([]M, 0, len(users))
	for _, u := range users {
		userList = append(userList, M{
			"name":     u.UUID,
			"password": u.UUID,
		})
	}
	base["users"] = userList

	applyTransport(base, nc)
	applyMultiplex(base, nc)

	if nc.TLS == 1 {
		base["tls"] = buildTLSConfig(nc, certFile, keyFile)
	} else if nc.TLS == 2 {
		base["tls"] = buildRealityConfig(nc)
	}
	return base
}

func buildHysteria(base M, nc *panel.NodeConfig, users []panel.User, certFile, keyFile string) M {
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

	tls := buildTLSConfig(nc, certFile, keyFile)
	// Hysteria/Hysteria2 uses QUIC and requires ALPN; default to h3 if not set.
	if _, ok := tls["alpn"]; !ok {
		tls["alpn"] = []string{"h3"}
	}
	base["tls"] = tls
	return base
}

func buildTUIC(base M, nc *panel.NodeConfig, users []panel.User, certFile, keyFile string) M {
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

	tls := buildTLSConfig(nc, certFile, keyFile)
	// TUIC requires ALPN for QUIC negotiation; default to h3 if not set by panel.
	if _, ok := tls["alpn"]; !ok {
		tls["alpn"] = []string{"h3"}
	}
	base["tls"] = tls
	return base
}

func buildAnyTLS(base M, nc *panel.NodeConfig, users []panel.User, certFile, keyFile string) M {
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
		base["padding_scheme"] = string(nc.PaddingScheme)
	}

	base["tls"] = buildTLSConfig(nc, certFile, keyFile)
	return base
}

func buildNaive(base M, nc *panel.NodeConfig, users []panel.User, certFile, keyFile string) M {
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
		base["tls"] = buildTLSConfig(nc, certFile, keyFile)
	}
	return base
}

func buildSocks(base M, users []panel.User) M {
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

func buildHTTP(base M, nc *panel.NodeConfig, users []panel.User, certFile, keyFile string) M {
	base["type"] = "http"

	userList := make([]M, 0, len(users))
	for _, u := range users {
		userList = append(userList, M{
			"username": u.UUID,
			"password": u.UUID,
		})
	}
	base["users"] = userList

	if nc.TLS == 1 {
		base["tls"] = buildTLSConfig(nc, certFile, keyFile)
	}
	return base
}

func applyTransport(base M, nc *panel.NodeConfig) {
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
			if v, ok := nc.NetworkSettings["service_name"]; ok {
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

func buildTLSConfig(nc *panel.NodeConfig, certFile, keyFile string) M {
	tls := M{"enabled": true}

	serverName := nc.ServerName
	if serverName == "" && nc.Host != "" {
		serverName = nc.Host
	}
	if serverName != "" {
		tls["server_name"] = serverName
	}

	if nc.TLSSettings != nil {
		if sn, ok := nc.TLSSettings["server_name"]; ok && sn != "" {
			tls["server_name"] = sn
		}
		if alpn, ok := nc.TLSSettings["alpn"]; ok {
			tls["alpn"] = alpn
		}
	}

	if certFile != "" && keyFile != "" {
		tls["certificate_path"] = certFile
		tls["key_path"] = keyFile
	} else {
		// If no real certificates are provided, but TLS is requested,
		// use a self-signed certificate as fallback to prevent sing-box
		// from failing with "missing certificate".
		tls["certificate_path"] = "self-signed"
	}

	return tls
}

func buildRealityConfig(nc *panel.NodeConfig) M {
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

func applyMultiplex(base M, nc *panel.NodeConfig) {
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
