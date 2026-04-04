package xray

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/nlog"
	"github.com/cedar2025/xboard-node/internal/panel"
)

// M is a shorthand for building JSON-like maps
type M = map[string]interface{}

func buildConfig(kcfg config.KernelConfig, nc *panel.NodeConfig, users []panel.User, certFile, keyFile string) M {
	var outbounds []M
	tags := make(map[string]bool)

	// Panel-defined custom outbounds (structured, converted to Xray native)
	for _, co := range nc.CustomOutbounds {
		outbounds = append(outbounds, outboundConfigToXray(co))
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

	// Add default outbounds only if not already defined (Issue #1: Panel priority)
	if !tags["direct"] {
		outbounds = append([]M{{"protocol": "freedom", "tag": "direct"}}, outbounds...)
	}
	if !tags["block"] {
		// block is often added after direct but before others for safety
		outbounds = append(outbounds, M{"protocol": "blackhole", "tag": "block"})
	}

	cfg := M{
		"log": M{
			"loglevel": xrayLogLevel(kcfg.LogLevel),
			"error":    "",
			"access":   "",
		},
		"stats": M{},
		"policy": M{
			"levels": M{
				"0": M{
					"statsUserUplink":   true,
					"statsUserDownlink": true,
				},
			},
			"system": M{
				"statsInboundUplink":    true,
				"statsInboundDownlink":  true,
				"statsOutboundUplink":   true,
				"statsOutboundDownlink": true,
			},
		},
		"outbounds": outbounds,
	}

	inbound := buildInbound(nc, users, certFile, keyFile)
	if inbound != nil {
		cfg["inbounds"] = []M{inbound}
	} else {
		nlog.Core().Warn("xray: unsupported protocol, no inbound configured — node will not accept connections",
			"protocol", nc.Protocol,
			"supported", "vmess, vless, trojan, shadowsocks, hysteria, socks, http")
	}

	// Merge panel routes and static config routes
	cfg["routing"] = buildRouting(nc.Routes, mergeRouteList(nc.CustomRoutes, kcfg.CustomRoute))

	mergeCustomXray(cfg, kcfg)
	return cfg
}

// outboundConfigToXray converts a structured OutboundConfig (from the panel)
// into an Xray outbound object. Xray uses a nested layout where protocol-
// specific fields go inside a "settings" key, and chain proxying uses "proxySettings".
func outboundConfigToXray(oc panel.OutboundConfig) M {
	m := M{
		"protocol": oc.Protocol,
		"tag":      oc.Tag,
	}
	if len(oc.Settings) > 0 {
		m["settings"] = oc.Settings
	}
	if oc.ProxyTag != "" {
		m["proxySettings"] = M{"tag": oc.ProxyTag}
	}
	return m
}

func mergeRouteList(a, b []map[string]any) []map[string]any {
	res := make([]map[string]any, 0, len(a)+len(b))
	res = append(res, a...)
	res = append(res, b...)
	return res
}

// mergeCustomXray deep-merges a custom Xray config file into the generated config.
// Merge strategy (compatible with V2bX/XrayR custom DNS etc.):
//   - dns: custom replaces auto-generated
//   - outbounds: custom entries appended
//   - routing.rules: custom rules prepended (matched first)
//   - policy, api: custom deep-merges
//   - inbounds: NOT merged (panel-managed, authoritative)
func mergeCustomXray(cfg M, kcfg config.KernelConfig) {
	custom, err := kernel.LoadCustomConfig(kcfg.CustomConfig)
	if err != nil {
		nlog.Core().Error("failed to load custom xray config", "error", err)
		return
	}
	if custom == nil {
		return
	}

	// dns — custom replaces (same as V2bX DnsConfigPath)
	if v, ok := custom["dns"]; ok {
		cfg["dns"] = v
	}

	// outbounds — append custom entries
	if v, ok := custom["outbounds"]; ok {
		if existing, ok := cfg["outbounds"].([]M); ok {
			cfg["outbounds"] = kernel.MergeAppendList(existing, v)
		}
	}

	// routing — merge sub-fields
	if customRouting, ok := custom["routing"]; ok {
		if customRoutingMap, ok := customRouting.(map[string]any); ok {
			mergeCustomXrayRouting(cfg, customRoutingMap)
		}
	}

	// other top-level keys (policy, api, transport, etc.) — custom overrides,
	// but we protect auto-generated inbounds, stats, log, routing, outbounds
	protected := map[string]bool{
		"inbounds": true, "outbounds": true, "routing": true,
		"dns": true, "log": true, "stats": true, "policy": true,
	}
	for k, v := range custom {
		if !protected[k] {
			cfg[k] = v
		}
	}
}

func mergeCustomXrayRouting(cfg M, customRouting map[string]any) {
	routing, ok := cfg["routing"].(M)
	if !ok {
		routing = M{}
		cfg["routing"] = routing
	}

	// rules — custom rules prepended (so they match before panel rules)
	if v, ok := customRouting["rules"]; ok {
		if existing, ok := routing["rules"].([]M); ok {
			routing["rules"] = kernel.MergePrependList(existing, v)
		}
	}

	// domainStrategy, balancers, etc. — custom overrides
	for k, v := range customRouting {
		if k == "rules" {
			continue
		}
		routing[k] = v
	}
}

func xrayLogLevel(singboxLevel string) string {
	switch singboxLevel {
	case "trace", "debug":
		return "debug"
	case "info":
		return "info"
	case "warn":
		return "warning"
	case "error":
		return "error"
	case "fatal", "panic":
		return "error"
	default:
		return "warning"
	}
}

func buildInbound(nc *panel.NodeConfig, users []panel.User, certFile, keyFile string) M {
	listenAddr := "::"
	if nc.ListenIP != "" {
		listenAddr = nc.ListenIP
	}
	base := M{
		"tag":      nc.Protocol + "-in",
		"listen":   listenAddr,
		"port":     nc.ServerPort,
		"protocol": nc.Protocol,
		"streamSettings": M{
			"sockopt": M{
				"reusePort": true,
			},
		},
	}

	switch nc.Protocol {
	case "vmess":
		return buildVMess(base, nc, users, certFile, keyFile)
	case "vless":
		return buildVLESS(base, nc, users, certFile, keyFile)
	case "trojan":
		return buildTrojan(base, nc, users, certFile, keyFile)
	case "shadowsocks":
		return buildShadowsocks(base, nc, users)
	case "socks":
		return buildSocks(base, users)
	case "http":
		return buildHTTP(base, nc, users, certFile, keyFile)
	case "hysteria":
		return buildHysteria(base, nc, users, certFile, keyFile)
	default:
		return nil
	}
}

// userEmail returns the stats-tracking email for a user.
// Format: "user@<id>" so we can parse back the user ID from stats counters.
func userEmail(userID int) string {
	return fmt.Sprintf("user@%d", userID)
}

func buildVMess(base M, nc *panel.NodeConfig, users []panel.User, certFile, keyFile string) M {
	clients := make([]M, 0, len(users))
	for _, u := range users {
		clients = append(clients, M{
			"id":      u.UUID,
			"alterId": 0,
			"email":   userEmail(u.ID),
		})
	}
	base["settings"] = M{"clients": clients}

	applyStreamSettings(base, nc, certFile, keyFile)
	return base
}

func buildVLESS(base M, nc *panel.NodeConfig, users []panel.User, certFile, keyFile string) M {
	clients := make([]M, 0, len(users))
	for _, u := range users {
		client := M{
			"id":    u.UUID,
			"email": userEmail(u.ID),
		}
		if nc.Flow != "" {
			client["flow"] = nc.Flow
		}
		clients = append(clients, client)
	}
	decryption := "none"
	if nc.Decryption != "" {
		decryption = nc.Decryption
	}
	base["settings"] = M{
		"clients":    clients,
		"decryption": decryption,
	}

	applyStreamSettings(base, nc, certFile, keyFile)
	return base
}

func buildTrojan(base M, nc *panel.NodeConfig, users []panel.User, certFile, keyFile string) M {
	clients := make([]M, len(users))
	for i := range users {
		u := &users[i]
		clients[i] = M{
			"password": u.UUID,
			"email":    userEmail(u.ID),
		}
	}
	base["settings"] = M{"clients": clients}

	applyStreamSettings(base, nc, certFile, keyFile)

	// Trojan requires TLS or Reality to be enabled.
	// If the panel didn't explicitly set TLS=1 or TLS=2, but we have certs,
	// we should enable a default TLS config to ensure the inbound can start.
	ss, _ := base["streamSettings"].(M)
	if security, ok := ss["security"].(string); !ok || (security != "tls" && security != "reality") {
		nc.TLS = 1 // Force internal state to trigger TLS build in applyStreamSettings
		applyStreamSettings(base, nc, certFile, keyFile)
	}

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

func buildShadowsocks(base M, nc *panel.NodeConfig, users []panel.User) M {
	ss2022, isSS2022 := ss2022Methods[nc.Cipher]

	clients := make([]M, 0, len(users))

	if isSS2022 {
		// SS2022: server key at top level, per-user key must be Base64 of fixed-length raw bytes.
		// Only blake3-aes-* supports multi-user in Xray; chacha20 variant is single-user only.
		rawBuf := make([]byte, ss2022.size)
		for i := range users {
			u := &users[i]
			for j := range rawBuf {
				rawBuf[j] = 0
			}
			copy(rawBuf, u.UUID)
			clients = append(clients, M{
				"password": base64.StdEncoding.EncodeToString(rawBuf),
				"email":    userEmail(u.ID),
			})
		}
		base["settings"] = M{
			"method":   nc.Cipher,
			"password": nc.ServerKey,
			"clients":  clients,
			"network":  "tcp,udp",
		}
	} else {
		// Traditional ciphers: multi-user via clients array.
		// Each entry must carry its own "method" field for Xray to parse correctly.
		for i := range users {
			u := &users[i]
			clients = append(clients, M{
				"method":   nc.Cipher,
				"password": u.UUID,
				"email":    userEmail(u.ID),
			})
		}
		base["settings"] = M{
			"method":  nc.Cipher,
			"clients": clients,
			"network": "tcp,udp",
		}
	}
	return base
}

func buildSocks(base M, users []panel.User) M {
	base["protocol"] = "socks"
	accounts := make([]M, 0, len(users))
	for _, u := range users {
		accounts = append(accounts, M{
			"user":  u.UUID,
			"pass":  u.UUID,
			"email": userEmail(u.ID),
		})
	}
	base["settings"] = M{
		"auth":     "password",
		"accounts": accounts,
		"udp":      true,
	}
	return base
}

func buildHTTP(base M, nc *panel.NodeConfig, users []panel.User, certFile, keyFile string) M {
	base["protocol"] = "http"
	accounts := make([]M, 0, len(users))
	for _, u := range users {
		accounts = append(accounts, M{
			"user":  u.UUID,
			"pass":  u.UUID,
			"email": userEmail(u.ID),
		})
	}
	base["settings"] = M{
		"accounts": accounts,
	}

	if nc.TLS == 1 {
		applyStreamSettings(base, nc, certFile, keyFile)
	}
	return base
}

// buildHysteria creates a Hysteria v2 inbound for xray-core.
func buildHysteria(base M, nc *panel.NodeConfig, users []panel.User, certFile, keyFile string) M {
	if nc.Version != 2 {
		nlog.Core().Warn("xray: only supports hysteria v2, skipping v1 inbound")
		return nil
	}

	clients := make([]M, 0, len(users))
	for _, u := range users {
		clients = append(clients, M{
			"auth":  u.UUID,
			"email": userEmail(u.ID),
		})
	}
	base["settings"] = M{"clients": clients}

	ss := M{
		"network": "hysteria",
		"hysteriaSettings": M{
			"version":        nc.Version,
			"udpIdleTimeout": 60,
		},
	}

	if nc.UpMbps > 0 || nc.DownMbps > 0 {
		quicParams := M{}
		if nc.UpMbps > 0 {
			quicParams["brutalUp"] = fmt.Sprintf("%d mbps", nc.UpMbps)
		}
		if nc.DownMbps > 0 {
			quicParams["brutalDown"] = fmt.Sprintf("%d mbps", nc.DownMbps)
		}
		ss["finalMask"] = M{
			"quicParams": quicParams,
		}
	}

	if certFile != "" && keyFile != "" {
		ss["security"] = "tls"
		ss["tlsSettings"] = M{
			"certificates": []M{
				{
					"certificateFile": certFile,
					"keyFile":         keyFile,
				},
			},
			"alpn": []string{"h3"},
		}
	} else {
		nlog.Core().Warn("hysteria requires TLS certificate files; configure cert_mode (self, file, http, dns, or content)")
	}

	if nc.GetProxyProtocol() {
		ss["sockopt"] = M{"acceptProxyProtocol": true}
	}

	base["streamSettings"] = ss
	return base
}

func applyStreamSettings(base M, nc *panel.NodeConfig, certFile, keyFile string) {
	ss := M{}

	// Network / transport
	network := nc.Network
	if network == "" {
		network = "tcp"
	}
	ss["network"] = network

	switch network {
	case "ws":
		wsSettings := M{}
		if nc.NetworkSettings != nil {
			if v, ok := nc.NetworkSettings["path"]; ok {
				wsSettings["path"] = v
			}
			headers := M{}
			if v, ok := nc.NetworkSettings["headers"]; ok {
				if headersMap, ok := v.(map[string]interface{}); ok {
					for k, val := range headersMap {
						headers[k] = val
					}
				}
			}
			if v, ok := nc.NetworkSettings["host"]; ok {
				headers["Host"] = v
			}
			if len(headers) > 0 {
				wsSettings["headers"] = headers
			}
		}
		ss["wsSettings"] = wsSettings

	case "grpc":
		grpcSettings := M{}
		if nc.NetworkSettings != nil {
			if v, ok := nc.NetworkSettings["serviceName"]; ok {
				grpcSettings["serviceName"] = v
			}
		}
		ss["grpcSettings"] = grpcSettings
		
    case "xhttp":
        xhttpSettings := M{}
        if nc.NetworkSettings != nil {
            if v, ok := nc.NetworkSettings["path"]; ok {
                xhttpSettings["path"] = v
            }
            if v, ok := nc.NetworkSettings["host"]; ok {
                    xhttpSettings["host"] = v
            }
            if v, ok := nc.NetworkSettings["mode"]; ok {
                    xhttpSettings["mode"] = v
            }
                        // extra 参数（服务端）
            if extra, ok := nc.NetworkSettings["extra"]; ok {
                    if extraMap, ok := extra.(map[string]interface{}); ok {
                            xhttpSettings["extra"] = extraMap
                    }
            }
            }
        ss["xhttpSettings"] = xhttpSettings
		
	case "httpupgrade":
		huSettings := M{}
		if nc.NetworkSettings != nil {
			if v, ok := nc.NetworkSettings["path"]; ok {
				huSettings["path"] = v
			}
			if v, ok := nc.NetworkSettings["host"]; ok {
				huSettings["host"] = v
			}
		}
		ss["httpupgradeSettings"] = huSettings

	case "h2", "http":
		ss["network"] = "h2"
		h2Settings := M{}
		if nc.NetworkSettings != nil {
			if v, ok := nc.NetworkSettings["path"]; ok {
				h2Settings["path"] = v
			}
			if v, ok := nc.NetworkSettings["host"]; ok {
				h2Settings["host"] = []interface{}{v}
			}
		}
		ss["httpSettings"] = h2Settings

	case "tcp":
		// default, no extra settings
	}

	// TLS
	if nc.TLS == 1 {
		tlsSettings := M{}
		serverName := nc.ServerName
		if serverName == "" && nc.Host != "" {
			serverName = nc.Host
		}
		if serverName != "" {
			tlsSettings["serverName"] = serverName
		}
		if nc.TLSSettings != nil {
			if sn, ok := nc.TLSSettings["server_name"]; ok && sn != "" {
				tlsSettings["serverName"] = sn
			}
		}
		if certFile != "" && keyFile != "" {
			tlsSettings["certificates"] = []M{
				{
					"certificateFile": certFile,
					"keyFile":         keyFile,
				},
			}
		} else {
			// Fallback placeholder for auto-TLS environments.
			// Xray allows empty certificates array in more cases than sing-box,
			// but providing a placeholder helps documentation.
		}
		ss["security"] = "tls"
		ss["tlsSettings"] = tlsSettings
	} else if nc.TLS == 2 {
		ss["security"] = "reality"
		ss["realitySettings"] = buildRealitySettings(nc)
	}

	// Proxy Protocol
	if nc.GetProxyProtocol() {
		sockopt, ok := base["streamSettings"].(M)["sockopt"].(M)
		if !ok {
			sockopt = M{}
		}
		sockopt["acceptProxyProtocol"] = true
		ss["sockopt"] = sockopt
	}

	base["streamSettings"] = ss
}

func buildRealitySettings(nc *panel.NodeConfig) M {
	reality := M{"show": false}

	if nc.TLSSettings == nil {
		return reality
	}

	if pk, ok := nc.TLSSettings["private_key"]; ok {
		reality["privateKey"] = pk
	}
	if sid, ok := nc.TLSSettings["short_id"]; ok {
		switch v := sid.(type) {
		case string:
			reality["shortIds"] = []string{v}
		case []interface{}:
			ids := make([]string, 0, len(v))
			for _, item := range v {
				ids = append(ids, fmt.Sprintf("%v", item))
			}
			reality["shortIds"] = ids
		}
	}

	if dest, ok := nc.TLSSettings["dest"]; ok {
		destStr := fmt.Sprintf("%v", dest)
		reality["dest"] = destStr
	}
	if sn, ok := nc.TLSSettings["server_name"]; ok {
		reality["serverNames"] = []string{fmt.Sprintf("%v", sn)}
		if _, exists := reality["dest"]; !exists {
			reality["dest"] = fmt.Sprintf("%v:443", sn)
		}
	}

	return reality
}

func buildRouting(rules []panel.RouteRule, customRules []map[string]any) M {
	var xrayRules []M

	// Custom route rules (from Panel CustomRoutes or local config) have HIGHEST priority
	for _, cr := range customRules {
		xrayRules = append(xrayRules, M(cr))
	}

	xrayRules = append(xrayRules, M{
		"type": "field",
		"ip": []string{
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
		"outboundTag": "block",
	})

	for _, rule := range rules {
		if len(rule.Match) == 0 {
			continue
		}

		var ips, domains []string
		for _, m := range rule.Match {
			m = strings.TrimSpace(m)
			if m == "" {
				continue
			}
			if strings.HasPrefix(m, "geoip:") {
				ips = append(ips, m) // "geoip:cn" → ip field, passed as-is
			} else if strings.HasPrefix(m, "geosite:") {
				domains = append(domains, m) // "geosite:google" → domain field, passed as-is
			} else if strings.Contains(m, "/") {
				ips = append(ips, m)
			} else {
				m = strings.TrimPrefix(m, "*.")
				domains = append(domains, "domain:"+m)
			}
		}

		outbound := "block"
		if rule.Action == "direct" {
			outbound = "direct"
		} else if rule.Action == "proxy" && rule.ActionValue != "" {
			outbound = rule.ActionValue
		}

		if len(domains) > 0 {
			xrayRules = append(xrayRules, M{
				"type":        "field",
				"domain":      domains,
				"outboundTag": outbound,
			})
		}
		if len(ips) > 0 {
			xrayRules = append(xrayRules, M{
				"type":        "field",
				"ip":          ips,
				"outboundTag": outbound,
			})
		}
	}

	return M{
		"domainStrategy": "AsIs",
		"rules":          xrayRules,
	}
}
