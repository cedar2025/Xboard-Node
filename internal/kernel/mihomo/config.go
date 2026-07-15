package mihomo

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
)

// M is a shorthand for building JSON-like maps (same convention as singbox kernel).
type M = map[string]interface{}

// buildMihomoConfig generates a complete mihomo config as JSON bytes from the
// given node spec, user set, and TLS certificate. Uses map[string]interface{}
// approach (same as singbox kernel), no YAML dependency.
func buildMihomoConfig(
	nodeConfig *model.NodeSpec,
	users []model.UserSpec,
	tls kernel.TLSCert,
	certDir string,
) (config []byte, certFiles []string, err error) {
	// Write TLS cert/key to temp files if provided.
	var certFile, keyFile string
	if tls.HasCert() {
		certFile = filepath.Join(certDir, "xboard_cert.pem")
		keyFile = filepath.Join(certDir, "xboard_key.pem")
		if err = os.WriteFile(certFile, tls.CertPEM, 0600); err != nil {
			return nil, nil, fmt.Errorf("write cert: %w", err)
		}
		if err = os.WriteFile(keyFile, tls.KeyPEM, 0600); err != nil {
			return nil, nil, fmt.Errorf("write key: %w", err)
		}
		certFiles = []string{certFile, keyFile}
	}

	cfg := M{
		"allow-lan":   false,
		"bind-address": "*",
		"mode":        "rule",
		"log-level":   logLevel(nodeConfig.KernelLogLevel),
		"ipv6":        false,
		"listeners": []M{
			buildListener(nodeConfig, users, certFile, keyFile),
		},
		"outbounds": buildOutbounds(nodeConfig),
		"rules":     buildRules(nodeConfig),
	}

	jsonBytes, err := json.Marshal(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal config: %w", err)
	}
	return jsonBytes, certFiles, nil
}

func logLevel(level string) string {
	switch level {
	case "debug", "DEBUG":
		return "debug"
	case "warning", "WARNING", "warn", "WARN":
		return "warning"
	case "error", "ERROR":
		return "error"
	case "silent", "SILENT":
		return "silent"
	default:
		return "info"
	}
}

func userUID(u model.UserSpec) string {
	return "uid_" + strconv.Itoa(u.ID)
}

// ─── Listener ──────────────────────────────────────────────────────

func buildListener(nc *model.NodeSpec, users []model.UserSpec, certFile, keyFile string) M {
	l := M{
		"name":   "xboard-in",
		"type":   nc.Protocol,
		"listen": listenAddr(nc.ListenIP),
		"port":   nc.ServerPort,
		"udp":    true,
	}

	switch nc.Protocol {
	case "vmess":
		l["users"] = buildVMessUsers(users)
		mergeMap(l, buildTransport(nc))
		mergeMap(l, buildTLS(certFile, keyFile, nc))
	case "vless":
		l["users"] = buildVlessUsers(users, nc)
		mergeMap(l, buildTransport(nc))
		mergeMap(l, buildTLS(certFile, keyFile, nc))
	case "trojan":
		l["users"] = buildTrojanUsers(users)
		mergeMap(l, buildTransport(nc))
		mergeMap(l, buildTLS(certFile, keyFile, nc))
	case "shadowsocks":
		mergeMap(l, buildShadowsocks(nc))
	case "hysteria2", "hysteria":
		l["users"] = buildHysteria2Users(users)
		mergeMap(l, buildHysteria2Config(nc, certFile, keyFile))
	case "tuic":
		l["users"] = buildTuicUsers(users)
		mergeMap(l, buildTuicConfig(nc, certFile, keyFile))
	case "anytls":
		l["users"] = buildAnyTLSUsers(users)
		mergeMap(l, buildAnyTLSConfig(nc, certFile, keyFile))
	case "mieru":
		l["users"] = buildMieruUsers(users)
		mergeMap(l, buildMieruConfig(nc))
	case "trusttunnel":
		l["users"] = buildTrustTunnelUsers(users)
		mergeMap(l, buildTrustTunnelConfig(nc, certFile, keyFile))
	case "sudoku":
		mergeMap(l, buildSudokuConfig(nc))
	default:
		l["users"] = buildVMessUsers(users)
	}

	return l
}

func listenAddr(ip string) string {
	if ip == "" || ip == "0.0.0.0" {
		return "::"
	}
	return ip
}

// ─── Protocol-specific user builders ────────────────────────────────

func buildVMessUsers(users []model.UserSpec) []M {
	out := make([]M, 0, len(users))
	for _, u := range users {
		out = append(out, M{
			"username": userUID(u),
			"uuid":     u.UUID,
		})
	}
	return out
}

func buildVlessUsers(users []model.UserSpec, nc *model.NodeSpec) []M {
	out := make([]M, 0, len(users))
	for _, u := range users {
		entry := M{
			"username": userUID(u),
			"uuid":     u.UUID,
		}
		if nc.Flow != "" {
			entry["flow"] = nc.Flow
		}
		out = append(out, entry)
	}
	return out
}

func buildTrojanUsers(users []model.UserSpec) []M {
	out := make([]M, 0, len(users))
	for _, u := range users {
		out = append(out, M{
			"username": userUID(u),
			"password": u.UUID,
		})
	}
	return out
}

func buildShadowsocks(nc *model.NodeSpec) M {
	m := M{}
	if nc.Cipher != "" {
		m["cipher"] = nc.Cipher
	}
	if nc.ServerKey != "" {
		m["password"] = nc.ServerKey
	}
	if nc.Plugin != "" {
		m["plugin"] = nc.Plugin
		if nc.PluginOpt != "" {
			m["plugin-opts"] = nc.PluginOpt
		}
	}
	return m
}

func buildHysteria2Users(users []model.UserSpec) M {
	out := make(M, len(users))
	for _, u := range users {
		out[userUID(u)] = u.UUID
	}
	return out
}

func buildHysteria2Config(nc *model.NodeSpec, certFile, keyFile string) M {
	m := M{}
	if nc.Obfs != "" {
		m["obfs"] = nc.Obfs
		if nc.ObfsPassword != "" {
			m["obfs-password"] = nc.ObfsPassword
		}
	}
	if nc.UpMbps > 0 {
		m["up"] = strconv.Itoa(nc.UpMbps) + " Mbps"
	}
	if nc.DownMbps > 0 {
		m["down"] = strconv.Itoa(nc.DownMbps) + " Mbps"
	}
	if certFile != "" {
		m["certificate"] = certFile
		m["private-key"] = keyFile
	}
	return m
}

func buildTuicUsers(users []model.UserSpec) []M {
	out := make([]M, 0, len(users))
	for _, u := range users {
		out = append(out, M{
			"username": userUID(u),
			"uuid":     u.UUID,
			"password": u.UUID,
		})
	}
	return out
}

func buildTuicConfig(nc *model.NodeSpec, certFile, keyFile string) M {
	m := M{
		"max-idle-time":          15000,
		"authentication-timeout": 1000,
		"alpn":                   []string{"h3"},
	}
	if nc.CongestionControl != "" {
		m["congestion-controller"] = nc.CongestionControl
	}
	if certFile != "" {
		m["certificate"] = certFile
		m["private-key"] = keyFile
	}
	return m
}

func buildAnyTLSUsers(users []model.UserSpec) []M {
	out := make([]M, 0, len(users))
	for _, u := range users {
		out = append(out, M{
			"name":     userUID(u),
			"password": u.UUID,
		})
	}
	return out
}

func buildAnyTLSConfig(nc *model.NodeSpec, certFile, keyFile string) M {
	m := M{}
	if certFile != "" {
		m["certificate"] = certFile
		m["private-key"] = keyFile
	}
	if ps := getString(nc.NetworkSettings, "padding_scheme"); ps != "" {
		m["padding-scheme"] = ps
	}
	return m
}

func buildMieruUsers(users []model.UserSpec) []M {
	out := make([]M, 0, len(users))
	for _, u := range users {
		out = append(out, M{
			"name":     userUID(u),
			"password": u.UUID,
		})
	}
	return out
}

func buildMieruConfig(nc *model.NodeSpec) M {
	m := M{}
	if nc.Transport != "" {
		m["transport"] = nc.Transport
	}
	if nc.TrafficPattern != "" {
		m["traffic_pattern"] = nc.TrafficPattern
	}
	return m
}

func buildTrustTunnelUsers(users []model.UserSpec) []M {
	out := make([]M, 0, len(users))
	for _, u := range users {
		out = append(out, M{
			"name":     userUID(u),
			"password": u.UUID,
		})
	}
	return out
}

func buildTrustTunnelConfig(nc *model.NodeSpec, certFile, keyFile string) M {
	m := M{}
	if len(nc.TrustTunnelNetwork) > 0 {
		m["network"] = nc.TrustTunnelNetwork
	}
	if nc.TrustTunnelCongestionController != "" {
		m["congestion-controller"] = nc.TrustTunnelCongestionController
	}
	if nc.TrustTunnelCWND > 0 {
		m["cwnd"] = nc.TrustTunnelCWND
	}
	if nc.TrustTunnelBBRProfile != "" {
		m["bbr-profile"] = nc.TrustTunnelBBRProfile
	}
	if certFile != "" {
		m["certificate"] = certFile
		m["private-key"] = keyFile
	}
	return m
}

func buildSudokuConfig(nc *model.NodeSpec) M {
	m := M{}
	if nc.ServerKey != "" {
		m["key"] = nc.ServerKey
	}
	if sc := nc.SudokuConfig; sc != nil {
		if sc.AEADMethod != "" {
			m["aead-method"] = sc.AEADMethod
		}
		if sc.PaddingMin != nil {
			m["padding-min"] = *sc.PaddingMin
		}
		if sc.PaddingMax != nil {
			m["padding-max"] = *sc.PaddingMax
		}
		if sc.TableType != "" {
			m["table-type"] = sc.TableType
		}
		if sc.HTTPMaskMode != "" {
			m["http-mask-mode"] = sc.HTTPMaskMode
		}
	}
	return m
}

// ─── Transport layer ────────────────────────────────────────────────

func buildTransport(nc *model.NodeSpec) M {
	if nc.Network == "" || nc.Network == "tcp" {
		return nil
	}
	m := M{}
	ns := nc.NetworkSettings

	switch nc.Network {
	case "ws":
		if path := getString(ns, "path"); path != "" {
			m["ws-path"] = path
		}
		if headers := getMap(ns, "headers"); len(headers) > 0 {
			h := M{}
			for k, v := range headers {
				h[k] = fmt.Sprint(v)
			}
			m["ws-headers"] = h
		}
	case "grpc":
		if name := getString(ns, "serviceName"); name != "" {
			m["grpc-service-name"] = name
		}
	case "h2":
		if path := getString(ns, "path"); path != "" {
			m["h2-path"] = path
		}
		if host := getString(ns, "host"); host != "" {
			m["h2-host"] = host
		}
	}
	return m
}

// ─── TLS ────────────────────────────────────────────────────────────

func buildTLS(certFile, keyFile string, nc *model.NodeSpec) M {
	m := M{}
	if certFile != "" {
		m["certificate"] = certFile
		m["private-key"] = keyFile
	}
	if nc.TLS == 2 {
		reality := buildRealityConfig(nc)
		if len(reality) > 0 {
			m["reality-config"] = reality
		}
	}
	return m
}

func buildRealityConfig(nc *model.NodeSpec) M {
	ts := nc.TLSSettings
	if ts == nil {
		return nil
	}
	m := M{}
	if dest, ok := ts["dest"].(string); ok && dest != "" {
		m["dest"] = dest
	}
	if privateKey, ok := ts["private_key"].(string); ok && privateKey != "" {
		m["private-key"] = privateKey
	}
	if shortIDs, ok := ts["short_ids"].([]any); ok && len(shortIDs) > 0 {
		ids := make([]string, 0, len(shortIDs))
		for _, sid := range shortIDs {
			ids = append(ids, fmt.Sprint(sid))
		}
		m["short-id"] = ids
	}
	if serverNames, ok := ts["server_names"].([]any); ok && len(serverNames) > 0 {
		names := make([]string, 0, len(serverNames))
		for _, sn := range serverNames {
			names = append(names, fmt.Sprint(sn))
		}
		m["server-names"] = names
	}
	if maxTime, ok := ts["max_time_diff"].(float64); ok && maxTime > 0 {
		m["max-time-difference"] = int(maxTime)
	}
	return m
}

// ─── Outbounds ──────────────────────────────────────────────────────

func buildOutbounds(nc *model.NodeSpec) []M {
	out := []M{
		{"name": "direct", "type": "direct"},
		{"name": "block", "type": "block"},
	}
	for _, ob := range nc.CustomOutbounds {
		entry := M{
			"name":     ob.Tag,
			"type":     ob.Protocol,
		}
		for k, v := range ob.Settings {
			entry[k] = v
		}
		out = append(out, entry)
	}
	return out
}

// ─── Rules ──────────────────────────────────────────────────────────

func buildRules(nc *model.NodeSpec) []string {
	if len(nc.Routes) == 0 && len(nc.CustomRouteRules) == 0 {
		return []string{"MATCH,DIRECT"}
	}

	rules := make([]string, 0)

	for _, rule := range nc.CustomRouteRules {
		if rule.Disabled {
			continue
		}
		action := rule.Action.Type
		switch action {
		case "block":
			action = "REJECT"
		case "direct":
			action = "DIRECT"
		case "route":
			action = rule.Action.Target
		}
		for _, domain := range rule.Match.Domains {
			rules = append(rules, "DOMAIN,"+domain+","+action)
		}
		for _, suffix := range rule.Match.DomainSuffixes {
			rules = append(rules, "DOMAIN-SUFFIX,"+suffix+","+action)
		}
		for _, cidr := range rule.Match.IPCIDRs {
			rules = append(rules, "IP-CIDR,"+cidr+","+action)
		}
	}

	for _, rule := range nc.Routes {
		for _, match := range rule.Match {
			rules = append(rules, match+","+rule.ActionValue)
		}
	}

	if len(rules) == 0 {
		return []string{"MATCH,DIRECT"}
	}
	rules = append(rules, "MATCH,DIRECT")
	return rules
}

// ─── Helpers ────────────────────────────────────────────────────────

func mergeMap(dst M, src M) {
	for k, v := range src {
		dst[k] = v
	}
}

func getString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok {
		return fmt.Sprint(v)
	}
	return ""
}

func getMap(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	if v, ok := m[key]; ok {
		if result, ok := v.(map[string]any); ok {
			return result
		}
	}
	return nil
}
