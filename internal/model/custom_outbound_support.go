package model

func OutboundSupportMatrix() map[string]KernelOutboundSupport {
	return map[string]KernelOutboundSupport{
		"xray": {
			Protocols: []string{
				"vmess",
				"vless",
				"trojan",
				"shadowsocks",
				"socks",
				"http",
				"wireguard",
			},
			Features: []string{
				"tag",
				"protocol",
				"settings",
				"proxy_tag",
			},
		},
		"singbox": {
			Protocols: []string{
				"vmess",
				"vless",
				"trojan",
				"shadowsocks",
				"socks",
				"http",
				"wireguard",
				"tuic",
				"hysteria2",
				"anytls",
				"naive",
				"mieru",
				"direct",
			},
			Features: []string{
				"tag",
				"protocol",
				"settings",
				"proxy_tag",
			},
		},
	}
}

type KernelOutboundSupport struct {
	Protocols []string
	Features  []string
}
