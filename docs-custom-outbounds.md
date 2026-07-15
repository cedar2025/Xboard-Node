# Custom Outbounds

## Quick Example

```json
{
  "custom_outbounds": [
    {
      "tag": "warp",
      "protocol": "wireguard",
      "settings": {
        "peers": [{"address": "162.159.195.1"}],
        "private_key": "aMzA..."
      }
    },
    {
      "tag": "us-proxy",
      "protocol": "socks",
      "settings": {"servers": [{"address": "1.2.3.4", "port": 1080}]},
      "proxy_tag": "warp"
    }
  ]
}
```

## Supported Protocols

| Protocol | Xray | Sing-box | Mihomo |
|----------|------|----------|--------|
| vmess | ✅ | ✅ | ✅ |
| vless | ✅ | ✅ | ✅ |
| trojan | ✅ | ✅ | ✅ |
| shadowsocks | ✅ | ✅ | ✅ |
| socks | ✅ | ✅ | ✅ |
| http | ✅ | ✅ | ✅ |
| wireguard | ✅ | ✅ | ✅ |
| tuic | ❌ | ✅ | ✅ |
| hysteria2 | ❌ | ✅ | ✅ |
| anytls | ❌ | ✅ | ❌ |
| naive | ❌ | ✅ | ❌ |
| mieru | ❌ | ✅ | ❌ |

## Core Fields

| Field | Required | Description |
|-------|----------|-------------|
| `tag` | ✅ | Outbound tag, referenced in routes |
| `protocol` | ✅ | Protocol type |
| `settings` | ✅ | Protocol-specific configuration |
| `proxy_tag` | ❌ | Chain to another outbound (references its tag) |

## Best Practices

- **Prefer** `custom_outbounds`: panel-managed, cross-kernel compatible
- **Use** `kernel.custom_outbound` only: when native fields are needed
