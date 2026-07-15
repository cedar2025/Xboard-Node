# Mihomo Kernel

Xboard-Node 支持 [mihomo](https://github.com/MetaCubeX/mihomo)（原 Clash.Meta）作为第三种内核后端，与 xray-core 和 sing-box 并列。

## Quick Start

在 `config.yml` 中设置 `kernel.type`：

```yaml
kernel:
  type: mihomo
  config_dir: /etc/xboard-node/mihomo
```

面板节点的 `kernel_type` 字段设为 `mihomo`，或在 machine 模式下通过面板 UI 选择。

## Supported Protocols

| Protocol | Mihomo | Xray | Sing-box |
|----------|--------|------|----------|
| vmess | ✅ | ✅ | ✅ |
| vless | ✅ | ✅ | ✅ |
| trojan | ✅ | ✅ | ✅ |
| shadowsocks | ✅ | ✅ | ✅ |
| hysteria2 | ✅ | ❌ | ✅ |
| tuic | ✅ | ❌ | ✅ |
| wireguard | ✅ | ✅ | ✅ |
| hysteria | ✅ | ❌ | ✅ |
| anytls | ✅ | ❌ | ✅ |
| mieru | ✅ | ❌ | ✅ |
| trusttunnel | ✅ | ❌ | ❌ |
| sudoku | ✅ | ❌ | ❌ |
| naive | ❌ | ❌ | ✅ |

## Capabilities

| Feature | Mihomo | Xray | Sing-box |
|---------|--------|------|----------|
| Per-user speed limit | ❌ | ✅ | ✅ |
| Device limit | ❌ | ✅ | ✅ |
| Built-in traffic stats | ✅ | ✅ | ❌ |
| Alive IP tracking | ✅ | ❌ | ✅ |
| Force close connection | ✅ | ✅ | ❌ |
| Force close user | ✅ | ❌ | ✅ |

> Per-user speed limit 和 device limit 由 Xboard-Node 框架层统一处理，不依赖内核原生支持。

## Transport Layers

| Transport | Mihomo | Notes |
|-----------|--------|-------|
| tcp | ✅ | Default |
| ws | ✅ | WebSocket |
| grpc | ✅ | gRPC |
| h2 | ✅ | HTTP/2 |
| quic | ✅ | QUIC |
| xhttp | ❌ | Xray-only |
| splithttp | ❌ | Xray-only |

## TLS Configuration

Mihomo 支持三种 TLS 模式：

| Mode | `tls` value | Description |
|------|-------------|-------------|
| Off | `0` | No TLS |
| Standard | `1` | Standard TLS with cert/key |
| Reality | `2` | Reality protocol |

证书通过面板的 cert 系统自动管理，PEM 内容由框架注入，内核自动写入临时文件并在停止时清理。

### Reality

Reality 配置通过 `tls_settings` 传递：

```json
{
  "tls": 2,
  "tls_settings": {
    "dest": "www.microsoft.com:443",
    "private_key": "...",
    "short_ids": ["abc123"],
    "server_names": ["sni.example.com"]
  }
}
```

## User Management

Mihomo 支持 **非中断式用户更新**（zero-disruption）。对于 VMess、VLESS、Hysteria2 协议，用户增删改操作不会中断现有连接：

| Protocol | User Update | Behavior |
|----------|-------------|----------|
| vmess | ✅ Hot-swap | Zero disruption |
| vless | ✅ Hot-swap | Zero disruption |
| hysteria2 | ✅ Hot-swap | Zero disruption |
| anytls | ✅ Hot-swap | Zero disruption |
| mieru | ✅ Hot-swap | Zero disruption |
| trojan | ❌ Rebuild | Brief disruption (< 1s) |
| shadowsocks | ❌ Rebuild | Brief disruption (< 1s) |
| trusttunnel | ❌ Rebuild | Brief disruption (< 1s) |

这通过 mihomo 的 `UpdatableInboundListener` 接口实现，与 sing-box 的 `UpdatableInbound` 模式一致。

## Traffic Tracking

Mihomo 内核提供原生 per-user 流量追踪：

- **Per-user bytes**: 每个用户的上传/下载累计字节数，从活跃连接的 atomic 计数器实时聚合
- **Alive IPs**: 每个用户的当前连接源 IP 集合，通过 refcounted map 维护
- **Connection count**: 全局活跃连接总数

流量数据通过 mihomo 的 `statistic.Manager.GetUserTraffic()` API 获取，O(N) 遍历所有活跃连接（面板轮询频率低，无性能问题）。

## Custom Outbounds

Mihomo 支持以下出站协议（通过面板 `custom_outbounds` 配置）：

| Protocol | Mihomo |
|----------|--------|
| vmess | ✅ |
| vless | ✅ |
| trojan | ✅ |
| shadowsocks | ✅ |
| socks | ✅ |
| http | ✅ |
| wireguard | ✅ |
| tuic | ✅ |
| hysteria2 | ✅ |
| anytls | ✅ |
| mieru | ✅ |

## Custom Routes

Mihomo 支持与 xray/sing-box 相同的路由规则格式：

```json
{
  "custom_route_rules": [
    {
      "name": "direct-china",
      "match": {"domain_suffixes": [".cn"]},
      "action": {"type": "direct"}
    },
    {
      "name": "block-ads",
      "match": {"domains": ["ads.example.com"]},
      "action": {"type": "block"}
    }
  ]
}
```

| Matcher | Mihomo |
|---------|--------|
| domains | ✅ |
| domain_suffixes | ✅ |
| ip_cidrs | ✅ |
| ports | ✅ |
| networks | ✅ |
| source_cidrs | ✅ |
| source_ports | ✅ |

## GeoData

Mihomo 使用与 xray 相同格式的 geo 数据文件（`.dat`）。首次启动时自动下载到 `config_dir`：

- `geoip.dat` — IP 地理位置数据库
- `geosite.dat` — 域名分类数据库

## Architecture

Mihomo 内核作为 Go library 嵌入 Xboard-Node，而非外部进程：

```
Xboard-Node
├── internal/kernel/mihomo/       ← 内核适配器
│   ├── mihomo.go                 ← Kernel 接口实现
│   └── config.go                 ← NodeSpec → mihomo YAML 配置生成
└── (imports github.com/metacubex/mihomo)
    ├── hub.Parse()               ← 配置加载
    ├── listener/                 ← 协议监听器
    ├── tunnel/statistic/         ← Per-user 流量追踪
    └── hub/executor/             ← 配置应用
```

### Config Generation Flow

```
NodeSpec + UserSpec + TLSCert
        ↓
  buildMihomoYAML()
        ↓
  mihomo YAML string
        ↓
  hub.Parse(yaml)
        ↓
  PatchInboundListeners()
        ↓
  ┌─ UpdatableInboundListener? → UpdateUsers() → zero disruption
  └─ Otherwise → Close() + Listen() → brief disruption
```

## Known Limitations

1. **Trojan/Shadowsocks/TrustTunnel 用户更新需要重建 listener** — 单密码模型无法增量更新，但中断时间 < 1s
2. **不支持 xhttp/splithttp 传输** — 这些是 xray 专有传输层
3. **不支持 naive 协议** — 这是 sing-box 专有协议
4. **Per-user 限速/设备限制由框架层处理** — 不依赖 mihomo 原生实现

## Example Config

完整的 `config.yml` 示例：

```yaml
panel:
  url: https://panel.example.com
  token: YOUR_TOKEN

node:
  id: 1

kernel:
  type: mihomo
  config_dir: /etc/xboard-node/mihomo
  log_level: info

cert:
  cert_mode: http
  domain: node.example.com
```
