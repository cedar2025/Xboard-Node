# Custom Routes

## Quick Example

```json
{
  "custom_route_rules": [
    {
      "name": "direct-example",
      "match": {"domain_suffixes": ["example.com"]},
      "action": {"type": "direct"}
    },
    {
      "name": "block-ads",
      "match": {"domains": ["ads.example.com"]},
      "action": {"type": "block"}
    },
    {
      "name": "route-warp",
      "match": {"ip_cidrs": ["1.1.1.0/24"], "ports": ["80", "443"]},
      "action": {"type": "route", "target": "warp-out"}
    }
  ]
}
```

## Match Conditions

| Condition | Description | Example |
|-----------|-------------|---------|
| `domains` | Exact domain match | `["api.example.com"]` |
| `domain_suffixes` | Suffix match | `["example.com"]` |
| `ip_cidrs` | IP CIDR ranges | `["10.0.0.0/8"]` |
| `ports` | Port (single or range) | `["443", "8000-9000"]` |
| `networks` | Protocol | `["tcp"]` or `["udp"]` |
| `source_cidrs` | Source IP CIDR | `["192.168.1.0/24"]` |
| `source_ports` | Source port | `["1024-65535"]` |

## Action Types

| Action | Description |
|--------|-------------|
| `{"type": "direct"}` | Direct connection, bypass proxy |
| `{"type": "block"}` | Block connection |
| `{"type": "route", "target": "tag"}` | Route to specified outbound (by tag) |

## Application Order

1. Structured `custom_route_rules` (highest priority)
2. Raw `custom_routes`
3. Built-in blocklist rules
4. Panel routes

## Kernel Compatibility

| Feature | Xray | Sing-box | Mihomo |
|---------|------|----------|--------|
| All match conditions | ✅ | ✅ | ✅ |
| direct / block / route | ✅ | ✅ | ✅ |

## Best Practices

- **Prefer** `custom_route_rules`: cross-kernel compatible, panel-managed
- **Use** `custom_routes` only: when native features are needed (e.g., load balancing)
