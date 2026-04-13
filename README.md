# xboard-node

Dedicated node backend for [Xboard](https://github.com/cedar2025/Xboard). Fully compatible with Xboard API.

> **Disclaimer**: This project is for educational and learning purposes only.

## Install

### Docker
```bash
docker run -d --restart=always --network=host \
  -e apiHost=https://panel.com \
  -e apiKey=TOKEN \
  -e nodeID=1 \
  ghcr.io/xusenhao/xboard-node:latest
```

### Docker Compose

**1. Get the `compose/` directory**

```bash
git clone -b compose --depth 1 https://github.com/xusenhao/xboard-node.git
cd xboard-node
```


**2. Edit local config**

```bash
vim config/config.yml
# edit config/config.yml — set panel.url, panel.token, panel.node_id
```

**3. Start**

```bash
docker compose up -d
```

## Features

- **Kernels**: sing-box (default) / Xray-core.
- **Protocols**: Full coverage (V2Ray, Trojan, SS, Hysteria2, TUIC, Naive).
- **Speed**: Kernel-level rate limiting.
- **Sync**: Real-time WebSocket + REST fallback.
- **Dev**: Single Go binary.

## Configuration

`config.yml`:
```yaml
panel:
  url: "https://panel.com"
  token: "token"
  node_id: 1
```

## License

MPL-2.0.

