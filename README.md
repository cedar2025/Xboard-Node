# xboard-node

[English](README.md) | [中文文档](README_CN.md)

Dedicated node backend for [Xboard](https://github.com/cedar2025/Xboard). Fully compatible with Xboard API.

> **Disclaimer**: This project is for educational and learning purposes only.

## Install

### Install Script

Supports: Ubuntu 20+, Debian 11+, CentOS 8+, Alpine 3.18+

```bash
# One-command deploy
bash install.sh -a https://panel.example.com -t YOUR_TOKEN -n 1

# With xray kernel
bash install.sh -a https://panel.example.com -t YOUR_TOKEN -n 2 -k xray

# Docker mode
bash install.sh -a https://panel.example.com -t YOUR_TOKEN -n 3 --docker

# Interactive mode
bash install.sh
```

**Management:**
```bash
bash install.sh list              # List all nodes
bash install.sh remove <node_id>  # Remove a node
bash install.sh update            # Update binary and restart
bash install.sh uninstall         # Remove everything
```

### Docker

```bash
docker run -d --restart=always --network=host \
  -e apiHost=https://panel.example.com \
  -e apiKey=YOUR_TOKEN \
  -e nodeID=1 \
  ghcr.io/cedar2025/xboard-node:latest
```

### Docker Compose

**1. Get the `compose/` directory**

```bash
git clone -b compose --depth 1 https://github.com/cedar2025/xboard-node.git
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

## Service Management

### Systemd (Ubuntu/Debian/CentOS)

```bash
systemctl status xboard-node@1
journalctl -u xboard-node@1 -f
systemctl restart xboard-node@1
```

### OpenRC (Alpine Linux)

```bash
rc-service xboard-node-1 status
tail -f /var/log/xboard-node-1.log
rc-service xboard-node-1 restart
```

## Features

- **Kernels**: sing-box (default) / Xray-core
- **Protocols**: Full coverage (V2Ray, Trojan, SS, Hysteria2, TUIC, Naive)
- **Speed**: Kernel-level rate limiting
- **Sync**: Real-time WebSocket + REST fallback
- **Multi-Node**: Deploy multiple nodes on one server
- **Service**: systemd / OpenRC / Docker
- **Dev**: Single Go binary

## Configuration

`config.yml`:
```yaml
panel:
  url: "https://panel.example.com"
  token: "your_token"
  node_id: 1

kernel:
  type: "singbox"  # singbox or xray
```

See [config.yml.example](config.yml.example) for all options.

## License

MPL-2.0

