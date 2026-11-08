# XNode

[简体中文说明](README.zh-CN.md) · English

Fork of xboard-node for the official [Xboard](https://github.com/cedar2025/Xboard) panel. Supports `sing-box` / `xray-core` dual kernels.

> **Disclaimer**: This project is for educational and learning purposes only.

## Features

- Protocols: V2Ray family, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS
- Sync: WebSocket push + REST polling dual channel
- User controls: speed limit, device limit, alive-IP tracking, hot update
- Deploy modes: node mode, machine mode, standalone mode
- Multi-instance: single process binding multiple panels / nodes

## Install

### Docker

```bash
docker run -d --restart=always --network=host \
  -e apiHost=https://panel.com -e apiKey=TOKEN -e nodeID=1 \
  ghcr.io/pipi-happy/xnode:latest
```

The fork image is published by this repository's CI. Mount a local `config.yml` into
`/etc/xboard-node/config.yml` when using `kernel.fallbacks`.

### Installer (Linux systemd)

```bash
# Node mode
curl -fsSL https://raw.githubusercontent.com/PiPi-happy/XNode/dev/install.sh | \
  sudo bash -s -- --mode node --panel https://panel.example.com --token TOKEN --node-id 1

# Machine mode
curl -fsSL https://raw.githubusercontent.com/PiPi-happy/XNode/dev/install.sh | \
  sudo bash -s -- --mode machine --panel https://panel.example.com --token TOKEN --machine-id 1
```

The installer downloads this fork's `dev` release by default. For reproducible
deployments, pass `--version <release-tag>` after publishing a tagged release.

## xbctl

Run `xbctl` after installation for help. Common commands:

```bash
xbctl list                          # list all instances
xbctl status                        # running status
xbctl bind add-node --panel URL --token TOKEN --node-id 1
xbctl bind add-machine --panel URL --token TOKEN --machine-id 1
xbctl bind remove-node --panel URL --node-id 1
xbctl service restart
```

## Configuration

Legacy single-panel config is fully compatible. Appending bindings auto-migrates to `instances` format. See `config.yml.example`.

Local Trojan TCP+TLS fallback is configured only in `config.yml`, never from panel data:

```yaml
kernel:
  type: xray # or singbox
  fallbacks:
    - dest: "127.0.0.1:8080"
    - alpn: h2
      dest: "127.0.0.1:8082"
```

Run a local HTTP/1.1 service on 8080 and an h2c-capable service on 8082. The
fallback rules survive compatible panel updates. Switching the node away from
Trojan TCP+TLS is rejected while local fallbacks are enabled. See [PRD](docs/PRD.md).

## Extensions

- Custom routes: [docs-custom-routes.md](docs-custom-routes.md)
- Custom outbounds: [docs-custom-outbounds.md](docs-custom-outbounds.md)
- DNS providers (ACME DNS-01): [docs-dns-providers.md](docs-dns-providers.md)

## License

MPL-2.0.
