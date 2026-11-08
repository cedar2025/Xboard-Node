# XNode

[English](README.md) · 简体中文

XNode 是适配[官方 Xboard 面板](https://github.com/cedar2025/Xboard)的节点后端 fork，内置 Xray-core 和 sing-box 两种内核。支持面板 WebSocket 推送与 REST 轮询，面板更新用户、路由等配置后，后端会自动同步。

## 主要功能

- 支持 Trojan、VLESS、VMess、Shadowsocks、Hysteria2、TUIC、AnyTLS 等协议；具体可用协议取决于所选内核。
- 支持单节点、机器模式、独立模式，以及一个进程管理多个实例。
- 支持用户限速、设备限制、在线 IP 统计和用户热更新。
- 支持在**本机配置文件**中为 Trojan TCP+TLS 设置 fallback；面板下发的配置不会覆盖这些规则。

## 安装

Linux systemd 单节点模式：

```bash
curl -fsSL https://raw.githubusercontent.com/PiPi-happy/XNode/dev/install.sh | \
  sudo bash -s -- --mode node --panel https://panel.example.com --token TOKEN --node-id 1
```

机器模式：

```bash
curl -fsSL https://raw.githubusercontent.com/PiPi-happy/XNode/dev/install.sh | \
  sudo bash -s -- --mode machine --panel https://panel.example.com --token TOKEN --machine-id 1
```

安装脚本默认下载本仓库的 `dev` Release。正式部署可传入 `--version <版本标签>` 固定版本。Docker 镜像为 `ghcr.io/pipi-happy/xnode:latest`；如需本地 fallback，请将配置文件挂载到容器内 `/etc/xboard-node/config.yml`。

## 本地 fallback 配置

在节点机器的 `config.yml` 中加入：

```yaml
kernel:
  type: xray # 也可用 singbox
  fallbacks:
    - dest: "127.0.0.1:8080"
    - alpn: h2
      dest: "127.0.0.1:8082"
```

本机需分别准备监听 8080 的 HTTP/1.1 服务和监听 8082、支持 h2c 的服务。XNode 负责将非 Trojan 流量转发到这些目标，不会安装或管理网站。`dest` 必须写明地址和端口；同一 ALPN 不能重复。

面板更新用户或兼容的节点参数时，本地 fallback 仍会生效。若面板把节点改成非 Trojan、非 TCP 或 Reality，后端会拒绝该不兼容更新。机器模式下，同一实例管理的节点共用本地 fallback 规则；不同节点需要不同目标时，可使用多个实例。

注意：sing-box 会为配置的 fallback 目标生成优先直连规则。回落目标应是可公开访问的网站服务，不要指向本机管理后台端口。

## 运维与开发

安装后可运行 `xbctl` 查看帮助；常用命令：

```bash
xbctl list
xbctl status
xbctl service restart
```

配置示例见 [`config.yml.example`](config.yml.example)。设计、测试结果、内核升级限制和后续事项见[项目 PRD](docs/PRD.md)。

## 许可证

MPL-2.0。
