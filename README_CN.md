# xboard-node

[English](README.md) | [中文文档](README_CN.md)

Xboard 面板专用节点后端，完全兼容 [Xboard](https://github.com/cedar2025/Xboard) API。

> **免责声明**：本项目仅供教育和学习目的使用。

## 安装

### 安装脚本

支持系统：Ubuntu 20+、Debian 11+、CentOS 8+、Alpine 3.18+

```bash
# 一键部署
bash install.sh -a https://panel.example.com -t YOUR_TOKEN -n 1

# 使用 xray 内核
bash install.sh -a https://panel.example.com -t YOUR_TOKEN -n 2 -k xray

# Docker 模式
bash install.sh -a https://panel.example.com -t YOUR_TOKEN -n 3 --docker

# 交互式安装
bash install.sh
```

**管理命令：**
```bash
bash install.sh list              # 列出所有节点
bash install.sh remove <node_id>  # 删除节点
bash install.sh update            # 更新并重启
bash install.sh uninstall         # 卸载所有
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

**1. 获取 `compose/` 目录**

```bash
git clone -b compose --depth 1 https://github.com/cedar2025/xboard-node.git
cd xboard-node
```

**2. 编辑本地配置**

```bash
vim config/config.yml
# 编辑 config/config.yml — 设置 panel.url、panel.token、panel.node_id
```

**3. 启动**

```bash
docker compose up -d
```

## 服务管理

### Systemd（Ubuntu/Debian/CentOS）

```bash
systemctl status xboard-node@1
journalctl -u xboard-node@1 -f
systemctl restart xboard-node@1
```

### OpenRC（Alpine Linux）

```bash
rc-service xboard-node-1 status
tail -f /var/log/xboard-node-1.log
rc-service xboard-node-1 restart
```

## 功能特性

- **双内核**：sing-box（默认）/ Xray-core
- **协议支持**：V2Ray、Trojan、Shadowsocks、Hysteria2、TUIC、Naive
- **速率限制**：内核级速率控制
- **实时同步**：WebSocket + REST 回退
- **多节点**：单服务器部署多个节点
- **服务管理**：systemd / OpenRC / Docker
- **开发友好**：单个 Go 二进制文件

## 配置

`config.yml`：
```yaml
panel:
  url: "https://panel.example.com"
  token: "your_token"
  node_id: 1

kernel:
  type: "singbox"  # singbox 或 xray
```

完整配置选项请查看 [config.yml.example](config.yml.example)。

## 许可证

MPL-2.0
