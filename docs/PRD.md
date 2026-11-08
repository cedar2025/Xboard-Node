# XNode 产品与迭代记录

更新日期：2026-11-08。本文是项目交接入口，事实和测试结果以对应提交为准。

## 目标与范围

XNode 对接官方 Xboard 面板，保留面板推送和轮询的自动更新能力。落地机可在本地 `config.yml` 配置 Trojan TCP+TLS fallback；面板更新用户、节点端口、路由等数据时，本地 fallback 规则继续进入生成的内核配置。兼容性检查应拒绝把配置有 fallback 的节点改成非 Trojan、非 TCP 或 Reality，避免误以为 fallback 仍有效。

同时持续核对 Xray-core、sing-box 官方代码及 Xboard 面板接口，逐项升级、测试，不以版本号较新作为合并依据。

## 代码基线

- 本 fork：`PiPi-happy/XNode`，`dev` 分支，审查基线 `0a29338`。
- 上游节点后端：`cedar2025/Xboard-Node`，`dev` 分支，审查时 `618263a`。本 fork 已增加机器模式、证书、热更新等大量代码，不能直接用上游覆盖。
- 官方面板：`cedar2025/Xboard`，审查时默认分支 `d826a3b`。
- 当前 `go.mod`：Xray-core 声明 `v1.260327.0`，实际通过 `replace` 使用 `cedar2025/Xray-core` 的 `f479355`；sing-box 声明 `v1.13.2`，实际通过 `replace` 使用 `cedar2025/sing-box` 的 `2e665cb`（1.14.0 alpha 2 派生版）。因此不能只看 `require` 行判断运行内核版本。

## 迭代 1：本地 fallback

### 配置契约

```yaml
kernel:
  type: xray # 也支持 singbox
  fallbacks:
    - dest: "127.0.0.1:8080"
    - alpn: h2
      dest: "127.0.0.1:8082"
```

`dest` 必须是明确的 `host:port`；空 `alpn` 是默认目标。`http/1.1` 使用默认目标，`h2` 使用指定目标。每个 ALPN 只允许一条规则。Xray 使用 inbound `settings.fallbacks`；sing-box 使用 `fallback` 和 `fallback_for_alpn`。有 ALPN 规则时，TLS 会通告相应 ALPN；默认目标与 h2 共存时也通告 `http/1.1`。回落目标必须由独立的 HTTP 服务提供，XNode 不负责安装网站。sing-box 会为配置的回落目标生成优先直连规则；若目标是本机管理端口，已认证的代理用户也可能访问该端口，因此只应指向可公开访问的回落网站端口。

配置属于本地 `kernel`，不从 Xboard API 读取。顶层设置由多实例继承，静态多节点可通过 `nodes[].kernel.fallbacks` 覆盖。机器模式目前共用实例的规则；若同一机器上不同节点需要不同回落目标，应使用多个实例或后续增加按节点 ID 的映射。

### 验收标准

- 解析无效地址、端口或重复 ALPN 时拒绝启动。
- 面板推送或轮询更新兼容的 Trojan 节点后，生成的两种内核配置仍包含本地 fallback。
- 面板改为不兼容协议、传输或 Reality 时拒绝该更新，并保留已运行配置。
- HTTP/1.1 与 h2 的 HTTPS 请求分别到达本地目标；Trojan 正确用户仍能连接。

### 当前状态

- [x] 本地配置、双内核生成、兼容性校验与单元测试；两种实际内核的配置解析器均接受生成结果。
- [x] 本机真实连接集成测试：两种内核的 HTTP/1.1 与 h2 请求均到达预期回落服务，正确密码的 Trojan 连接也成功。测试命令：`go test -tags integration -timeout 30s ./internal/kernel/integration`。
- [ ] Linux 实机集成测试：浏览器 HTTP/1.1/h2、错误密码、正确密码、面板热更新。

## 迭代 2：内核与面板适配

### 已核对

- 官方 Xboard `ServerService::buildNodeConfig` 仍发送 `protocol`、`networkSettings`、`tls_settings`、`custom_outbounds`、`custom_routes`、`cert_config` 等字段；当前 `internal/panel/types.go` 可接收这些字段。
- 官方 Xboard 的机器节点接口使用 `POST /api/v2/server/machine/nodes`；fork 的机器模式代码已改为 POST。
- 官方 sing-box Trojan inbound 定义 `fallback` 和 `fallback_for_alpn`；官方 Xray-core Trojan/VLESS 定义 `fallbacks`。
- 官方 sing-box `v1.14.4` 替换当前 fork 时无法编译：缺少 `adapter.Router.UpdateRules`、`adapter.UpdatableInbound` 等 fork 专用热更新接口；需移植补丁或改写热更新后再升级。
- 官方 Xray-core Go 模块 `v1.260327.0` 替换当前 fork 时无法编译：缺少 `features/bandwidth`；需移植限速补丁或重做该能力后再升级。
- 当前 fork 的 CI 原用 Go 1.25.7（低于 `go.mod` 的 1.26）、发布和升级指向 `cedar2025`。已把 CI 工具链、镜像命名空间、安装脚本和 `xbctl` 下载地址改为本 fork。
- fork 的 PR 目标分支是 `dev`，原 CI 未监听该分支；Docker 发布任务也会在 PR 上尝试写入。已补上 `dev` PR 测试，并限定镜像发布只在 push 上运行。
- Xray Trojan 在证书自动启用 TLS 时曾修改传入的面板节点对象；已改为复制对象后生成配置，避免影响缓存的面板状态。
- sing-box 默认的私网地址阻断规则会把 `127.0.0.1` 回落也阻断；已增加只匹配配置目标和 Trojan inbound 的优先直连规则，并用真实 TLS 回落请求复验。

### 待完成的升级门槛

- [ ] 对照官方稳定版 sing-box 1.14.4，解决 fork 特有 API、依赖图和测试差异后升级。
- [ ] 对照官方 Xray-core 2026-10 系列；官方 Go 模块标签目前只列到 `v1.260327.0`，需确认目标 Git 提交、fork 特有补丁和模块兼容性。
- [ ] 用实际面板响应样本覆盖新协议、证书和路由字段的契约测试。
- [x] 本机 `go test ./...` 通过（Go 1.27.3，2026-11-08）。
- [x] CI 同款 `make test`（全仓 race 检测）通过；新增 `make test-integration` 作为 CI 第二项测试。
- [x] `go vet ./...`、Linux amd64 交叉编译（与 CI 相同构建标签）、`bash -n install.sh`、`git diff --check` 通过（2026-11-08）。
- [x] Linux arm64 交叉编译通过（与 CI 相同构建标签）。
- [ ] Linux 实机回归及 GitHub Actions 验证。

## 交接步骤

1. 阅读本文件、`config.yml.example` 和相关提交。
2. 确认当前 `go.mod` 的 `require` 与 `replace`，勿跳过 fork 差异直接删除替换。
3. 在独立分支升级一个内核，先编译和运行该内核测试，再运行全仓测试。
4. 用官方 Xboard 的实际 API 响应测试热更新，并在 Linux 节点验证 fallback 和代理连接。
5. 每次迭代更新本文的基线、结论、验证命令和未解决风险。

## 官方依据

- Xboard：<https://github.com/cedar2025/Xboard>
- xboard-node：<https://github.com/cedar2025/Xboard-Node>
- Xray fallback：<https://xtls.github.io/en/config/features/fallback.html>
- sing-box Trojan inbound：<https://sing-box.sagernet.org/configuration/inbound/trojan/>
