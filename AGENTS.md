# xboard-node — Agent Instructions

## Repo overview

Go 1.26 monorepo. Two binaries, three kernels.

- `cmd/xboard-node` — main daemon. Entry: `cmd/xboard-node/main.go`
- `cmd/xbctl` — CLI management tool. Entry: `cmd/xbctl/main.go`
- `internal/kernel/` — kernel adapters: `singbox/`, `xray/`, `mihomo/`
- `internal/machine/` — machine-mode orchestrator (single instance)
- `internal/service/` — node-mode service (spawned per node)
- `internal/config/` — config loading, normalization, hot-reload watcher
- `internal/panel/` — panel API client + WebSocket
- `internal/controlplane/` — inbound listener management
- `internal/cert/` — TLS certificate management (HTTP/DNS-01)
- `internal/limiter/` — per-user speed limiting + traffic tracking
- `internal/tracker/` — alive-IP tracking
- `internal/monitor/` — health monitoring
- `internal/model/` — data types + validation

Three kernels are embedded as Go libraries (not external processes). The `go.mod` uses `replace` directives to use patched forks of `sing-box`, `xray-core`, and `mihomo`.

## Commands

```bash
make build                     # build xboard-node + xbctl (current platform)
make build-linux               # cross-compile linux/amd64
make build-linux-arm64         # cross-compile linux/arm64
make build-all                 # both linux targets
make test                      # go test -v -race -count=1 ./internal/...
make clean                     # remove build artifacts
make install                   # build + copy to /usr/local/bin, install example config
make docker                    # build Docker image
```

Build tags required for full feature set: `with_quic with_utls with_wireguard with_acme with_clash_api`

Tests: `make test` runs all `./internal/...` tests with race detector. No test framework beyond `go test`. Benchmarks are in files matching `*_bench_test.go` (gitignored).

## Gotchas

- **Config file**: `config.yml` is gitignored. Copy from `config.yml.example` or run `make install`.
- **Sing-box fork**: The `go.mod` replaces `github.com/sagernet/sing-box` with `github.com/cedar2025/sing-box` — do not assume upstream sing-box APIs are stable.
- **Xray fork**: Similarly replaced with `github.com/cedar2025/Xray-core`.
- **Mihomo fork**: Replaced with `github.com/Fearless743/mihomo`.
- **Multi-instance**: A single config can define multiple panel bindings via `instances:`. The daemon spawns one service per node or one machine orchestrator per instance.
- **Hot reload**: Config changes trigger a full restart of all instances (SIGINT → graceful shutdown → re-parse → restart).
- **Health endpoint**: `/healthz` on configurable port (default 65530). Port 0 disables it.
- **Environment variables**: Panel config can be supplied entirely via env vars (`API_HOST`, `API_KEY`, `NODE_ID`, `KERNEL`, `DOMAIN`, `CERT_FILE`, `KEY_FILE`, `LOG_LEVEL`) — no config file needed.
- **Release flow**: Tag pushes trigger CI release. `dev` branch auto-releases on binary changes (detected by `cmd/`, `internal/`, `go.mod`, `go.sum`). Version bump is conventional-commits-based (`feat`→minor, `fix`/`perf`→patch, `breaking!`→major).
- **Docker**: Uses `--network=host` by default. Alpine-based multi-stage build.
- **Installer**: `install.sh` supports `systemd` and `openrc`. Requires root. Has rollback on failure.

## Extension docs

- Custom routes: `docs-custom-routes.md`
- Custom outbounds: `docs-custom-outbounds.md`
- DNS providers (ACME): `docs-dns-providers.md`
- Mihomo kernel specifics: `docs-mihomo-kernel.md`
