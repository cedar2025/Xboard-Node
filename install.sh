#!/usr/bin/env bash
# xboard-node installer with OpenRC support.
# Detects the running init system and installs either an OpenRC service
# (Alpine, Gentoo, Devuan, Artix, ...) or the original systemd unit.
if [ -z "${BASH_VERSION:-}" ]; then
    echo "This installer requires bash. On Alpine: apk add bash" >&2
    exit 1
fi
set -Eeuo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

APP_NAME="xboard-node"
INSTALL_ROOT="/etc/xboard-node"
BACKUP_DIR="${INSTALL_ROOT}/backups"
INSTALL_META="${INSTALL_ROOT}/install-meta.json"
CONFIG_FILE="${INSTALL_ROOT}/config.yml"
CREDENTIALS_FILE="${INSTALL_ROOT}/credentials.env"
BINARY_PATH="/usr/local/bin/xboard-node"
CLI_PATH="/usr/local/bin/xbctl"
INSTALLER_COPY_PATH="${INSTALL_ROOT}/install.sh"
CLI_BINARY_SOURCE=""
LOG_FILE="/var/log/xboard-node.log"
ERR_LOG_FILE="/var/log/xboard-node.err"
OPENRC_RUN="/sbin/openrc-run"
INIT_SYSTEM=""
SERVICE_NAME=""
SERVICE_PATH=""
SERVICE_MODE=644
STAGED_SERVICE=""
DEFAULT_HEALTH_PORT=65530
DEFAULT_KERNEL="singbox"
DEFAULT_MODE="node"
DEFAULT_ACTION="install"
DEFAULT_RELEASE_VERSION="latest"
DEFAULT_LOG_LEVEL="info"
DEFAULT_KERNEL_LOG_LEVEL="warn"
DEFAULT_DOWNLOAD_BASE="https://github.com/cedar2025/xboard-node/releases"

ACTION="${DEFAULT_ACTION}"
MODE=""
PANEL_URL=""
TOKEN=""
NODE_ID=""
NODE_TYPE=""
MACHINE_ID=""
KERNEL_TYPE="${DEFAULT_KERNEL}"
RELEASE_VERSION="${DEFAULT_RELEASE_VERSION}"
HEALTH_PORT="${DEFAULT_HEALTH_PORT}"
HEALTH_ENABLED=1
RUNTIME_GOMEMLIMIT=""
RUNTIME_GOGC=""
BINARY_SOURCE=""
CLI_BINARY_SOURCE=""
FORCE_RECONFIGURE=0
PURGE=0
YES=0
ARCH=""
OS=""
OS_LIKE=""
DOWNLOAD_URL=""
CURRENT_STATE="fresh"
TMP_DIR=""
BACKUP_PATH=""
SERVICE_EXISTED=0
CLEANUP_DONE=0

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${CYAN}[STEP]${NC} ${BOLD}$1${NC}"; }

cleanup_tmp() {
    if [ "$CLEANUP_DONE" -eq 1 ]; then
        return
    fi
    CLEANUP_DONE=1
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}

load_health_port_from_config() {
    local cfg_path="$1"
    if [ ! -f "$cfg_path" ]; then
        return
    fi
    local parsed
    if [ -x "$CLI_PATH" ]; then
        parsed=$("$CLI_PATH" config health-port --config "$cfg_path" 2>/dev/null)
    else
        parsed=$(grep -m1 'health_port:' "$cfg_path" 2>/dev/null | sed 's/.*health_port:[[:space:]]*//' | tr -cd '0-9')
    fi
    if [ -n "$parsed" ] && [ "$parsed" -ge 0 ] 2>/dev/null; then
        HEALTH_PORT="$parsed"
        if [ "$HEALTH_PORT" -eq 0 ]; then
            HEALTH_ENABLED=0
        else
            HEALTH_ENABLED=1
        fi
    fi
}

resolve_openrc_run() {
    local candidate=""
    local resolved=""
    if candidate=$(command -v openrc-run 2>/dev/null); then
        case "$candidate" in
            /*)
                resolved="$candidate"
                ;;
            *)
                if command -v realpath >/dev/null 2>&1; then
                    resolved=$(realpath "$candidate" 2>/dev/null || true)
                fi
                ;;
        esac
        if [ -n "$resolved" ] && [ -x "$resolved" ]; then
            OPENRC_RUN="$resolved"
            return 0
        fi
    fi
    for candidate in /sbin/openrc-run /usr/sbin/openrc-run /usr/bin/openrc-run; do
        if [ -x "$candidate" ]; then
            OPENRC_RUN="$candidate"
            return 0
        fi
    done
    return 1
}

has_openrc_tools() {
    command -v rc-service >/dev/null 2>&1 \
        && command -v rc-update >/dev/null 2>&1 \
        && command -v supervise-daemon >/dev/null 2>&1 \
        && resolve_openrc_run
}

openrc_runtime_active() {
    [ -e /run/openrc/softlevel ]
}

configure_service_paths() {
    case "$INIT_SYSTEM" in
        systemd)
            SERVICE_NAME="xboard-node.service"
            SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}"
            SERVICE_MODE=644
            STAGED_SERVICE="$SERVICE_NAME"
            ;;
        openrc)
            SERVICE_NAME="xboard-node"
            SERVICE_PATH="/etc/init.d/${SERVICE_NAME}"
            SERVICE_MODE=755
            STAGED_SERVICE="xboard-node.initd"
            if ! resolve_openrc_run; then
                log_error "openrc-run was not found"
                return 1
            fi
            ;;
        *)
            log_error "Unknown init system: ${INIT_SYSTEM:-<unset>}"
            return 1
            ;;
    esac
}

detect_init_system() {
    local strict="${1:-1}"
    local comm=""
    INIT_SYSTEM=""

    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        INIT_SYSTEM="systemd"
    elif openrc_runtime_active && has_openrc_tools; then
        INIT_SYSTEM="openrc"
    else
        if [ -r /proc/1/comm ]; then
            comm=$(tr -d '\0' </proc/1/comm 2>/dev/null || true)
        fi
        case "$comm" in
            systemd)
                INIT_SYSTEM="systemd"
                ;;
            openrc|openrc-init)
                INIT_SYSTEM="openrc"
                ;;
            init)
                if has_openrc_tools && [ ! -d /run/systemd/system ]; then
                    INIT_SYSTEM="openrc"
                elif command -v systemctl >/dev/null 2>&1; then
                    INIT_SYSTEM="systemd"
                fi
                ;;
        esac
    fi

    if [ -z "$INIT_SYSTEM" ]; then
        if openrc_runtime_active && has_openrc_tools; then
            INIT_SYSTEM="openrc"
        elif command -v systemctl >/dev/null 2>&1; then
            INIT_SYSTEM="systemd"
        fi
    fi

    if [ "$INIT_SYSTEM" = "systemd" ]; then
        if ! command -v systemctl >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; then
            if [ "$strict" -eq 1 ]; then
                log_error "This host does not appear to be running systemd"
                exit 1
            fi
            INIT_SYSTEM=""
            return 1
        fi
    fi

    if [ "$INIT_SYSTEM" = "openrc" ]; then
        if ! has_openrc_tools; then
            if [ "$strict" -eq 1 ]; then
                log_error "OpenRC is required but rc-service, rc-update, supervise-daemon, or openrc-run was not found"
                exit 1
            fi
            INIT_SYSTEM=""
            return 1
        fi
        if ! openrc_runtime_active; then
            if [ "$strict" -eq 1 ]; then
                log_error "OpenRC is installed but is not the running init system (missing /run/openrc/softlevel)"
                exit 1
            fi
            INIT_SYSTEM=""
            return 1
        fi
    fi

    if [ -z "$INIT_SYSTEM" ]; then
        if [ "$strict" -eq 1 ]; then
            log_error "systemd or OpenRC is required for this installer"
            exit 1
        fi
        return 1
    fi

    configure_service_paths
    if [ "$strict" -eq 1 ]; then
        log_info "Init system: ${INIT_SYSTEM}"
    fi
}

service_is_active() {
    case "$INIT_SYSTEM" in
        systemd)
            systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1
            ;;
        openrc)
            rc-service "$SERVICE_NAME" status >/dev/null 2>&1
            ;;
        *)
            return 1
            ;;
    esac
}

service_is_enabled() {
    case "$INIT_SYSTEM" in
        systemd)
            systemctl is-enabled "$SERVICE_NAME" >/dev/null 2>&1
            ;;
        openrc)
            rc-update show default 2>/dev/null | awk -v svc="$SERVICE_NAME" '$1 == svc { found=1 } END { exit(found ? 0 : 1) }'
            ;;
        *)
            return 1
            ;;
    esac
}

reload_service_manager() {
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        systemctl daemon-reload || true
    fi
}

enable_service() {
    case "$INIT_SYSTEM" in
        systemd)
            systemctl daemon-reload
            systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
            ;;
        openrc)
            if ! service_is_enabled; then
                rc-update add "$SERVICE_NAME" default >/dev/null
            fi
            ;;
    esac
}

disable_service() {
    case "$INIT_SYSTEM" in
        systemd)
            systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
            ;;
        openrc)
            rc-update -a del "$SERVICE_NAME" >/dev/null 2>&1 || true
            ;;
    esac
}

stop_service() {
    case "$INIT_SYSTEM" in
        systemd)
            if [ -f "$SERVICE_PATH" ] || systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then
                systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
            fi
            ;;
        openrc)
            if [ -f "$SERVICE_PATH" ]; then
                rc-service "$SERVICE_NAME" stop >/dev/null 2>&1 || true
            fi
            ;;
    esac
}

openrc_service_status_code() {
    local rc=0
    if rc-service "$SERVICE_NAME" status >/dev/null 2>&1; then
        rc=0
    else
        rc=$?
    fi
    printf '%s' "$rc"
}

openrc_zap_if_crashed() {
    log_warn "OpenRC status for ${SERVICE_NAME} is crashed or unsupervised; zapping stale state before start"
    rc-service "$SERVICE_NAME" zap >/dev/null 2>&1 || true
}

openrc_start_or_restart() {
    local rc
    rc=$(openrc_service_status_code)
    case "$rc" in
        0)
            rc-service "$SERVICE_NAME" restart
            ;;
        32|64)
            openrc_zap_if_crashed
            rc-service "$SERVICE_NAME" start
            ;;
        *)
            rc-service "$SERVICE_NAME" start
            ;;
    esac
}

prepare_service_restart() {
    local rc=0
    case "$INIT_SYSTEM" in
        systemd)
            systemctl reset-failed "$SERVICE_NAME" >/dev/null 2>&1 || true
            ;;
        openrc)
            rc=$(openrc_service_status_code)
            case "$rc" in
                32|64) openrc_zap_if_crashed ;;
            esac
            ;;
    esac
}

restart_service() {
    case "$INIT_SYSTEM" in
        systemd)
            if service_is_enabled; then
                systemctl restart "$SERVICE_NAME"
            else
                systemctl start "$SERVICE_NAME"
            fi
            ;;
        openrc)
            openrc_start_or_restart
            ;;
    esac
}

force_restart_service() {
    case "$INIT_SYSTEM" in
        systemd)
            systemctl restart "$SERVICE_NAME"
            ;;
        openrc)
            openrc_start_or_restart
            ;;
    esac
}

install_service_file() {
    local src="$1"
    if [ -z "$STAGED_SERVICE" ] || [ "$(basename "$src")" = "xboard-node" ] || [ "$(basename "$src")" = "xbctl" ]; then
        log_error "Refusing to install the service from the binary staging path"
        exit 1
    fi
    install -m "$SERVICE_MODE" "$src" "$SERVICE_PATH"
}

warn_foreign_service() {
    if [ "$INIT_SYSTEM" = "openrc" ] && [ -f /etc/systemd/system/xboard-node.service ]; then
        log_warn "Found a systemd unit at /etc/systemd/system/xboard-node.service; this run manages the OpenRC service"
    elif [ "$INIT_SYSTEM" = "systemd" ] && [ -f /etc/init.d/xboard-node ]; then
        log_warn "Found an OpenRC service at /etc/init.d/xboard-node; this run manages the systemd unit"
    fi
}

rollback_install() {
    log_warn "Rolling back installation"
    if [ -n "$BACKUP_PATH" ] && [ -d "$BACKUP_PATH" ]; then
        if [ -f "$BACKUP_PATH/xboard-node" ]; then
            install -m 755 "$BACKUP_PATH/xboard-node" "$BINARY_PATH"
        else
            rm -f "$BINARY_PATH"
        fi
        if [ -f "$BACKUP_PATH/config.yml" ]; then
            install -m 600 "$BACKUP_PATH/config.yml" "$CONFIG_FILE"
        else
            rm -f "$CONFIG_FILE"
        fi
        if [ -f "$BACKUP_PATH/credentials.env" ]; then
            install -m 600 "$BACKUP_PATH/credentials.env" "$CREDENTIALS_FILE"
        else
            rm -f "$CREDENTIALS_FILE"
        fi
        if [ -f "$BACKUP_PATH/install-meta.json" ]; then
            install -m 644 "$BACKUP_PATH/install-meta.json" "$INSTALL_META"
        else
            rm -f "$INSTALL_META"
        fi
        if [ -f "$BACKUP_PATH/xbctl" ]; then
            install -m 755 "$BACKUP_PATH/xbctl" "$CLI_PATH"
        else
            rm -f "$CLI_PATH"
        fi
        if [ -n "$SERVICE_PATH" ] && [ -n "$STAGED_SERVICE" ] && [ -f "$BACKUP_PATH/${STAGED_SERVICE}" ]; then
            install -m "$SERVICE_MODE" "$BACKUP_PATH/${STAGED_SERVICE}" "$SERVICE_PATH"
        elif [ -n "$SERVICE_PATH" ]; then
            rm -f "$SERVICE_PATH"
        fi
    fi
    load_health_port_from_config "$CONFIG_FILE"
    reload_service_manager
    if [ "$SERVICE_EXISTED" -eq 1 ] || { [ -n "$SERVICE_PATH" ] && [ -f "$SERVICE_PATH" ]; }; then
        prepare_service_restart
        force_restart_service >/dev/null 2>&1 || true
        if ! wait_for_health; then
            log_error "Rollback completed but restored service did not become healthy"
            show_recent_logs
            return 1
        fi
    else
        stop_service
        disable_service
    fi
    log_warn "Rollback complete"
}

on_error() {
    local exit_code=$?
    local line_no=${1:-unknown}
    if [ "$exit_code" -ne 0 ]; then
        log_error "Install failed at line ${line_no} (exit=${exit_code})"
        if [ -n "$BACKUP_PATH" ]; then
            rollback_install || true
        fi
    fi
    cleanup_tmp
    exit "$exit_code"
}
trap 'on_error $LINENO' ERR
trap cleanup_tmp EXIT

usage() {
    cat <<'HELP'

  xboard-node Installer (systemd + OpenRC)

  ACTIONS:
    install      Install or reconcile the configured deployment (default)
    upgrade      Upgrade binary and restart service
    uninstall    Remove installed service and binary (config kept unless --purge)
    status       Show current installation status
    help         Show this help

  INIT:
    Detected automatically.
    systemd      /etc/systemd/system/xboard-node.service
    openrc       /etc/init.d/xboard-node  (Alpine, Gentoo, Devuan, Artix, ...)

  MODES (auto-detected from --node-id or --machine-id if omitted):
    --mode node      Panel single-node mode (default)
    --mode machine   Panel machine mode

  REQUIRED FOR NODE MODE:
    --panel, -a      Panel URL
    --token, -t      Panel server token
    --node-id, -n    Node ID

  REQUIRED FOR MACHINE MODE:
    --panel, -a       Panel URL
    --token, -t       Machine token
    --machine-id      Machine ID

  OPTIONAL:
    --node-type, -T     Explicit node type for node mode
    --kernel, -k        singbox or xray (default: singbox)
    --version           Release version or latest (default: latest)
    --binary            Use a local xboard-node binary path instead of downloading
    --xbctl-binary      Use a local xbctl binary path instead of downloading
    --health-port       Local health port (default: 65530, use 0 to disable)
    --gomemlimit        Runtime GOMEMLIMIT value, e.g. 256MiB
    --gogc              Runtime GOGC value, e.g. 50
    --force-reconfigure Overwrite an existing install even if mode/target changed
    --purge             With uninstall, delete /etc/xboard-node too
    --yes, -y           Non-interactive confirmation for destructive operations

  EXAMPLES:
    sudo bash install.sh --panel https://panel.example.com --token TOKEN --node-id 1
    sudo bash install.sh --panel https://panel.example.com --token TOKEN --machine-id 1
    sudo bash install.sh upgrade
    sudo bash install.sh uninstall --purge --yes

  Alpine does not ship bash. Install it before running this script:
    apk add bash

HELP
}

parse_args() {
    local positional=()
    while [ $# -gt 0 ]; do
        case "$1" in
            install|upgrade|uninstall|status|help)
                ACTION="$1"
                shift
                ;;
            --mode)
                MODE="$2"
                shift 2
                ;;
            --panel|-a|--api)
                PANEL_URL="$2"
                shift 2
                ;;
            --token|-t)
                TOKEN="$2"
                shift 2
                ;;
            --node-id|-n)
                NODE_ID="$2"
                shift 2
                ;;
            --node-type|-T)
                NODE_TYPE="$2"
                shift 2
                ;;
            --machine-id)
                MACHINE_ID="$2"
                shift 2
                ;;
            --kernel|-k)
                KERNEL_TYPE="$2"
                shift 2
                ;;
            --version)
                RELEASE_VERSION="$2"
                shift 2
                ;;
            --binary)
                BINARY_SOURCE="$2"
                shift 2
                ;;
            --xbctl-binary)
                CLI_BINARY_SOURCE="$2"
                shift 2
                ;;
            --health-port)
                HEALTH_PORT="$2"
                shift 2
                ;;
            --gomemlimit)
                RUNTIME_GOMEMLIMIT="$2"
                shift 2
                ;;
            --gogc)
                RUNTIME_GOGC="$2"
                shift 2
                ;;
            --force-reconfigure)
                FORCE_RECONFIGURE=1
                shift
                ;;
            --purge)
                PURGE=1
                shift
                ;;
            --yes|-y)
                YES=1
                shift
                ;;
            --help|-h)
                ACTION="help"
                shift
                ;;
            *)
                positional+=("$1")
                shift
                ;;
        esac
    done

    if [ ${#positional[@]} -gt 0 ] && [ "$ACTION" = "install" ]; then
        ACTION="${positional[0]}"
    fi

    case "$KERNEL_TYPE" in
        singbox|SingBox|SINGBOX) KERNEL_TYPE="singbox" ;;
        xray|Xray|XRAY) KERNEL_TYPE="xray" ;;
        *) ;;
    esac

    # Auto-detect mode from arguments when --mode is not specified.
    if [ -z "$MODE" ]; then
        if [ -n "$MACHINE_ID" ]; then
            MODE="machine"
        else
            MODE="node"
        fi
    fi

    case "$MODE" in
        node|machine) ;;
        *)
            log_error "Unsupported mode: $MODE"
            usage
            exit 1
            ;;
    esac
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "Please run as root or with sudo"
        exit 1
    fi
}

detect_arch() {
    local raw
    raw=$(uname -m)
    case "$raw" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *)
            log_error "Unsupported architecture: $raw"
            exit 1
            ;;
    esac
}

detect_os() {
    OS="unknown"
    OS_LIKE=""
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS="${ID:-unknown}"
        OS_LIKE="${ID_LIKE:-}"
    fi
}

run_with_retry() {
    local attempts="$1"
    local delay="$2"
    shift 2
    local i=1
    while [ "$i" -le "$attempts" ]; do
        if "$@"; then
            return 0
        fi
        if [ "$i" -lt "$attempts" ]; then
            log_warn "Command failed, retrying in ${delay}s: $*"
            sleep "$delay"
        fi
        i=$((i + 1))
    done
    return 1
}

install_apt_deps() {
    DEBIAN_FRONTEND=noninteractive run_with_retry 10 3 apt-get update -qq
    DEBIAN_FRONTEND=noninteractive run_with_retry 10 3 apt-get install -y -qq curl wget ca-certificates >/dev/null 2>&1
}

install_rpm_deps() {
    if command -v dnf >/dev/null 2>&1; then
        run_with_retry 5 3 dnf install -y -q curl wget ca-certificates >/dev/null 2>&1
    else
        run_with_retry 5 3 yum install -y -q curl wget ca-certificates >/dev/null 2>&1
    fi
}

install_apk_deps() {
    if ! command -v apk >/dev/null 2>&1; then
        log_error "apk is required to install dependencies on ${OS}"
        exit 1
    fi
    # bash is required for the copied installer and for re-running this script.
    run_with_retry 5 3 apk add --no-cache bash curl wget ca-certificates
}

install_dependencies() {
    local family="unknown"
    case "$OS" in
        ubuntu|debian|devuan|linuxmint|pop|raspbian) family="apt" ;;
        centos|rhel|rocky|almalinux|fedora) family="rpm" ;;
        alpine|postmarketos) family="apk" ;;
        *)
            case " ${OS_LIKE} " in
                *" debian "*|*" ubuntu "*) family="apt" ;;
                *" rhel "*|*" fedora "*|*" centos "*) family="rpm" ;;
                *" alpine "*) family="apk" ;;
            esac
            ;;
    esac

    case "$family" in
        apt) install_apt_deps ;;
        rpm) install_rpm_deps ;;
        apk) install_apk_deps ;;
        *)
            log_warn "OS ${OS} is not in the official support set; continuing best-effort"
            ;;
    esac

    if ! command -v curl >/dev/null 2>&1; then
        log_error "curl is required but was not found"
        exit 1
    fi
}

ensure_dirs() {
    mkdir -p "$INSTALL_ROOT" "$BACKUP_DIR"
    chmod 700 "$INSTALL_ROOT"
}

validate_positive_int() {
    local label="$1"
    local value="$2"
    if ! [[ "$value" =~ ^[0-9]+$ ]] || [ "$value" -le 0 ]; then
        log_error "${label} must be a positive integer, got: ${value}"
        exit 1
    fi
}

validate_install_request() {
    if [ -z "$PANEL_URL" ]; then
        log_error "Panel URL is required"
        exit 1
    fi
    if [ -z "$TOKEN" ]; then
        log_error "Token is required"
        exit 1
    fi
    if ! [[ "$HEALTH_PORT" =~ ^[0-9]+$ ]]; then
        log_error "health-port must be a non-negative integer"
        exit 1
    fi
    if [ "$HEALTH_PORT" -eq 0 ]; then
        HEALTH_ENABLED=0
    fi
    case "$KERNEL_TYPE" in
        singbox|xray) ;;
        *)
            log_error "Kernel must be singbox or xray"
            exit 1
            ;;
    esac
    case "$MODE" in
        node)
            validate_positive_int "Node ID" "$NODE_ID"
            ;;
        machine)
            validate_positive_int "Machine ID" "$MACHINE_ID"
            ;;
    esac
}

detect_current_state() {
    local has_binary=0 has_config=0 has_service=0
    [ -x "$BINARY_PATH" ] && has_binary=1
    [ -f "$CONFIG_FILE" ] && has_config=1
    if [ -n "$SERVICE_PATH" ] && [ -f "$SERVICE_PATH" ]; then
        has_service=1
    fi

    if [ "$has_binary" -eq 0 ] && [ "$has_config" -eq 0 ] && [ "$has_service" -eq 0 ]; then
        CURRENT_STATE="fresh"
    elif [ "$has_binary" -eq 1 ] && [ "$has_config" -eq 1 ] && [ "$has_service" -eq 1 ]; then
        CURRENT_STATE="installed"
    else
        CURRENT_STATE="partial"
    fi
}

require_reconfigure_confirmation() {
    return
}

select_binary_source() {
    if [ -n "$BINARY_SOURCE" ]; then
        if [ ! -f "$BINARY_SOURCE" ]; then
            log_error "Binary source not found: $BINARY_SOURCE"
            exit 1
        fi
        echo "$BINARY_SOURCE"
        return
    fi
    if [ -f "./xboard-node" ]; then
        echo "./xboard-node"
        return
    fi
    if [ -f "./xboard-node-linux-${ARCH}" ]; then
        echo "./xboard-node-linux-${ARCH}"
        return
    fi
    echo ""
}

resolve_download_url() {
    local artifact="$1"
    if [ "$RELEASE_VERSION" = "latest" ]; then
        DOWNLOAD_URL="${DEFAULT_DOWNLOAD_BASE}/latest/download/${artifact}"
    else
        DOWNLOAD_URL="${DEFAULT_DOWNLOAD_BASE}/download/${RELEASE_VERSION}/${artifact}"
    fi
}

stage_binary() {
    local staged="$TMP_DIR/xboard-node"
    local local_src
    local_src=$(select_binary_source)
    if [ -n "$local_src" ]; then
        log_step "Using local binary: ${local_src}"
        cp "$local_src" "$staged"
    else
        resolve_download_url "xboard-node-linux-${ARCH}"
        log_step "Downloading binary: ${DOWNLOAD_URL}"
        if ! curl -fsSL "$DOWNLOAD_URL" -o "$staged"; then
            log_error "Failed to download binary from ${DOWNLOAD_URL}"
            exit 1
        fi
    fi
    chmod +x "$staged"
    if ! "$staged" -v >/dev/null 2>&1; then
        log_error "Downloaded binary failed version check"
        exit 1
    fi
}

stage_xbctl() {
    local staged="$TMP_DIR/xbctl"
    local local_src=""
    if [ -n "$CLI_BINARY_SOURCE" ]; then
        if [ ! -f "$CLI_BINARY_SOURCE" ]; then
            log_error "xbctl binary source not found: $CLI_BINARY_SOURCE"
            exit 1
        fi
        local_src="$CLI_BINARY_SOURCE"
    elif [ -f "./xbctl" ]; then
        local_src="./xbctl"
    elif [ -f "./xbctl-linux-${ARCH}" ]; then
        local_src="./xbctl-linux-${ARCH}"
    fi
    if [ -n "$local_src" ]; then
        log_step "Using local xbctl binary: ${local_src}"
        cp "$local_src" "$staged"
    else
        resolve_download_url "xbctl-linux-${ARCH}"
        log_step "Downloading xbctl: ${DOWNLOAD_URL}"
        if ! curl -fsSL "$DOWNLOAD_URL" -o "$staged"; then
            log_error "Failed to download xbctl from ${DOWNLOAD_URL}"
            exit 1
        fi
    fi
    chmod +x "$staged"
    if ! "$staged" version > /dev/null 2>&1; then
        log_error "Downloaded xbctl failed version check"
        exit 1
    fi
}

render_config() {
    local init_args=(
        config init
        --mode "$MODE"
        --panel-url "$PANEL_URL"
        --kernel "${KERNEL_TYPE:-singbox}"
        --health-port "${HEALTH_PORT:-0}"
        --token "$TOKEN"
        --version "$RELEASE_VERSION"
        --output "$TMP_DIR/config.yml"
        --credentials-out "$TMP_DIR/credentials.env"
        --meta "$TMP_DIR/install-meta.json"
        --install-root "$INSTALL_ROOT"
    )
    if [ -f "$CONFIG_FILE" ]; then
        init_args+=(--config "$CONFIG_FILE")
    fi
    if [ -f "$CREDENTIALS_FILE" ]; then
        init_args+=(--credentials-in "$CREDENTIALS_FILE")
    fi
    if [ "$MODE" = "machine" ]; then
        init_args+=(--machine-id "$MACHINE_ID")
    else
        init_args+=(--node-id "$NODE_ID")
        if [ -n "$NODE_TYPE" ]; then
            init_args+=(--node-type "$NODE_TYPE")
        fi
    fi
    if [ -n "$RUNTIME_GOMEMLIMIT" ]; then
        init_args+=(--gomemlimit "$RUNTIME_GOMEMLIMIT")
    fi
    if [ -n "$RUNTIME_GOGC" ] && [ "$RUNTIME_GOGC" -gt 0 ] 2>/dev/null; then
        init_args+=(--gogc "$RUNTIME_GOGC")
    fi

    local output
    output=$("$TMP_DIR/xbctl" "${init_args[@]}") || {
        log_error "xbctl config init failed"
        exit 1
    }

    INSTANCE_ID=$(echo "$output" | grep '^INSTANCE_ID=' | cut -d= -f2-)
    chmod 600 "$TMP_DIR/credentials.env"
}

render_systemd_service() {
    cat >"$TMP_DIR/${STAGED_SERVICE}" <<EOF_UNIT
[Unit]
Description=Xboard Node Backend
Documentation=https://github.com/cedar2025/xboard-node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_ROOT}
EnvironmentFile=-${CREDENTIALS_FILE}
ExecStart=${BINARY_PATH} -c ${CONFIG_FILE}
Restart=always
RestartSec=5
LimitNOFILE=1048576
NoNewPrivileges=true
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF_UNIT
}

openrc_supervise_supports_no_new_privs() {
    local helper=""
    local help=""
    helper=$(command -v supervise-daemon 2>/dev/null || true)
    [ -n "$helper" ] || return 1
    help=$("$helper" --help 2>&1 || true)
    case "$help" in
        *--no-new-privs*) return 0 ;;
    esac
    return 1
}

render_openrc_service() {
    local staged="$TMP_DIR/${STAGED_SERVICE}"
    local supervise_args_line=""
    if ! command -v supervise-daemon >/dev/null 2>&1; then
        log_warn "supervise-daemon was not found in PATH; omitting --no-new-privs (OpenRC resolves the helper when the service starts)"
    elif openrc_supervise_supports_no_new_privs; then
        supervise_args_line='supervise_daemon_args="--no-new-privs"'
    else
        log_warn "supervise-daemon does not support --no-new-privs; omitting it so older OpenRC can start the service"
    fi
    cat >"$staged" <<'EOF_INIT'
#!@OPENRC_RUN@

name="xboard-node"
description="Xboard Node Backend"
supervisor=supervise-daemon
command="@BINARY_PATH@"
command_args="-c @CONFIG_FILE@"
directory="@INSTALL_ROOT@"
pidfile="/run/${RC_SVCNAME}.pid"
output_log="@LOG_FILE@"
error_log="@ERR_LOG_FILE@"
respawn_delay=5
respawn_max=0
rc_ulimit="-n 1048576"
@SUPERVISE_DAEMON_ARGS_LINE@
required_files="@CONFIG_FILE@"

depend() {
    use net dns
    after net firewall
}

xboard_node_load_env() {
    env_file=$1
    cr=$(printf '\r')
    [ -f "$env_file" ] || return 0
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%"$cr"}
        case "$line" in
            ""|\#*|\;*) continue ;;
        esac
        line=${line#export }
        case "$line" in
            *=*) ;;
            *) continue ;;
        esac
        key=${line%%=*}
        value=${line#*=}
        case "$value" in
            \"*\") value=${value#\"}; value=${value%\"} ;;
            \'*\') value=${value#\'}; value=${value%\'} ;;
        esac
        case "$key" in
            [A-Za-z_][A-Za-z0-9_]*) export "$key=$value" ;;
        esac
    done < "$env_file"
}

start_pre() {
    checkpath --directory --mode 0755 /run
    checkpath --file --mode 0640 "@LOG_FILE@"
    checkpath --file --mode 0640 "@ERR_LOG_FILE@"
    xboard_node_load_env "@CREDENTIALS_FILE@"
}
EOF_INIT
    if [ -n "$supervise_args_line" ]; then
        sed -i 's|@SUPERVISE_DAEMON_ARGS_LINE@|'"${supervise_args_line}"'|' "$staged"
    else
        sed -i '/@SUPERVISE_DAEMON_ARGS_LINE@/d' "$staged"
    fi
    if grep -q '@SUPERVISE_DAEMON_ARGS_LINE@' "$staged"; then
        log_error "Failed to render OpenRC supervise-daemon arguments"
        return 1
    fi
    sed -i \
        -e "s|@OPENRC_RUN@|${OPENRC_RUN}|g" \
        -e "s|@BINARY_PATH@|${BINARY_PATH}|g" \
        -e "s|@CONFIG_FILE@|${CONFIG_FILE}|g" \
        -e "s|@INSTALL_ROOT@|${INSTALL_ROOT}|g" \
        -e "s|@LOG_FILE@|${LOG_FILE}|g" \
        -e "s|@ERR_LOG_FILE@|${ERR_LOG_FILE}|g" \
        -e "s|@CREDENTIALS_FILE@|${CREDENTIALS_FILE}|g" \
        "$staged"
}

render_service() {
    case "$INIT_SYSTEM" in
        systemd) render_systemd_service ;;
        openrc) render_openrc_service ;;
    esac
}

backup_existing_state() {
    BACKUP_PATH="${BACKUP_DIR}/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_PATH"
    if [ -x "$BINARY_PATH" ]; then
        cp "$BINARY_PATH" "$BACKUP_PATH/xboard-node"
    fi
    if [ -x "$CLI_PATH" ]; then
        cp "$CLI_PATH" "$BACKUP_PATH/xbctl"
    fi
    if [ -f "$CONFIG_FILE" ]; then
        cp "$CONFIG_FILE" "$BACKUP_PATH/config.yml"
    fi
    if [ -f "$CREDENTIALS_FILE" ]; then
        cp "$CREDENTIALS_FILE" "$BACKUP_PATH/credentials.env"
    fi
    if [ -f "$INSTALL_META" ]; then
        cp "$INSTALL_META" "$BACKUP_PATH/install-meta.json"
    fi
    if [ -n "$SERVICE_PATH" ] && [ -f "$SERVICE_PATH" ]; then
        cp "$SERVICE_PATH" "$BACKUP_PATH/${STAGED_SERVICE}"
        SERVICE_EXISTED=1
    else
        SERVICE_EXISTED=0
    fi
}

copy_installer() {
    if [ -f "$0" ] && [ "$(realpath "$0")" != "$(realpath "$INSTALLER_COPY_PATH" 2>/dev/null || echo "$INSTALLER_COPY_PATH")" ]; then
        install -m 755 "$0" "$INSTALLER_COPY_PATH"
    fi
}

install_staged_files() {
    stop_service
    install -m 755 "$TMP_DIR/xboard-node" "$BINARY_PATH"
    install -m 600 "$TMP_DIR/config.yml" "$CONFIG_FILE"
    install -m 600 "$TMP_DIR/credentials.env" "$CREDENTIALS_FILE"
    install -m 644 "$TMP_DIR/install-meta.json" "$INSTALL_META"
    copy_installer
    install -m 755 "$TMP_DIR/xbctl" "$CLI_PATH"
    ln -sf "$CLI_PATH" /usr/bin/xbctl 2>/dev/null || true
    install_service_file "$TMP_DIR/${STAGED_SERVICE}"
    enable_service
}

wait_for_health() {
    if ! service_is_active; then
        return 1
    fi
    if [ "$HEALTH_ENABLED" -eq 0 ]; then
        return 0
    fi
    local attempt=0
    local max_attempts=30
    while [ "$attempt" -lt "$max_attempts" ]; do
        if ! service_is_active; then
            return 1
        fi
        if curl -fsS "http://127.0.0.1:${HEALTH_PORT}/healthz" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    return 1
}

show_recent_logs() {
    case "$INIT_SYSTEM" in
        systemd)
            if command -v journalctl >/dev/null 2>&1; then
                journalctl -u "$SERVICE_NAME" -n 30 --no-pager || true
            fi
            ;;
        openrc)
            if [ -f "$LOG_FILE" ]; then
                log_warn "Recent stdout (${LOG_FILE}):"
                tail -n 30 "$LOG_FILE" || true
            fi
            if [ -f "$ERR_LOG_FILE" ]; then
                log_warn "Recent stderr (${ERR_LOG_FILE}):"
                tail -n 30 "$ERR_LOG_FILE" || true
            fi
            if [ ! -f "$LOG_FILE" ] && [ ! -f "$ERR_LOG_FILE" ]; then
                log_warn "No OpenRC logs found at ${LOG_FILE}"
            fi
            ;;
    esac
}

start_service() {
    restart_service
    if ! wait_for_health; then
        log_error "Service failed health check"
        show_recent_logs
        return 1
    fi
}

print_manage_hints() {
    case "$INIT_SYSTEM" in
        openrc)
            log_info "Manage: rc-service ${SERVICE_NAME} status|restart|stop"
            log_info "Enable: rc-update add ${SERVICE_NAME} default"
            log_info "Logs:   ${LOG_FILE}"
            ;;
        systemd)
            log_info "Manage: systemctl status ${SERVICE_NAME}"
            log_info "Logs:   journalctl -u ${SERVICE_NAME} -n 50 --no-pager"
            ;;
    esac
}

perform_install() {
    validate_install_request
    detect_current_state
    require_reconfigure_confirmation
    warn_foreign_service
    TMP_DIR=$(mktemp -d)
    ensure_dirs
    stage_binary
    stage_xbctl
    render_config
    render_service
    backup_existing_state
    install_staged_files
    start_service

    log_info "Installation succeeded"
    log_info "Init: ${INIT_SYSTEM}"
    log_info "Service: ${SERVICE_NAME}"
    log_info "Config: ${CONFIG_FILE}"
    log_info "Credentials: ${CREDENTIALS_FILE}"
    if [ "$HEALTH_ENABLED" -eq 1 ]; then
        log_info "Health: http://127.0.0.1:${HEALTH_PORT}/healthz"
    fi
    log_info "CLI: ${CLI_PATH}  (run '${CLI_PATH} list' if xbctl is not in PATH)"
    print_manage_hints
}

perform_upgrade() {
    detect_current_state
    if [ "$CURRENT_STATE" = "fresh" ]; then
        log_warn "No existing install found; falling back to install"
        perform_install
        return
    fi
    TMP_DIR=$(mktemp -d)
    ensure_dirs
    stage_binary
    stage_xbctl
    render_service
    backup_existing_state
    install -m 755 "$TMP_DIR/xboard-node" "$BINARY_PATH"
    install -m 755 "$TMP_DIR/xbctl" "$CLI_PATH"
    ln -sf "$CLI_PATH" /usr/bin/xbctl 2>/dev/null || true
    copy_installer
    install_service_file "$TMP_DIR/${STAGED_SERVICE}"
    reload_service_manager
    force_restart_service
    if ! wait_for_health; then
        log_error "Upgrade health check failed"
        show_recent_logs
        return 1
    fi
    log_info "Upgrade succeeded"
    print_manage_hints
}

confirm_uninstall() {
    if [ "$YES" -eq 1 ]; then
        return
    fi
    echo
    read -r -p "Proceed with uninstall? [y/N]: " answer
    if ! [[ "$answer" =~ ^[Yy]$ ]]; then
        log_warn "Uninstall cancelled"
        exit 0
    fi
}

perform_uninstall() {
    confirm_uninstall
    if [ -n "$SERVICE_PATH" ] && [ -f "$SERVICE_PATH" ]; then
        stop_service
        disable_service
        if [ "$INIT_SYSTEM" = "openrc" ]; then
            rc-service "$SERVICE_NAME" zap >/dev/null 2>&1 || true
            rm -f "/run/${SERVICE_NAME}.pid" "/var/run/${SERVICE_NAME}.pid"
        fi
        rm -f "$SERVICE_PATH"
        reload_service_manager
    fi
    rm -f "$BINARY_PATH"
    rm -f "$CLI_PATH"
    rm -f /usr/bin/xbctl 2>/dev/null || true
    if [ "$PURGE" -eq 1 ]; then
        rm -f "$LOG_FILE" "$ERR_LOG_FILE"
        rm -rf "$INSTALL_ROOT"
        log_info "Removed ${INSTALL_ROOT}"
    else
        rm -f "$INSTALL_META"
        log_info "Config preserved under ${INSTALL_ROOT}"
    fi
    log_info "Uninstall complete"
}

perform_status() {
    detect_current_state
    echo
    echo -e "${BOLD}xboard-node install status${NC}"
    echo "  state:   ${CURRENT_STATE}"
    if [ -n "$INIT_SYSTEM" ]; then
        echo "  init:    ${INIT_SYSTEM}"
    else
        echo "  init:    undetected"
    fi
    if [ -f "$INSTALL_META" ]; then
        echo "  meta:    ${INSTALL_META}"
        if [ -x "$CLI_PATH" ]; then
            "$CLI_PATH" list 2>/dev/null || true
        else
            # Simple key extraction from JSON (no Python needed)
            local val
            for key in config_mode version latest_instance_id instance_count updated_at; do
                val=$(sed -n "s/.*\"${key}\": *\"\{0,1\}\([^\"]*\)\"\{0,1\}.*/\1/p" "$INSTALL_META" | head -1)
                val="${val%,}"  # strip trailing comma from numeric JSON values
                [ -n "$val" ] && echo "  ${key}: ${val}"
            done
        fi
    fi
    if [ -n "$SERVICE_PATH" ] && [ -f "$SERVICE_PATH" ]; then
        echo "  service: ${SERVICE_NAME} (${SERVICE_PATH})"
        case "$INIT_SYSTEM" in
            systemd)
                systemctl status "$SERVICE_NAME" --no-pager || true
                ;;
            openrc)
                rc-service "$SERVICE_NAME" status || true
                if service_is_enabled; then
                    echo "  boot:    enabled (default)"
                else
                    echo "  boot:    disabled"
                fi
                ;;
        esac
    fi
}

main() {
    parse_args "$@"
    case "$ACTION" in
        help)
            usage
            exit 0
            ;;
        status)
            detect_init_system 0 || true
            perform_status
            exit 0
            ;;
    esac

    check_root
    detect_arch
    detect_os
    detect_init_system 1
    install_dependencies

    case "$ACTION" in
        install)
            perform_install
            ;;
        upgrade)
            perform_upgrade
            ;;
        uninstall)
            perform_uninstall
            ;;
        *)
            log_error "Unknown action: $ACTION"
            usage
            exit 1
            ;;
    esac
}

main "$@"
