#!/bin/bash
set -e

# xboard-node Multi-Node Deploy Script
# Supports: Ubuntu 20+, Debian 11+, CentOS 8+, Alpine 3.18+
#
# One-command deploy (non-interactive):
#   bash install.sh -a https://panel.example.com -t YOUR_TOKEN -n 1
#   bash install.sh -a https://panel.example.com -t YOUR_TOKEN -n 2 -k xray
#   bash install.sh -a https://panel.example.com -t YOUR_TOKEN -n 3 --docker
#
# Interactive:
#   bash install.sh
#
# Management:
#   bash install.sh list
#   bash install.sh remove <node_id>
#   bash install.sh update
#   bash install.sh uninstall

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/xboard-node"
SERVICE_TEMPLATE="xboard-node@.service"
DOCKER_COMPOSE_FILE="${CONFIG_DIR}/docker-compose.yml"
DOCKER_IMAGE="ghcr.io/cedar2025/xboard-node:latest"

# Parsed parameters (populated by parse_args)
PANEL_URL=""
PANEL_TOKEN=""
NODE_ID=""
NODE_TYPE=""
KERNEL_TYPE="singbox"
DOCKER_MODE=0
SUBCOMMAND=""

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${CYAN}[STEP]${NC} ${BOLD}$1${NC}"; }

# ─── Argument Parsing ─────────────────────────────────────────────────

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -a|--api)       PANEL_URL="$2";    shift 2 ;;
            -t|--token)     PANEL_TOKEN="$2";  shift 2 ;;
            -n|--node-id)   NODE_ID="$2";      shift 2 ;;
            -T|--node-type) NODE_TYPE="$2";    shift 2 ;;
            -k|--kernel)    KERNEL_TYPE="$2";   shift 2 ;;
            --docker)       DOCKER_MODE=1;      shift ;;
            add|remove|list|update|uninstall|help|--help|-h)
                if [ -z "$SUBCOMMAND" ]; then
                    SUBCOMMAND="$1"
                fi
                shift
                ;;
            *)
                if [ "$SUBCOMMAND" = "remove" ] && [ -z "$NODE_ID" ]; then
                    NODE_ID="$1"
                fi
                shift
                ;;
        esac
    done

    # Normalize kernel type
    case "$KERNEL_TYPE" in
        xray|Xray|XRAY) KERNEL_TYPE="xray" ;;
        *) KERNEL_TYPE="singbox" ;;
    esac
}

has_all_params() {
    [ -n "$PANEL_URL" ] && [ -n "$PANEL_TOKEN" ] && [ -n "$NODE_ID" ]
}

validate_params() {
    if [ -z "$PANEL_URL" ]; then
        log_error "Panel URL is required (-a/--api)"
        exit 1
    fi
    if [ -z "$PANEL_TOKEN" ]; then
        log_error "Server Token is required (-t/--token)"
        exit 1
    fi
    if [ -z "$NODE_ID" ]; then
        log_error "Node ID is required (-n/--node-id)"
        exit 1
    fi
    if ! [[ "$NODE_ID" =~ ^[0-9]+$ ]]; then
        log_error "Node ID must be a positive integer, got: $NODE_ID"
        exit 1
    fi
}

# ─── System Detection ────────────────────────────────────────────────

check_root() {
    if [ "$(id -u)" != "0" ]; then
        log_error "Please run as root (or with sudo)"
        exit 1
    fi
}

detect_arch() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l) ARCH="armv7" ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    elif [ -f /etc/alpine-release ]; then
        OS="alpine"
    else
        OS="unknown"
    fi
}

install_deps() {
    case "$OS" in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq wget curl tar >/dev/null 2>&1
            ;;
        centos|rhel|rocky|almalinux|fedora)
            yum install -y -q wget curl tar >/dev/null 2>&1
            ;;
        alpine)
            apk add --no-cache wget curl tar >/dev/null 2>&1
            ;;
    esac
}

# ─── Binary Install ──────────────────────────────────────────────────

is_binary_installed() {
    [ -x "${INSTALL_DIR}/xboard-node" ]
}

install_binary() {
    if is_binary_installed; then
        log_info "xboard-node binary already installed"
        return
    fi

    log_step "Installing xboard-node binary..."

    local src=""

    if [ -f "./xboard-node" ]; then
        src="./xboard-node"
    elif [ -f "./xboard-node-linux-${ARCH}" ]; then
        src="./xboard-node-linux-${ARCH}"
    fi

    if [ -n "$src" ]; then
        cp "$src" "${INSTALL_DIR}/xboard-node"
        log_info "Installed from local file: $src"
    else
        local url="https://github.com/cedar2025/xboard-node/releases/latest/download/xboard-node-linux-${ARCH}"
        log_info "Downloading from GitHub releases..."
        if wget -q "$url" -O "${INSTALL_DIR}/xboard-node" 2>/dev/null; then
            log_info "Downloaded successfully"
        elif curl -fsSL "$url" -o "${INSTALL_DIR}/xboard-node" 2>/dev/null; then
            log_info "Downloaded successfully"
        else
            log_error "Failed to download. Place xboard-node binary in current directory and retry."
            exit 1
        fi
    fi

    chmod +x "${INSTALL_DIR}/xboard-node"
    log_info "xboard-node installed to ${INSTALL_DIR}/xboard-node"
}

# ─── Systemd Template ────────────────────────────────────────────────

install_systemd_template() {
    if ! command -v systemctl >/dev/null 2>&1; then
        return
    fi

    if [ -f "/etc/systemd/system/${SERVICE_TEMPLATE}" ]; then
        return
    fi

    log_step "Installing systemd service template..."

    cat > "/etc/systemd/system/${SERVICE_TEMPLATE}" << 'UNIT'
[Unit]
Description=Xboard Node Backend (node %i)
Documentation=https://github.com/cedar2025/xboard-node
After=network.target nss-lookup.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xboard-node -c /etc/xboard-node/%i/config.yml
Restart=always
RestartSec=5
LimitNOFILE=1048576
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

    systemctl daemon-reload
    log_info "Systemd template installed: ${SERVICE_TEMPLATE}"
}

# ─── OpenRC Template ──────────────────────────────────────────────────

install_openrc_template() {
    if ! command -v rc-service >/dev/null 2>&1; then
        return
    fi

    # OpenRC doesn't use templates, create service per node
    local node_id="$1"
    local service_name="xboard-node-${node_id}"
    local service_file="/etc/init.d/${service_name}"

    if [ -f "$service_file" ]; then
        return
    fi

    log_step "Installing OpenRC service: ${service_name}..."

    cat > "$service_file" << EOF
#!/sbin/openrc-run

name="${service_name}"
description="Xboard Node Backend (node ${node_id})"
command="/usr/local/bin/xboard-node"
command_args="-c /etc/xboard-node/${node_id}/config.yml"
command_background=true
pidfile="/run/\${RC_SVCNAME}.pid"
output_log="/var/log/\${RC_SVCNAME}.log"
error_log="/var/log/\${RC_SVCNAME}.err"

depend() {
    need net
    after firewall
}

start_pre() {
    checkpath --directory --mode 0755 /var/log
    checkpath --directory --mode 0755 /run
}
EOF

    chmod +x "$service_file"
    log_info "OpenRC service installed: ${service_name}"
}

# ─── Migrate Legacy Config ───────────────────────────────────────────

migrate_legacy_config() {
    if [ -f "${CONFIG_DIR}/config.yml" ] && [ ! -d "${CONFIG_DIR}/config.yml" ]; then
        local legacy_id
        legacy_id=$(grep -E '^\s*node_id:\s*' "${CONFIG_DIR}/config.yml" 2>/dev/null | head -1 | sed 's/[^0-9]*//g')

        if [ -z "$legacy_id" ]; then
            legacy_id="default"
        fi

        if [ ! -d "${CONFIG_DIR}/${legacy_id}" ]; then
            log_warn "Migrating legacy config to multi-node layout: node ${legacy_id}"
            mkdir -p "${CONFIG_DIR}/${legacy_id}"
            mv "${CONFIG_DIR}/config.yml" "${CONFIG_DIR}/${legacy_id}/config.yml"

            if command -v systemctl >/dev/null 2>&1; then
                systemctl stop xboard-node 2>/dev/null || true
                systemctl disable xboard-node 2>/dev/null || true
                rm -f /etc/systemd/system/xboard-node.service

                install_systemd_template
                systemctl enable "xboard-node@${legacy_id}" 2>/dev/null || true
                systemctl start "xboard-node@${legacy_id}" 2>/dev/null || true
                log_info "Migrated service: xboard-node → xboard-node@${legacy_id}"
            fi
        fi
    fi
}

# ─── Interactive Prompts ──────────────────────────────────────────────

prompt_missing_params() {
    echo ""
    log_step "=== Node Configuration ==="
    echo ""

    if [ -z "$PANEL_URL" ]; then
        read -rp "  Panel URL (e.g. https://panel.example.com): " PANEL_URL
    else
        echo -e "  Panel URL: ${CYAN}${PANEL_URL}${NC}"
    fi

    if [ -z "$PANEL_TOKEN" ]; then
        read -rp "  Server Token: " PANEL_TOKEN
    else
        echo -e "  Server Token: ${CYAN}${PANEL_TOKEN:0:8}***${NC}"
    fi

    if [ -z "$NODE_ID" ]; then
        read -rp "  Node ID: " NODE_ID
    else
        echo -e "  Node ID: ${CYAN}${NODE_ID}${NC}"
    fi

    if [ -n "$NODE_TYPE" ]; then
        echo -e "  Node Type: ${CYAN}${NODE_TYPE}${NC}"
    fi

    if [ -n "$KERNEL_TYPE" ] && [ "$KERNEL_TYPE" != "singbox" ]; then
        echo -e "  Kernel: ${CYAN}${KERNEL_TYPE}${NC}"
    else
        echo ""
        echo "  Kernel type:"
        echo "    1) singbox (default, recommended)"
        echo "    2) xray"
        read -rp "  Choose [1/2]: " KERNEL_CHOICE
        case "$KERNEL_CHOICE" in
            2) KERNEL_TYPE="xray" ;;
            *) KERNEL_TYPE="singbox" ;;
        esac
    fi

    echo ""
    validate_params
}

# ─── Node Operations ─────────────────────────────────────────────────

write_node_config() {
    local node_id="$1"
    local node_dir="${CONFIG_DIR}/${node_id}"

    mkdir -p "$node_dir"

    local node_type_line=""
    if [ -n "$NODE_TYPE" ]; then
        node_type_line="  node_type: \"${NODE_TYPE}\""
    fi

    cat > "${node_dir}/config.yml" << EOF
panel:
  url: "${PANEL_URL}"
  token: "${PANEL_TOKEN}"
  node_id: ${node_id}
${node_type_line}

node:
  push_interval: 0
  pull_interval: 0

kernel:
  type: "${KERNEL_TYPE}"
  config_dir: "${node_dir}"
  log_level: "warn"

log:
  level: "info"
  output: "stdout"
EOF

    log_info "Config written: ${node_dir}/config.yml"
}

add_node_native() {
    local node_id="$1"

    if [ -d "${CONFIG_DIR}/${node_id}" ]; then
        log_error "Node ${node_id} already exists at ${CONFIG_DIR}/${node_id}/"
        log_info "To reconfigure, first remove it: $0 remove ${node_id}"
        exit 1
    fi

    write_node_config "$node_id"

    if command -v systemctl >/dev/null 2>&1; then
        install_systemd_template
        systemctl enable "xboard-node@${node_id}"
        systemctl start "xboard-node@${node_id}"
        log_info "Service started: xboard-node@${node_id}"
    elif command -v rc-service >/dev/null 2>&1; then
        install_openrc_template "$node_id"
        rc-update add "xboard-node-${node_id}" default
        rc-service "xboard-node-${node_id}" start
        log_info "Service started: xboard-node-${node_id}"
    else
        log_warn "No service manager found. Start manually:"
        echo "  xboard-node -c ${CONFIG_DIR}/${node_id}/config.yml"
    fi
}

add_node_docker() {
    local node_id="$1"

    if [ -d "${CONFIG_DIR}/${node_id}" ]; then
        log_error "Node ${node_id} already exists at ${CONFIG_DIR}/${node_id}/"
        log_info "To reconfigure, first remove it: $0 remove ${node_id}"
        exit 1
    fi

    write_node_config "$node_id"
    regenerate_docker_compose
    log_info "Docker compose updated: ${DOCKER_COMPOSE_FILE}"

    if command -v docker >/dev/null 2>&1; then
        if docker compose version >/dev/null 2>&1; then
            COMPOSE_CMD="docker compose"
        elif command -v docker-compose >/dev/null 2>&1; then
            COMPOSE_CMD="docker-compose"
        else
            log_warn "docker compose not found. Start manually:"
            echo "  cd ${CONFIG_DIR} && docker compose up -d"
            return
        fi
        cd "${CONFIG_DIR}"
        ${COMPOSE_CMD} up -d "node-${node_id}"
        log_info "Container started: xboard-node-${node_id}"
    else
        log_warn "Docker not installed. Install Docker first, then run:"
        echo "  cd ${CONFIG_DIR} && docker compose up -d"
    fi
}

regenerate_docker_compose() {
    local nodes=()
    for dir in "${CONFIG_DIR}"/*/; do
        [ -f "${dir}config.yml" ] || continue
        local nid
        nid=$(basename "$dir")
        nodes+=("$nid")
    done

    if [ ${#nodes[@]} -eq 0 ]; then
        rm -f "${DOCKER_COMPOSE_FILE}"
        return
    fi

    cat > "${DOCKER_COMPOSE_FILE}" << 'HEADER'
# Auto-generated by install.sh — do not edit manually.
# Regenerated each time a node is added or removed.

services:
HEADER

    for nid in "${nodes[@]}"; do
        cat >> "${DOCKER_COMPOSE_FILE}" << EOF
  node-${nid}:
    image: ${DOCKER_IMAGE}
    container_name: xboard-node-${nid}
    restart: always
    network_mode: host
    volumes:
      - ./${nid}/config.yml:/etc/xboard-node/config.yml:ro
      - ./${nid}:/etc/xboard-node/data
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

EOF
    done
}

# ─── Deploy Node (unified entry) ─────────────────────────────────────

deploy_node() {
    if has_all_params; then
        validate_params
        log_info "Deploying node ${NODE_ID} (${KERNEL_TYPE}) → ${PANEL_URL}"
    else
        prompt_missing_params
    fi

    if [ "$DOCKER_MODE" -eq 1 ]; then
        add_node_docker "$NODE_ID"
    else
        add_node_native "$NODE_ID"
    fi

    echo ""
    echo -e "${GREEN}=== Node ${NODE_ID} Deployed ===${NC}"
    echo ""

    if [ "$DOCKER_MODE" -eq 1 ]; then
        echo "  Manage:"
        echo "    Logs:    docker logs -f xboard-node-${NODE_ID}"
        echo "    Stop:    cd ${CONFIG_DIR} && docker compose stop node-${NODE_ID}"
        echo "    Restart: cd ${CONFIG_DIR} && docker compose restart node-${NODE_ID}"
    elif command -v systemctl >/dev/null 2>&1; then
        echo "  Manage:"
        echo "    Status:  systemctl status xboard-node@${NODE_ID}"
        echo "    Logs:    journalctl -u xboard-node@${NODE_ID} -f"
        echo "    Stop:    systemctl stop xboard-node@${NODE_ID}"
        echo "    Restart: systemctl restart xboard-node@${NODE_ID}"
    elif command -v rc-service >/dev/null 2>&1; then
        echo "  Manage:"
        echo "    Status:  rc-service xboard-node-${NODE_ID} status"
        echo "    Logs:    tail -f /var/log/xboard-node-${NODE_ID}.log"
        echo "    Stop:    rc-service xboard-node-${NODE_ID} stop"
        echo "    Restart: rc-service xboard-node-${NODE_ID} restart"
    fi

    echo ""
    echo "  Config:  ${CONFIG_DIR}/${NODE_ID}/config.yml"
    echo ""
}

# ─── Remove Node ──────────────────────────────────────────────────────

remove_node() {
    local node_id="$1"

    if [ -z "$node_id" ]; then
        log_error "Usage: $0 remove <node_id>"
        exit 1
    fi

    if [ ! -d "${CONFIG_DIR}/${node_id}" ]; then
        log_error "Node ${node_id} not found"
        exit 1
    fi

    log_step "Removing node ${node_id}..."

    # Stop and disable systemd service
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop "xboard-node@${node_id}" 2>/dev/null || true
        systemctl disable "xboard-node@${node_id}" 2>/dev/null || true
        log_info "Systemd service stopped and disabled"
    fi

    # Stop and disable OpenRC service
    if command -v rc-service >/dev/null 2>&1; then
        if [ -f "/etc/init.d/xboard-node-${node_id}" ]; then
            rc-service "xboard-node-${node_id}" stop 2>/dev/null || true
            rc-update del "xboard-node-${node_id}" default 2>/dev/null || true
            rm -f "/etc/init.d/xboard-node-${node_id}"
            log_info "OpenRC service stopped and removed"
        fi
    fi

    # Stop and remove Docker container
    if command -v docker >/dev/null 2>&1; then
        docker rm -f "xboard-node-${node_id}" 2>/dev/null || true
    fi

    rm -rf "${CONFIG_DIR}/${node_id}"
    log_info "Config removed: ${CONFIG_DIR}/${node_id}/"

    regenerate_docker_compose
    log_info "Node ${node_id} removed"
}

# ─── List Nodes ───────────────────────────────────────────────────────

list_nodes() {
    echo ""
    echo -e "${BOLD}  Deployed Nodes${NC}"
    echo -e "  ────────────────────────────────────────────"

    local found=0
    for dir in "${CONFIG_DIR}"/*/; do
        [ -f "${dir}config.yml" ] || continue
        found=1

        local nid
        nid=$(basename "$dir")

        local panel_url kernel_type
        panel_url=$(grep -E '^\s*url:' "${dir}config.yml" 2>/dev/null | head -1 | sed 's/.*url:\s*"\?\([^"]*\)"\?.*/\1/')
        kernel_type=$(grep -E '^\s*type:' "${dir}config.yml" 2>/dev/null | head -1 | sed 's/.*type:\s*"\?\([^"]*\)"\?.*/\1/')

        local status="${RED}stopped${NC}"
        
        # Check systemd
        if command -v systemctl >/dev/null 2>&1; then
            if systemctl is-active "xboard-node@${nid}" >/dev/null 2>&1; then
                status="${GREEN}running (systemd)${NC}"
            fi
        fi
        
        # Check OpenRC
        if command -v rc-service >/dev/null 2>&1; then
            if [ -f "/etc/init.d/xboard-node-${nid}" ]; then
                if rc-service "xboard-node-${nid}" status >/dev/null 2>&1; then
                    status="${GREEN}running (openrc)${NC}"
                fi
            fi
        fi
        
        # Check Docker
        if command -v docker >/dev/null 2>&1; then
            if docker inspect -f '{{.State.Running}}' "xboard-node-${nid}" 2>/dev/null | grep -q true; then
                status="${GREEN}running (docker)${NC}"
            fi
        fi

        printf "  ${BOLD}Node %-6s${NC}  kernel=%-8s  panel=%s\n" "$nid" "${kernel_type:-singbox}" "${panel_url:-unknown}"
        echo -e "              status=${status}"
        echo ""
    done

    if [ "$found" -eq 0 ]; then
        echo "  No nodes deployed yet."
        echo ""
        echo "  Deploy your first node:"
        echo "    $0 -a https://panel.example.com -t TOKEN -n 1"
        echo "    $0 -a https://panel.example.com -t TOKEN -n 1 --docker"
    fi
    echo ""
}

# ─── Update / Uninstall ──────────────────────────────────────────────

update_binary() {
    log_step "Updating xboard-node binary..."

    detect_arch

    local url="https://github.com/cedar2025/xboard-node/releases/latest/download/xboard-node-linux-${ARCH}"
    local tmp="/tmp/xboard-node-update"

    if wget -q "$url" -O "$tmp" 2>/dev/null || curl -fsSL "$url" -o "$tmp" 2>/dev/null; then
        chmod +x "$tmp"
        mv "$tmp" "${INSTALL_DIR}/xboard-node"
        log_info "Binary updated"
    else
        log_error "Failed to download update"
        rm -f "$tmp"
        exit 1
    fi

    # Restart systemd services
    if command -v systemctl >/dev/null 2>&1; then
        for dir in "${CONFIG_DIR}"/*/; do
            [ -f "${dir}config.yml" ] || continue
            local nid
            nid=$(basename "$dir")
            if systemctl is-active "xboard-node@${nid}" >/dev/null 2>&1; then
                systemctl restart "xboard-node@${nid}"
                log_info "Restarted: xboard-node@${nid}"
            fi
        done
    fi

    # Restart OpenRC services
    if command -v rc-service >/dev/null 2>&1; then
        for dir in "${CONFIG_DIR}"/*/; do
            [ -f "${dir}config.yml" ] || continue
            local nid
            nid=$(basename "$dir")
            if [ -f "/etc/init.d/xboard-node-${nid}" ]; then
                if rc-service "xboard-node-${nid}" status >/dev/null 2>&1; then
                    rc-service "xboard-node-${nid}" restart 2>/dev/null || log_warn "Failed to restart xboard-node-${nid}"
                    log_info "Restarted: xboard-node-${nid}"
                fi
            fi
        done
    fi

    if [ -f "${DOCKER_COMPOSE_FILE}" ] && command -v docker >/dev/null 2>&1; then
        log_info "For Docker nodes, pull the latest image and restart:"
        echo "  cd ${CONFIG_DIR} && docker compose pull && docker compose up -d"
    fi
}

do_uninstall() {
    log_step "Uninstalling xboard-node..."

    # Stop and disable all systemd services
    if command -v systemctl >/dev/null 2>&1; then
        for dir in "${CONFIG_DIR}"/*/; do
            [ -f "${dir}config.yml" ] || continue
            local nid
            nid=$(basename "$dir")
            systemctl stop "xboard-node@${nid}" 2>/dev/null || true
            systemctl disable "xboard-node@${nid}" 2>/dev/null || true
        done
        systemctl stop xboard-node 2>/dev/null || true
        systemctl disable xboard-node 2>/dev/null || true
        rm -f /etc/systemd/system/xboard-node.service
        rm -f "/etc/systemd/system/${SERVICE_TEMPLATE}"
        systemctl daemon-reload
    fi

    # Stop and disable all OpenRC services
    if command -v rc-service >/dev/null 2>&1; then
        for dir in "${CONFIG_DIR}"/*/; do
            [ -f "${dir}config.yml" ] || continue
            local nid
            nid=$(basename "$dir")
            if [ -f "/etc/init.d/xboard-node-${nid}" ]; then
                rc-service "xboard-node-${nid}" stop 2>/dev/null || true
                rc-update del "xboard-node-${nid}" default 2>/dev/null || true
            fi
        done
        rm -f /etc/init.d/xboard-node-*
    fi

    # Stop and remove all Docker containers
    if command -v docker >/dev/null 2>&1; then
        for dir in "${CONFIG_DIR}"/*/; do
            [ -f "${dir}config.yml" ] || continue
            local nid
            nid=$(basename "$dir")
            docker rm -f "xboard-node-${nid}" 2>/dev/null || true
        done
    fi

    rm -f "${INSTALL_DIR}/xboard-node"
    log_info "Binary removed"

    echo ""
    read -rp "  Delete all configs? (${CONFIG_DIR}) [y/N]: " DELETE_ALL
    if [[ "$DELETE_ALL" =~ ^[Yy]$ ]]; then
        rm -rf "${CONFIG_DIR}"
        log_info "All configs removed"
    else
        log_info "Configs preserved at ${CONFIG_DIR}/"
    fi

    log_info "xboard-node uninstalled"
}

# ─── Print Help ───────────────────────────────────────────────────────

print_help() {
    cat << 'HELP'

  xboard-node Deploy Script

  DEPLOY A NODE (one command, repeat for each node):

    install.sh -a <url> -t <token> -n <node_id> [-T <node_type>] [-k singbox|xray] [--docker]

  OPTIONS:
    -a, --api        Panel URL          (e.g. https://panel.example.com)
    -t, --token      Server Token       (from panel settings)
    -n, --node-id    Node ID            (positive integer)
    -T, --node-type  Node type          (optional, auto-detected from panel)
    -k, --kernel     Kernel type        (singbox or xray, default: singbox)
    --docker         Use Docker instead of systemd

  EXAMPLES:

    # Deploy node 1 (sing-box, systemd):
    bash install.sh -a https://panel.example.com -t mytoken123 -n 1

    # Deploy node 2 (xray, systemd):
    bash install.sh -a https://panel.example.com -t mytoken123 -n 2 -k xray

    # Deploy node 3 with explicit type (Docker):
    bash install.sh -a https://panel.example.com -t mytoken123 -n 3 -T shadowsocks --docker

    # Interactive mode (will prompt for all params):
    bash install.sh

  MANAGEMENT:

    bash install.sh list               List all deployed nodes
    bash install.sh remove <node_id>   Remove a node
    bash install.sh update             Update binary + restart all nodes
    bash install.sh uninstall          Remove everything

  DOCKER (env-var mode, no config file needed):

    docker run -d --restart=always --network=host \
      -e apiHost=https://panel.example.com \
      -e apiKey=YOUR_TOKEN \
      -e nodeID=1 \
      ghcr.io/cedar2025/xboard-node:latest

HELP
}

# ─── Main ─────────────────────────────────────────────────────────────

main() {
    parse_args "$@"

    case "$SUBCOMMAND" in
        remove)
            check_root
            remove_node "$NODE_ID"
            ;;
        list)
            list_nodes
            ;;
        update)
            check_root
            update_binary
            ;;
        uninstall)
            check_root
            do_uninstall
            ;;
        help|--help|-h)
            print_help
            ;;
        add|"")
            check_root
            detect_arch
            detect_os
            install_deps
            mkdir -p "$CONFIG_DIR"
            migrate_legacy_config

            if [ "$DOCKER_MODE" -eq 0 ]; then
                install_binary
                install_systemd_template
            fi

            deploy_node
            ;;
        *)
            log_error "Unknown command: $SUBCOMMAND"
            print_help
            exit 1
            ;;
    esac
}

main "$@"
