#!/usr/bin/env bash
# =============================================================================
# xray-wg-deploy.sh — Xray-core WireGuard + FinalMask 一键部署
#
# Features:
#   - Pick one of 8 scenarios (WireGuard or VLESS based)
#   - Auto-detect VPS IPv4/IPv6
#   - Auto-generate all keys & passwords (x25519)
#   - Auto-detect domain need → ACME.sh cert
#   - Install Xray-core (direct binary from GitHub)
#   - Force Cloudflare DNS on Xray-core level
#   - Generate client config + QR code
#   - Simple TUI menu
#
# Usage:
#   bash xray-wg-deploy.sh          # interactive menu
#   bash xray-wg-deploy.sh 08       # deploy scenario 08 directly
#   bash xray-wg-deploy.sh 08 docker  # deploy with Docker
# =============================================================================

set -euo pipefail

# ─── Error trap: show line number on failure ─────────────────────────
trap 'echo -e "\n${RED}ERROR at line $LINENO — exiting${NC}" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_DIR="$SCRIPT_DIR/.."
SERVER_DIR="$CONFIG_DIR/server"
CLIENT_DIR="$CONFIG_DIR/client"

# Auto-detect if running standalone (no repo cloned alongside)
STANDALONE=false
if [ ! -d "$SERVER_DIR" ] || [ ! -d "$CLIENT_DIR" ]; then
  STANDALONE=true
  SERVER_DIR=""
  CLIENT_DIR=""
fi
DEPLOY_DIR="/opt/xray-wg"
CLIENT_OUT_DIR="$SCRIPT_DIR/clients"
XRAY_VERSION="v26.3.27"

# ─── Colors ───────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ─── State ────────────────────────────────────────────────────────────
SCENARIO=""
DEPLOY_MODE="binary"   # binary | docker
VPS_IPV4=""
VPS_IPV6=""
DOMAIN=""
NEED_DOMAIN=false
NEED_TLS=false
USE_WIREGUARD=false
USE_VLESS=false

# Keys/Secrets (generated per-run)
declare -A KEYS
declare -A PASSWORDS
UUID=""

# ─── Banner ───────────────────────────────────────────────────────────
banner() {
  echo -e "${CYAN}${BOLD}"
  echo "╔══════════════════════════════════════════════════════════╗"
  echo "║   Xray-core WireGuard + FinalMask  一键部署脚本         ║"
  echo "║   v26.3.27  |  auto keys  |  QR client  |  CF DNS      ║"
  echo "╚══════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
}

# ─── TUI: Menu ───────────────────────────────────────────────────────
show_menu() {
  echo ""
  echo -e "${BOLD}Choose deployment scenario:${NC}"
  echo ""
  echo -e "  ${GREEN}WireGuard + FinalMask (real WG tunnel):${NC}"
  echo "  [1]  WG + header-custom           (custom binary headers)"
  echo "  [2]  WG + header-wireguard        (WG-in-WG double pattern)"
  echo "  [3]  WG + stacked (custom+noise+salamander)   ★ strongest"
  echo "  [4]  WG + header-dtls             (DTLS 1.2 mimicry)"
  echo "  [5]  WG multi-peer + header-custom"
  echo ""
  echo -e "  ${YELLOW}VLESS + FinalMask (v2rayN share-link compatible):${NC}"
  echo "  [6]  VLESS+mKCP + header-wireguard    (disguised as WG)"
  echo "  [7]  VLESS+TCP+TLS + header-custom    (needs domain)"
  echo ""
  echo -e "  ${CYAN}Multi-Inbound (multiple WG on one VPS):${NC}"
  echo "  [8]  WG x4 strong obfuscation     ★ all in one"
  echo ""
  echo "  [q]  Quit"
  echo ""
  read -r -p "Choice [1-8/q]: " choice

  case "$choice" in
    1) SCENARIO="01"; DEPLOY_MODE="${2:-binary}" ;;
    2) SCENARIO="04"; DEPLOY_MODE="${2:-binary}" ;;
    3) SCENARIO="05"; DEPLOY_MODE="${2:-binary}" ;;
    4) SCENARIO="06"; DEPLOY_MODE="${2:-binary}" ;;
    5) SCENARIO="07"; DEPLOY_MODE="${2:-binary}" ;;
    6) SCENARIO="02"; DEPLOY_MODE="${2:-binary}" ;;
    7) SCENARIO="03"; DEPLOY_MODE="${2:-binary}"; NEED_DOMAIN=true; NEED_TLS=true ;;
    8) SCENARIO="08"; DEPLOY_MODE="${2:-binary}" ;;
    q|Q) echo "Bye."; exit 0 ;;
    *) echo -e "${RED}Invalid choice.${NC}"; show_menu "$@" ;;
  esac
}

# ─── IP Detection ────────────────────────────────────────────────────
detect_ips() {
  echo -e "\n${BLUE}→ Detecting VPS IP addresses...${NC}"

  VPS_IPV4=$(curl -4 -s --max-time 5 ifconfig.me 2>/dev/null || \
             curl -4 -s --max-time 5 ipinfo.io/ip 2>/dev/null || \
             curl -4 -s --max-time 5 icanhazip.com 2>/dev/null || echo "")

  VPS_IPV6=$(curl -6 -s --max-time 5 ifconfig.me 2>/dev/null || \
             curl -6 -s --max-time 5 ipinfo.io/ip 2>/dev/null || \
             curl -6 -s --max-time 5 icanhazip.com 2>/dev/null || echo "")

  if [ -z "$VPS_IPV4" ] && [ -z "$VPS_IPV6" ]; then
    echo -e "${RED}ERROR: Cannot detect any public IP. Check network.${NC}"
    exit 1
  fi

  echo -e "  IPv4: ${GREEN}${VPS_IPV4:-none}${NC}"
  echo -e "  IPv6: ${GREEN}${VPS_IPV6:-none}${NC}"
}

# ─── Key Generation ──────────────────────────────────────────────────
gen_keys() {
  echo -e "\n${BLUE}→ Generating cryptographic keys...${NC}"

  # Check for xray (for x25519) or fall back to wg
  local XRAY_BIN=""
  if command -v xray &>/dev/null; then
    XRAY_BIN="xray"
  elif [ -f /usr/local/bin/xray ]; then
    XRAY_BIN="/usr/local/bin/xray"
  fi

  x25519() {
    if [ -n "$XRAY_BIN" ]; then
      $XRAY_BIN x25519 2>/dev/null | head -2
    else
      # Fallback: use openssl to generate x25519 keys
      # Generate private key (32 bytes base64)
      local priv=$(openssl rand -base64 32 | tr -d '\n' | head -c 44)
      # Derive public key (simplified - in real deployment xray handles this)
      # For deployment script, we just need the keys to exist
      echo "Priv: placeholder-run-xray-x25519"
      echo "Pub:  placeholder-run-xray-x25519"
    fi
  }

  # WireGuard scenarios need WG key pairs
  case "$SCENARIO" in
    01|04|05|06|07|08)
      USE_WIREGUARD=true
      echo -e "  ${YELLOW}Generating WireGuard key pairs...${NC}"

      if [ -n "$XRAY_BIN" ]; then
        # Server keys
        local srv_keys
        srv_keys=$($XRAY_BIN x25519 2>/dev/null)
        KEYS["SRV_PRIV"]=$(echo "$srv_keys" | sed -n '1p' | awk '{print $NF}')
        KEYS["SRV_PUB"]=$(echo "$srv_keys"  | sed -n '2p' | awk '{print $NF}')

        # Client keys
        local cli_keys
        cli_keys=$($XRAY_BIN x25519 2>/dev/null)
        KEYS["CLI_PRIV"]=$(echo "$cli_keys" | sed -n '1p' | awk '{print $NF}')
        KEYS["CLI_PUB"]=$(echo "$cli_keys"  | sed -n '2p' | awk '{print $NF}')

        # For multi-peer/multi-inbound: gen extra keys
        if [ "$SCENARIO" = "07" ] || [ "$SCENARIO" = "08" ]; then
          for i in $(seq 2 4); do
            local extra
            extra=$($XRAY_BIN x25519 2>/dev/null)
            KEYS["CLI${i}_PRIV"]=$(echo "$extra" | sed -n '1p' | awk '{print $NF}')
            KEYS["CLI${i}_PUB"]=$(echo "$extra"  | sed -n '2p' | awk '{print $NF}')
          done
        fi
      elif command -v wg &>/dev/null; then
        KEYS["SRV_PRIV"]=$(wg genkey)
        KEYS["SRV_PUB"]=$(echo "${KEYS["SRV_PRIV"]}" | wg pubkey)
        KEYS["CLI_PRIV"]=$(wg genkey)
        KEYS["CLI_PUB"]=$(echo "${KEYS["CLI_PRIV"]}" | wg pubkey)
      else
        echo -e "${RED}ERROR: Need 'xray' or 'wg' for key generation.${NC}"
        echo "Install xray first, or run: apt install wireguard-tools / dnf install wireguard-tools"
        exit 1
      fi
      echo -e "  Server PubKey: ${GREEN}${KEYS["SRV_PUB"]:0:12}...${NC}"
      echo -e "  Client PubKey: ${GREEN}${KEYS["CLI_PUB"]:0:12}...${NC}"
      ;;
  esac

  # VLESS scenarios need UUID
  case "$SCENARIO" in
    02|03)
      USE_VLESS=true
      if [ -n "$XRAY_BIN" ]; then
        UUID=$($XRAY_BIN uuid 2>/dev/null || echo "")
      fi
      if [ -z "$UUID" ]; then
        UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || \
               python3 -c "import uuid; print(uuid.uuid4())" 2>/dev/null || \
               openssl rand -hex 16 | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\3-\4/')
      fi
      echo -e "  VLESS UUID:  ${GREEN}${UUID}${NC}"
      ;;
  esac

  # Generate obfuscation passwords
  gen_password() {
    if [ -n "$XRAY_BIN" ]; then
      $XRAY_BIN x25519 2>/dev/null | sed -n '1p' | awk '{print $NF}' | head -c 32
    else
      openssl rand -base64 24 | tr -d '\n' | head -c 32
    fi
  }

  case "$SCENARIO" in
    03)
      PASSWORDS["HEADER_HEX"]=$(openssl rand -hex 4)
      ;;
    05)
      PASSWORDS["SALAMANDER"]=$(gen_password)
      ;;
    08)
      PASSWORDS["AES"]=$(gen_password)
      PASSWORDS["SALAM"]=$(gen_password)
      PASSWORDS["SUDOK"]=$(gen_password)
      ;;
  esac
}

# ─── Domain & ACME ───────────────────────────────────────────────────
setup_domain() {
  if ! $NEED_DOMAIN; then
    return 0
  fi

  echo -e "\n${BLUE}→ Domain setup (needed for TLS)...${NC}"
  read -r -p "Your domain name (e.g., vps.example.com): " DOMAIN

  if [ -z "$DOMAIN" ]; then
    echo -e "${RED}ERROR: Domain required for this scenario.${NC}"
    exit 1
  fi

  echo -e "  Domain: ${GREEN}${DOMAIN}${NC}"

  # Check if acme.sh is installed
  if ! command -v acme.sh &>/dev/null; then
    echo -e "  ${YELLOW}Installing acme.sh...${NC}"
    curl -sS https://get.acme.sh | sh -s email="admin@${DOMAIN}" || {
      echo -e "${RED}ERROR: Failed to install acme.sh${NC}"
      exit 1
    }
    # shellcheck source=/dev/null
    source ~/.bashrc 2>/dev/null || true
    export PATH="$HOME/.acme.sh:$PATH"
  fi

  # Issue certificate
  echo -e "  ${YELLOW}Issuing TLS certificate via acme.sh...${NC}"
  mkdir -p /etc/ssl/xray

  # Stop anything on port 80 first
  fuser -k 80/tcp 2>/dev/null || true

  ~/.acme.sh/acme.sh --issue \
    -d "$DOMAIN" \
    --standalone \
    --keylength ec-256 \
    --force 2>/dev/null || {
    echo -e "${RED}ACME issue failed. Check DNS points to this VPS.${NC}"
    exit 1
  }

  ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
    --key-file       /etc/ssl/xray/server.key \
    --fullchain-file /etc/ssl/xray/server.crt

  echo -e "  ${GREEN}Certificate installed to /etc/ssl/xray/${NC}"
}

# ─── Cloudflare DNS Config ───────────────────────────────────────────
cf_dns_config() {
  # Returns JSON fragment for Xray-core DNS config forcing Cloudflare
  cat <<'DNSEOF'
  "dns": {
    "servers": [
      {
        "address": "https://1.1.1.1/dns-query",
        "domains": ["geosite:geolocation-!cn"]
      },
      {
        "address": "https://1.0.0.1/dns-query",
        "domains": ["geosite:geolocation-!cn"]
      },
      {
        "address": "https://dns.cloudflare.com/dns-query",
        "domains": ["geosite:geolocation-!cn"]
      },
      "localhost"
    ],
    "clientIp": "1.1.1.1"
  },
DNSEOF
}

# ─── Xray-core Install ───────────────────────────────────────────────
install_xray() {
  echo -e "\n${BLUE}→ Installing Xray-core ${XRAY_VERSION}...${NC}"

  local ARCH
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64)  ARCH="64" ;;
    aarch64) ARCH="arm64-v8a" ;;
    armv7l)  ARCH="arm32-v7a" ;;
    armv6l)  ARCH="arm32-v6" ;;
    *) echo -e "${RED}Unsupported arch: ${ARCH}${NC}"; exit 1 ;;
  esac

  local OS
  OS=$(uname -s | tr '[:upper:]' '[:lower:]')

  # Xray release uses: Xray-linux-64.zip (not Xray-linux-amd64.zip)
  local URL="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-${OS}-${ARCH}.zip"
  local TMP_DIR
  TMP_DIR=$(mktemp -d)

  echo "  Downloading: $URL"
  if ! curl -sSL --retry 3 --retry-delay 2 "$URL" -o "$TMP_DIR/xray.zip"; then
    echo -e "${RED}ERROR: Failed to download Xray-core${NC}"
    echo "  URL: $URL"
    echo "  Check network or try a different version"
    exit 1
  fi

  mkdir -p /usr/local/bin /usr/local/share/xray

  unzip -qo "$TMP_DIR/xray.zip" -d "$TMP_DIR/xray"
  cp "$TMP_DIR/xray/xray" /usr/local/bin/xray
  chmod +x /usr/local/bin/xray

  # Geo files are bundled inside the zip
  cp "$TMP_DIR/xray/geoip.dat" /usr/local/share/xray/geoip.dat 2>/dev/null || true
  cp "$TMP_DIR/xray/geosite.dat" /usr/local/share/xray/geosite.dat 2>/dev/null || true

  rm -rf "$TMP_DIR"

  echo -e "  ${GREEN}Xray-core installed: $(/usr/local/bin/xray version 2>/dev/null | head -1)${NC}"
}

# ─── Config Generation ───────────────────────────────────────────────
generate_config() {
  echo -e "\n${BLUE}→ Generating server config...${NC}"

  mkdir -p "$DEPLOY_DIR"

  local OUT="$DEPLOY_DIR/config.json"
  local TEMPLATE=""

  # Try local template first (only if repo is cloned)
  if [ -n "$SERVER_DIR" ] && [ -d "$SERVER_DIR" ]; then
    TEMPLATE=$(ls "$SERVER_DIR/${SCENARIO}-"*.json 2>/dev/null | head -1) || true
  fi

  # If running standalone (curl'd script, no repo), download template from GitHub
  if [ -z "$TEMPLATE" ] || [ ! -f "$TEMPLATE" ]; then
    local RAW_BASE="https://raw.githubusercontent.com/takashi728/xray-wireguard-finalmask/main/server"
    # Known template filenames per scenario (from repo)
    local TPL_FILE
    case "$SCENARIO" in
      01) TPL_FILE="01-wg-headercustom.json" ;;
      02) TPL_FILE="02-vless-kcp-headerwireguard.json" ;;
      03) TPL_FILE="03-vless-tcp-headercustom.json" ;;
      04) TPL_FILE="04-wg-headerwireguard.json" ;;
      05) TPL_FILE="05-wg-stacked.json" ;;
      06) TPL_FILE="06-wg-headerdtls.json" ;;
      07) TPL_FILE="07-wg-multipeer.json" ;;
      08) TPL_FILE="08-wg-multi-header.json" ;;
    esac

    if [ -n "$TPL_FILE" ]; then
      echo "  Downloading server template from GitHub..."
      TEMPLATE="$DEPLOY_DIR/template-${SCENARIO}.json"
      curl -sSL --retry 3 --retry-delay 2 "${RAW_BASE}/${TPL_FILE}" -o "$TEMPLATE" || {
        echo -e "${RED}ERROR: Failed to download template from GitHub${NC}"
        echo "  URL: ${RAW_BASE}/${TPL_FILE}"
        echo "  Check network or clone the repo:"
        echo "  git clone https://github.com/takashi728/xray-wireguard-finalmask.git"
        exit 1
      }
    fi
  fi

  if [ ! -f "$TEMPLATE" ]; then
    echo -e "${RED}ERROR: Template not found for scenario $SCENARIO${NC}"
    echo "  Clone the repo: git clone https://github.com/takashi728/xray-wireguard-finalmask.git"
    exit 1
  fi

  echo "  Template: $(basename "$TEMPLATE")"

  # Read template and substitute placeholders
  local config
  config=$(cat "$TEMPLATE")

  # Substitute WireGuard keys
  config=${config//<SERVER_PRIVATE_KEY>/${KEYS["SRV_PRIV"]:-PLACEHOLDER}}
  config=${config//<SERVER1_PRIVATE_KEY>/${KEYS["SRV_PRIV"]:-PLACEHOLDER}}
  config=${config//<SERVER2_PRIVATE_KEY>/${KEYS["CLI2_PRIV"]:-PLACEHOLDER}}
  config=${config//<SERVER3_PRIVATE_KEY>/${KEYS["CLI3_PRIV"]:-PLACEHOLDER}}
  config=${config//<SERVER4_PRIVATE_KEY>/${KEYS["CLI4_PRIV"]:-PLACEHOLDER}}

  config=${config//<CLIENT_PUBLIC_KEY>/${KEYS["CLI_PUB"]:-PLACEHOLDER}}
  config=${config//<PEER1A_PUBLIC_KEY>/${KEYS["CLI_PUB"]:-PLACEHOLDER}}
  config=${config//<PEER2A_PUBLIC_KEY>/${KEYS["CLI2_PUB"]:-PLACEHOLDER}}
  config=${config//<PEER3A_PUBLIC_KEY>/${KEYS["CLI3_PUB"]:-PLACEHOLDER}}
  config=${config//<PEER4A_PUBLIC_KEY>/${KEYS["CLI4_PUB"]:-PLACEHOLDER}}

  # Substitute UUID
  config=${config//<UUID>/${UUID:-PLACEHOLDER}}

  # Substitute passwords
  config=${config//<PASSWORD_AES>/${PASSWORDS["AES"]:-}}
  config=${config//<PASSWORD_SALAM>/${PASSWORDS["SALAM"]:-}}
  config=${config//<PASSWORD_SUDOK>/${PASSWORDS["SUDOK"]:-}}
  config=${config//<SALAMANDER_PASSWORD>/${PASSWORDS["SALAMANDER"]:-${PASSWORDS["SALAM"]:-}}}

  # Substitute domain
  config=${config//your-domain.com/${DOMAIN:-}}

  # Inject Cloudflare DNS config (before "outbounds")
  local dns_json
  dns_json=$(cf_dns_config)
  config=${config/\"outbounds\"/$dns_json\"outbounds\"}

  # Write config (use printf to avoid echo interpreting backslash escapes)
  printf '%s\n' "$config" > "$OUT"

  # Validate JSON
  if command -v python3 &>/dev/null; then
    if ! python3 -c "import json,re; json.loads(re.sub(r'//[^\n]*','',open('$OUT').read()))" 2>/dev/null; then
      echo -e "${RED}WARNING: Generated config may have JSON issues. Check $OUT${NC}"
    fi
  fi

  echo -e "  ${GREEN}Server config: $OUT${NC}"
}

# ─── Systemd Service ─────────────────────────────────────────────────
setup_service() {
  echo -e "\n${BLUE}→ Setting up systemd service...${NC}"

  cat > /etc/systemd/system/xray-wg.service <<EOF
[Unit]
Description=Xray-core WireGuard + FinalMask
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -config $DEPLOY_DIR/config.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable xray-wg
  systemctl restart xray-wg

  sleep 2

  if systemctl is-active --quiet xray-wg; then
    echo -e "  ${GREEN}Service running: xray-wg${NC}"
  else
    echo -e "  ${RED}Service failed to start! Check: journalctl -u xray-wg -n 50${NC}"
    journalctl -u xray-wg -n 20 --no-pager
    exit 1
  fi
}

# ─── Client Config Generation ────────────────────────────────────────
generate_client() {
  echo -e "\n${BLUE}→ Generating client config...${NC}"

  mkdir -p "$CLIENT_OUT_DIR"

  local CLIENT_TEMPLATE=""

  # Try local template first (only if repo is cloned)
  if [ -n "$CLIENT_DIR" ] && [ -d "$CLIENT_DIR" ]; then
    CLIENT_TEMPLATE=$(ls "$CLIENT_DIR/${SCENARIO}-"*.json 2>/dev/null | head -1) || true
  fi

  # Download client template from GitHub if running standalone
  if [ -z "$CLIENT_TEMPLATE" ] || [ ! -f "$CLIENT_TEMPLATE" ]; then
    local RAW_BASE="https://raw.githubusercontent.com/takashi728/xray-wireguard-finalmask/main/client"
    local TPL_FILE
    case "$SCENARIO" in
      01) TPL_FILE="01-wg-headercustom.json" ;;
      02) TPL_FILE="02-vless-kcp-headerwireguard.json" ;;
      03) TPL_FILE="03-vless-tcp-headercustom.json" ;;
      04) TPL_FILE="04-wg-headerwireguard.json" ;;
      05) TPL_FILE="05-wg-stacked.json" ;;
      06) TPL_FILE="06-wg-headerdtls.json" ;;
      07) TPL_FILE="" ;;  # no client template for multi-peer server-only
      08) TPL_FILE="08-wg-multi-header.json" ;;
    esac
    if [ -n "$TPL_FILE" ]; then
      echo "  Downloading client template from GitHub..."
      CLIENT_TEMPLATE="$DEPLOY_DIR/client-template-${SCENARIO}.json"
      curl -sSL --retry 3 --retry-delay 2 "${RAW_BASE}/${TPL_FILE}" -o "$CLIENT_TEMPLATE" || {
        echo -e "${YELLOW}WARNING: Failed to download client template — will generate minimal config${NC}"
        CLIENT_TEMPLATE=""
      }
    fi
  fi

  if [ ! -f "$CLIENT_TEMPLATE" ]; then
    echo -e "  ${YELLOW}No client template for scenario $SCENARIO. Generating minimal config.${NC}"
    generate_minimal_client
    return
  fi

  local client_config
  client_config=$(cat "$CLIENT_TEMPLATE")

  # Apply same substitutions
  client_config=${client_config//<CLIENT_PRIVATE_KEY>/${KEYS["CLI_PRIV"]:-PLACEHOLDER}}
  client_config=${client_config//<CLIENT1_PRIVATE_KEY>/${KEYS["CLI_PRIV"]:-PLACEHOLDER}}
  client_config=${client_config//<CLIENT2_PRIVATE_KEY>/${KEYS["CLI2_PRIV"]:-PLACEHOLDER}}
  client_config=${client_config//<CLIENT3_PRIVATE_KEY>/${KEYS["CLI3_PRIV"]:-PLACEHOLDER}}
  client_config=${client_config//<CLIENT4_PRIVATE_KEY>/${KEYS["CLI4_PRIV"]:-PLACEHOLDER}}

  client_config=${client_config//<SERVER_PUBLIC_KEY>/${KEYS["SRV_PUB"]:-PLACEHOLDER}}
  client_config=${client_config//<SERVER1_PUBLIC_KEY>/${KEYS["SRV_PUB"]:-PLACEHOLDER}}
  client_config=${client_config//<SERVER2_PUBLIC_KEY>/${KEYS["CLI2_PUB"]:-PLACEHOLDER}}
  client_config=${client_config//<SERVER3_PUBLIC_KEY>/${KEYS["CLI3_PUB"]:-PLACEHOLDER}}
  client_config=${client_config//<SERVER4_PUBLIC_KEY>/${KEYS["CLI4_PUB"]:-PLACEHOLDER}}

  client_config=${client_config//<SERVER_IP>/${VPS_IPV4:-$VPS_IPV6}}
  client_config=${client_config//<UUID>/${UUID:-}}

  client_config=${client_config//<PASSWORD_AES>/${PASSWORDS["AES"]:-}}
  client_config=${client_config//<PASSWORD_SALAM>/${PASSWORDS["SALAM"]:-}}
  client_config=${client_config//<PASSWORD_SUDOK>/${PASSWORDS["SUDOK"]:-}}
  client_config=${client_config//<SALAMANDER_PASSWORD>/${PASSWORDS["SALAMANDER"]:-${PASSWORDS["SALAM"]:-}}}

  client_config=${client_config//your-domain.com/${DOMAIN:-}}

  local OUT_FILE="$CLIENT_OUT_DIR/client-${SCENARIO}-$(date +%Y%m%d-%H%M%S).json"
  printf '%s\n' "$client_config" > "$OUT_FILE"

  echo -e "  ${GREEN}Client config: $OUT_FILE${NC}"
  echo "  $(wc -c < "$OUT_FILE") bytes"
}

generate_minimal_client() {
  # Generate standalone WG config for manual import
  local OUT_FILE="$CLIENT_OUT_DIR/client-${SCENARIO}-wg.conf"
  cat > "$OUT_FILE" <<EOF
[Interface]
PrivateKey = ${KEYS["CLI_PRIV"]:-PLACEHOLDER}
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = ${KEYS["SRV_PUB"]:-PLACEHOLDER}
Endpoint = ${VPS_IPV4:-$VPS_IPV6}:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
  echo -e "  ${GREEN}Standalone WG config: $OUT_FILE${NC}"
}

# ─── QR Code Generation ──────────────────────────────────────────────
generate_qr() {
  echo -e "\n${BLUE}→ Generating QR codes...${NC}"

  # For VLESS: generate share link
  if $USE_VLESS; then
    local share_link=""
    case "$SCENARIO" in
      02)
        # vless://UUID@IP:PORT?type=kcp&security=none&headerType=none&fm=header-wireguard#WG-Disguise
        share_link="vless://${UUID}@${VPS_IPV4:-$VPS_IPV6}:51820?type=kcp&security=none&headerType=none&fm=udp-header-wireguard#Xray-WG-Disguise"
        ;;
      03)
        share_link="vless://${UUID}@${DOMAIN:-$VPS_IPV4}:443?type=tcp&security=tls&flow=&fm=tcp-header-custom#Xray-TCP-Custom"
        ;;
    esac

    echo -e "  ${CYAN}Share link:${NC}"
    echo -e "  ${GREEN}${share_link}${NC}"
    echo ""

    # QR the share link
    if command -v qrencode &>/dev/null; then
      qrencode -t ANSIUTF8 -m 1 -s 2 "$share_link" 2>/dev/null || \
      qrencode -t UTF8 "$share_link"
    elif python3 -c "import qrcode" 2>/dev/null; then
      python3 -c "
import qrcode, sys
qr = qrcode.QRCode(border=1)
qr.add_data('$share_link')
qr.make()
qr.print_ascii()
" 2>/dev/null || echo "  (QR generation failed — copy share link above)"
    else
      echo -e "  ${YELLOW}Install 'qrencode' or 'pip install qrcode' for QR.${NC}"
      echo "  Share link saved above."
    fi

    printf '%s\n' "$share_link" > "$CLIENT_OUT_DIR/share-link-${SCENARIO}.txt"
  fi

  # For WireGuard: QR the JSON client config (base64 compressed)
  if $USE_WIREGUARD; then
    local latest_client
    latest_client=$(ls -t "$CLIENT_OUT_DIR"/client-*.json 2>/dev/null | head -1) || true

    if [ -f "$latest_client" ]; then
      # Compress client config for QR
      local encoded
      encoded=$(python3 -c "
import json, sys, base64, gzip
with open('$latest_client') as f:
    data = json.loads('\n'.join(
        l for l in f if not l.strip().startswith('//')
    ))
compact = json.dumps(data, separators=(',', ':')).encode()
compressed = base64.urlsafe_b64encode(gzip.compress(compact)).decode()
print('xray://' + compressed)
" 2>/dev/null || echo "")

      if [ -n "$encoded" ]; then
        echo -e "  ${CYAN}Client config (xray:// link — import into v2rayN/FocoX etc.):${NC}"
        echo -e "  ${GREEN}${encoded:0:80}...${NC}"
        printf '%s\n' "$encoded" > "$CLIENT_OUT_DIR/xray-link-${SCENARIO}.txt"

        # QR the compressed link
        if command -v qrencode &>/dev/null; then
          qrencode -t ANSIUTF8 -m 1 -s 2 "$encoded" 2>/dev/null || \
          qrencode -t UTF8 "$encoded"
        elif python3 -c "import qrcode" 2>/dev/null; then
          python3 -c "
import qrcode
qr = qrcode.QRCode(border=1)
qr.add_data('''$encoded''')
qr.make()
qr.print_ascii()
" 2>/dev/null || echo "  (QR too large for terminal — check file below)"
        fi
      fi
    fi

    echo ""
    echo -e "  ${CYAN}Client config files:${NC}"
    ls -la "$CLIENT_OUT_DIR"/ 2>/dev/null | grep -v "^total"
  fi
}

# ─── Firewall ────────────────────────────────────────────────────────
setup_firewall() {
  echo -e "\n${BLUE}→ Configuring firewall...${NC}"

  # Determine ports from scenario
  local ports=""
  case "$SCENARIO" in
    01|04|06) ports="51820" ;;
    02)       ports="51820" ;;
    03)       ports="443" ;;
    05)       ports="51820" ;;
    07)       ports="51820" ;;
    08)       ports="51820 51821 51822 51823" ;;
  esac

  for port in $ports; do
    local proto="udp"
    [ "$SCENARIO" = "03" ] && proto="tcp"

    # firewalld
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
      firewall-cmd --add-port="${port}/${proto}" --permanent 2>/dev/null || true
    fi

    # ufw
    if command -v ufw &>/dev/null; then
      ufw allow "${port}/${proto}" 2>/dev/null || true
    fi

    # iptables (fallback)
    if ! command -v firewall-cmd &>/dev/null && ! command -v ufw &>/dev/null; then
      iptables -A INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || true
      ip6tables -A INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || true
    fi

    echo "  Opened: ${port}/${proto}"
  done

  # Reload firewalld
  if command -v firewall-cmd &>/dev/null; then
    firewall-cmd --reload 2>/dev/null || true
  fi

  echo -e "  ${GREEN}Firewall configured.${NC}"
}

# ─── Summary ─────────────────────────────────────────────────────────
print_summary() {
  echo ""
  echo -e "${CYAN}${BOLD}"
  echo "╔══════════════════════════════════════════════════════════╗"
  echo "║                   Deployment Complete                    ║"
  echo "╚══════════════════════════════════════════════════════════╝"
  echo -e "${NC}"

  echo -e "  Scenario:    ${GREEN}${SCENARIO}${NC}"
  echo -e "  VPS IPv4:    ${GREEN}${VPS_IPV4:-none}${NC}"
  echo -e "  VPS IPv6:    ${GREEN}${VPS_IPV6:-none}${NC}"
  [ -n "$DOMAIN" ] && echo -e "  Domain:      ${GREEN}${DOMAIN}${NC}"

  if $USE_WIREGUARD; then
    echo -e "  Server Pub:  ${GREEN}${KEYS["SRV_PUB"]}${NC}"
    echo -e "  Client Priv: ${GREEN}${KEYS["CLI_PRIV"]}${NC}"
    echo -e "  Client Pub:  ${GREEN}${KEYS["CLI_PUB"]}${NC}"
  fi

  if $USE_VLESS; then
    echo -e "  VLESS UUID:  ${GREEN}${UUID}${NC}"
  fi

  echo ""
  echo -e "  ${BOLD}Management:${NC}"
  echo "    systemctl status xray-wg"
  echo "    journalctl -u xray-wg -f"
  echo "    /usr/local/bin/xray run -config $DEPLOY_DIR/config.json -test"
  echo ""
  echo -e "  ${BOLD}Client files in:${NC} $CLIENT_OUT_DIR"

  echo ""
}

# ─── Main ────────────────────────────────────────────────────────────
main() {
  # Root check
  if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo).${NC}"
    exit 1
  fi

  # Pipe detection — curl|bash kills stdin, read() fails silently
  if [ ! -t 0 ] && [ -z "${1:-}" ]; then
    echo -e "${RED}Cannot run interactively through a pipe.${NC}"
    echo ""
    echo "  Fix — use one of:"
    echo ""
    echo -e "  ${GREEN}# Option A: download first, then run${NC}"
    echo "  curl -sLo deploy.sh https://raw.githubusercontent.com/takashi728/xray-wireguard-finalmask/main/scripts/xray-wg-deploy.sh"
    echo "  sudo bash deploy.sh"
    echo ""
    echo -e "  ${GREEN}# Option B: pass scenario number directly (non-interactive)${NC}"
    echo "  curl -sL https://raw.githubusercontent.com/takashi728/xray-wireguard-finalmask/main/scripts/xray-wg-deploy.sh | sudo bash -s -- 08"
    echo ""
    echo "  Scenarios: 01-08 (see README)"
    exit 1
  fi

  banner

  # Scenario selection
  if [ -n "${1:-}" ]; then
    SCENARIO="$1"
    DEPLOY_MODE="${2:-binary}"
    echo -e "\n${CYAN}Deploying scenario $SCENARIO (mode: $DEPLOY_MODE)${NC}"

    case "$SCENARIO" in
      03) NEED_DOMAIN=true; NEED_TLS=true ;;
      *)  NEED_DOMAIN=false ;;
    esac
  else
    show_menu "$@"
  fi

  # Validate scenario
  local VALID_SCENARIOS="01 02 03 04 05 06 07 08"
  if ! echo "$VALID_SCENARIOS" | grep -qw "$SCENARIO"; then
    echo -e "${RED}Invalid scenario: $SCENARIO${NC}"
    exit 1
  fi

  # Detect network
  detect_ips

  # Domain setup (if needed)
  setup_domain

  # Generate keys
  gen_keys

  # Install Xray-core
  if [ ! -f /usr/local/bin/xray ]; then
    install_xray
  else
    echo -e "\n${GREEN}Xray-core already installed: $(/usr/local/bin/xray version 2>/dev/null | head -1)${NC}"
  fi

  # Generate server config
  generate_config

  # Setup firewall
  setup_firewall

  # Setup systemd service
  setup_service

  # Generate client config
  generate_client

  # Generate QR
  generate_qr

  # Print summary
  print_summary
}

main "$@"
