#!/usr/bin/env bash
# =============================================================================
# xray-wg-client.sh — Client config generator
#
# Run this AFTER deploy.sh on the VPS. Generates:
#   1. Full Xray-core JSON client config
#   2. Share link (vless:// or xray://)
#   3. QR code (terminal + PNG file)
#   4. WireGuard standalone .conf (for non-Xray clients)
#
# Usage:
#   bash xray-wg-client.sh              # detect from running config
#   bash xray-wg-client.sh /path/to/server-config.json
#   bash xray-wg-client.sh --qr-only    # re-generate QR only
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOY_DIR="/opt/xray-wg"
OUT_DIR="$SCRIPT_DIR/clients"

# ─── Colors ───────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ─── Parse server config ─────────────────────────────────────────────
parse_config() {
  local cfg="$1"

  echo -e "${BLUE}→ Parsing server config: ${cfg}${NC}"

  # Extract with python for reliability
  python3 -c "
import json, sys, re

with open('$cfg') as f:
    raw = f.read()
raw = re.sub(r'//[^\n]*', '', raw)
c = json.loads(raw)

inb = c['inbounds'][0]
proto = inb.get('protocol','?')
port = inb.get('port','?')
settings = inb.get('settings',{})

print(f'PROTO={proto}')
print(f'PORT={port}')

if proto == 'wireguard':
    print(f'SRV_PUB={settings.get(\"secretKey\",\"\")}')  # private key of server
    for p in settings.get('peers',[]):
        print(f'CLI_PUB={p.get(\"publicKey\",\"\")}')
elif proto == 'vless':
    for cl in settings.get('clients',[]):
        print(f'UUID={cl.get(\"id\",\"\")}')

fm = c.get('inbounds',[{}])[0].get('streamSettings',{}).get('finalmask',{})
udp = fm.get('udp',[])
tcp = fm.get('tcp',[])
for i, u in enumerate(udp):
    t = u.get('type','?')
    s = u.get('settings',{})
    print(f'FM_UDP_{i}_TYPE={t}')
    if t == 'header-custom':
        print(f'FM_UDP_{i}_CLIENT={json.dumps(s.get(\"client\",[]))}')
        print(f'FM_UDP_{i}_SERVER={json.dumps(s.get(\"server\",[]))}')
    elif t in ('mkcp-aes128gcm','salamander','sudoku'):
        print(f'FM_UDP_{i}_PASSWORD={s.get(\"password\",\"\")}')
    elif t == 'noise':
        print(f'FM_UDP_{i}_NOISE={json.dumps(s.get(\"noise\",[]))}')
        print(f'FM_UDP_{i}_RESET={s.get(\"reset\",0)}')
for i, tc in enumerate(tcp):
    t = tc.get('type','?')
    s = tc.get('settings',{})
    print(f'FM_TCP_{i}_TYPE={t}')
    if t == 'header-custom':
        print(f'FM_TCP_{i}_CLIENTS={json.dumps(s.get(\"clients\",[]))}')
        print(f'FM_TCP_{i}_SERVERS={json.dumps(s.get(\"servers\",[]))}')

tls = c.get('inbounds',[{}])[0].get('streamSettings',{}).get('tlsSettings',{})
if tls:
    print(f'HAS_TLS=true')
else:
    print(f'HAS_TLS=false')

dns = c.get('dns',{})
if dns:
    print('HAS_DNS=true')
" 2>/dev/null
}

# ─── QR Code ──────────────────────────────────────────────────────────
qr_print() {
  local data="$1"
  local label="${2:-}"

  echo -e "\n${CYAN}${BOLD}${label}${NC}"

  if command -v qrencode &>/dev/null; then
    qrencode -t ANSIUTF8 -m 1 -s 2 "$data" 2>/dev/null || qrencode -t UTF8 "$data"
  elif python3 -c "import qrcode" 2>/dev/null; then
    python3 -c "
import qrcode
qr = qrcode.QRCode(border=1, box_size=2)
qr.add_data(r'''$data''')
qr.make()
qr.print_ascii()
" 2>/dev/null || echo "  (QR too large for terminal)"
  else
    echo -e "  ${YELLOW}Install qrencode for QR: apt install qrencode / pip install qrcode${NC}"
  fi
}

# ─── Build WireGuard client JSON ─────────────────────────────────────
build_wg_client_json() {
  local proto="$1" port="$2"
  shift 2
  # Remaining args are key=value pairs from parse_config
  local -A V
  while IFS='=' read -r k v; do
    V["$k"]="$v"
  done < <(printf '%s\n' "$@")

  local server_ip
  server_ip=$(curl -4 -s --max-time 3 ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")

  local fm_udp=""
  local fm_tcp=""
  local fm_count=0

  # Rebuild FinalMask UDP array
  for key in $(printf '%s\n' "${!V[@]}" | grep '^FM_UDP_' | grep '_TYPE$' | sort); do
    local idx
    idx=$(echo "$key" | sed 's/FM_UDP_\(.*\)_TYPE/\1/')
    local ftype="${V[$key]}"

    [ $fm_count -gt 0 ] && fm_udp+=","
    fm_udp+="{\"type\":\"$ftype\""

    case "$ftype" in
      header-custom)
        local cli_raw="${V[FM_UDP_${idx}_CLIENT]-[]}"
        local srv_raw="${V[FM_UDP_${idx}_SERVER]-[]}"
        fm_udp+=",\"settings\":{\"client\":$cli_raw,\"server\":$srv_raw}"
        ;;
      mkcp-aes128gcm|salamander|sudoku)
        local pw="${V[FM_UDP_${idx}_PASSWORD]-}"
        fm_udp+=",\"settings\":{\"password\":\"$pw\"}"
        ;;
      noise)
        local n="${V[FM_UDP_${idx}_NOISE]-[]}"
        local r="${V[FM_UDP_${idx}_RESET]-0}"
        fm_udp+=",\"settings\":{\"reset\":$r,\"noise\":$n}"
        ;;
    esac
    fm_udp+="}"
    ((fm_count++))
  done

  # Rebuild FinalMask TCP array
  local tc_count=0
  for key in $(printf '%s\n' "${!V[@]}" | grep '^FM_TCP_' | grep '_TYPE$' | sort); do
    local idx
    idx=$(echo "$key" | sed 's/FM_TCP_\(.*\)_TYPE/\1/')
    local ftype="${V[$key]}"

    [ $tc_count -gt 0 ] && fm_tcp+=","
    fm_tcp+="{\"type\":\"$ftype\""

    case "$ftype" in
      header-custom)
        local cli_raw="${V[FM_TCP_${idx}_CLIENTS]-[]}"
        local srv_raw="${V[FM_TCP_${idx}_SERVERS]-[]}"
        fm_tcp+=",\"settings\":{\"clients\":$cli_raw,\"servers\":$srv_raw}"
        ;;
    esac
    fm_tcp+="}"
    ((tc_count++))
  done

  # Build full FinalMask block
  local fm_block=""
  local fm_parts=()
  [ -n "$fm_udp" ] && fm_parts+=("\"udp\":[$fm_udp]")
  [ -n "$fm_tcp" ] && fm_parts+=("\"tcp\":[$fm_tcp]")
  if [ ${#fm_parts[@]} -gt 0 ]; then
    fm_block="\"finalmask\":{$(IFS=,; echo "${fm_parts[*]}")}"
  fi

  cat <<JSONEOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 10808,
      "protocol": "socks",
      "settings": {"udp": true}
    }
  ],
  "outbounds": [
    {
      "protocol": "wireguard",
      "settings": {
        "secretKey": "YOUR_CLIENT_PRIVATE_KEY",
        "address": ["10.0.0.2/32"],
        "mtu": 1420,
        "domainStrategy": "ForceIP",
        "peers": [
          {
            "endpoint": "${server_ip}:${port}",
            "publicKey": "${V[CLI_PUB]:-SERVER_PUBLIC_KEY}",
            "allowedIPs": ["0.0.0.0/0", "::/0"]
          }
        ]
      },
      "streamSettings": {${fm_block}}
    },
    {"protocol": "freedom", "tag": "direct"}
  ],
  "routing": {
    "rules": [
      {"type": "field", "inboundTag": ["socks-in"], "outboundTag": "wireguard"}
    ]
  }
}
JSONEOF
}

# ─── Main ────────────────────────────────────────────────────────────
main() {
  echo -e "${CYAN}${BOLD}"
  echo "╔══════════════════════════════════════════════╗"
  echo "║   Xray-WG Client Config Generator           ║"
  echo "╚══════════════════════════════════════════════╝"
  echo -e "${NC}"

  mkdir -p "$OUT_DIR"

  local CONFIG_FILE="${1:-$DEPLOY_DIR/config.json}"

  if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${RED}Config not found: $CONFIG_FILE${NC}"
    echo "Usage: bash xray-wg-client.sh /path/to/server-config.json"
    exit 1
  fi

  # Parse server config
  local parsed
  parsed=$(parse_config "$CONFIG_FILE")
  eval "$parsed"

  echo -e "  Protocol: ${GREEN}${PROTO}${NC}"
  echo -e "  Port:     ${GREEN}${PORT}${NC}"

  local SERVER_IP
  SERVER_IP=$(curl -4 -s --max-time 3 ifconfig.me 2>/dev/null || \
              curl -6 -s --max-time 3 ifconfig.me 2>/dev/null || \
              echo "YOUR_SERVER_IP")

  # ─── VLESS share link ──────────────────────────────────────────
  if [ "$PROTO" = "vless" ]; then
    local vless_link=""
    local enc="none"

    vless_link="vless://${UUID}@${SERVER_IP}:${PORT}"

    local params=""
    # Detect transport
    local network
    network=$(python3 -c "
import json,re
with open('$CONFIG_FILE') as f:
    c = json.loads(re.sub(r'//[^\n]*','',f.read()))
print(c['inbounds'][0].get('streamSettings',{}).get('network','tcp'))
" 2>/dev/null || echo "tcp")
    params="type=${network}"

    if [ "$HAS_TLS" = "true" ]; then
      params="${params}&security=tls"
    fi

    # Detect FM types for share link
    local fm_types=""
    for key in $(env | grep '^FM_UDP_' | grep '_TYPE=' | sort); do
      local ft
      ft=$(echo "$key" | cut -d= -f2)
      [ -n "$fm_types" ] && fm_types="${fm_types}+"
      fm_types="${fm_types}udp-${ft}"
    done
    for key in $(env | grep '^FM_TCP_' | grep '_TYPE=' | sort); do
      local ft
      ft=$(echo "$key" | cut -d= -f2)
      [ -n "$fm_types" ] && fm_types="${fm_types}+"
      fm_types="${fm_types}tcp-${ft}"
    done
    [ -n "$fm_types" ] && params="${params}&fm=${fm_types}"

    vless_link="${vless_link}?${params}#Xray-FinalMask-$(date +%m%d)"

    echo -e "\n${CYAN}${BOLD}VLESS Share Link:${NC}"
    echo -e "${GREEN}${vless_link}${NC}"
    echo "$vless_link" > "$OUT_DIR/vless-share-link.txt"

    qr_print "$vless_link" "VLESS QR:"

  elif [ "$PROTO" = "wireguard" ]; then
    # ─── WireGuard: generate full JSON client config ────────────
    local wg_json
    wg_json=$(build_wg_client_json "$PROTO" "$PORT")

    local wg_file="$OUT_DIR/client-wg-$(date +%Y%m%d-%H%M%S).json"
    echo "$wg_json" > "$wg_file"

    echo -e "\n${CYAN}Client config: ${GREEN}${wg_file}${NC}"

    # Compress for QR
    local compressed
    compressed=$(python3 -c "
import json, base64, gzip, re
with open('$wg_file') as f:
    data = json.loads(re.sub(r'//[^\n]*','',f.read()))
compact = json.dumps(data, separators=(',',':')).encode()
print(base64.urlsafe_b64encode(gzip.compress(compact)).decode())
" 2>/dev/null || echo "")

    if [ -n "$compressed" ]; then
      local xray_link="xray://${compressed}"
      echo "$xray_link" > "$OUT_DIR/xray-share-link.txt"

      local link_short="${xray_link:0:60}..."
      echo -e "\n${CYAN}xray:// link: ${GREEN}${link_short}${NC}"
      qr_print "$xray_link" "xray:// QR (import into Xray GUI):"
    fi

    # ─── Standalone WireGuard .conf ─────────────────────────────
    if command -v wg &>/dev/null || true; then
      local wg_conf="$OUT_DIR/client-wg-standalone.conf"
      python3 -c "
import json, re
with open('$CONFIG_FILE') as f:
    c = json.loads(re.sub(r'//[^\n]*','',f.read()))
inb = c['inbounds'][0]
s = inb['settings']
peers = s.get('peers',[{}])

# Write standard WG config
conf = f'''[Interface]
PrivateKey = YOUR_CLIENT_PRIVATE_KEY
Address = 10.0.0.2/32
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = {peers[0].get('publicKey','SERVER_PUBKEY')}
Endpoint = ${SERVER_IP}:${PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
'''
with open('$wg_conf','w') as f:
    f.write(conf)
print(conf)
" 2>/dev/null

      echo -e "\n${CYAN}${BOLD}WireGuard Standalone Config:${NC}"
      echo -e "${GREEN}${wg_conf}${NC}"
      echo -e "${YELLOW}Note: standalone WG does NOT include FinalMask! Use Xray-core client for full obfuscation.${NC}"
    fi
  fi

  # ─── Summary ──────────────────────────────────────────────────
  echo ""
  echo -e "${BOLD}Files in ${OUT_DIR}:${NC}"
  ls -la "$OUT_DIR" 2>/dev/null | grep -v "^total"

  echo ""
  echo -e "${CYAN}Done. Copy files to client or scan QR above.${NC}"
}

main "$@"
