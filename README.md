# WireGuard + FinalMask (header-*) Configuration Examples

Xray-core v26.3.27+ supports combining **WireGuard** protocol with **FinalMask** transport camouflage,
giving stronger obfuscation than any other WireGuard variant.

## 🚀 Quick Deploy (one command)

```bash
# On your VPS (as root):
curl -sL https://...raw.../xray-wg-deploy.sh | sudo bash

# Interactive menu → pick scenario → auto-deploy → QR code appears
```

| Script | Purpose |
|--------|---------|
| `scripts/xray-wg-deploy.sh` | Full VPS deployment (TUI menu, keys, install, firewall, systemd, QR) |
| `scripts/xray-wg-client.sh` | Regenerate client configs + QR codes from running server |

---

## What is FinalMask?

FinalMask is Xray-core's last-stage traffic obfuscation layer. It processes raw bytes **after**
TLS/REALITY, adding custom headers, noise, fragments, or protocol mimicry on top of your actual
traffic. It supports both TCP and UDP, with multiple camouflage types.

For **UDP**, FinalMask offers these `header-*` types:

| Type | Description | Config |
|------|-------------|--------|
| `header-custom` | Custom binary header with random/fixed bytes | Yes |
| `header-dns` | Mimics DNS queries | Yes |
| `header-dtls` | Mimics DTLS 1.2 handshake | No |
| `header-srtp` | Mimics SRTP (video calls like FaceTime) | No |
| `header-utp` | Mimics uTP (BitTorrent) | No |
| `header-wechat` | Mimics WeChat video calls | No |
| `header-wireguard` | Mimics WireGuard packets | No |

> **Note:** `header-shadowsocks` does **not** exist as a native type.
> Use `header-custom` with a 16 or 32 byte random salt to approximate
> Shadowsocks AEAD packet structure, or use `mkcp-aes128gcm` / `salamander`
> for password-based payload obfuscation.
| `noise` | Random noise before payload | Yes |
| `salamander` | Hysteria2 obfuscation | Yes |
| `sudoku` | Sudoku-based obfuscation | Yes |
| `xdns` | Tunnels through DNS queries | Yes |

For **TCP**, FinalMask offers: `header-custom`, `fragment`, `sudoku`

---

## Scenarios

### Scenario 1: Real WireGuard + FinalMask `header-custom`

The actual WireGuard protocol tunnel, with custom binary headers prepended to each UDP
packet via FinalMask. This is the most powerful combination — real WireGuard encryption
plus custom traffic signature customization.

- **Files:** `server/01-wg-headercustom.json`, `client/01-wg-headercustom.json`

### Scenario 2: VLESS+mKCP disguised as WireGuard via `header-wireguard`

NOT real WireGuard. This uses VLESS protocol over mKCP transport, with FinalMask's
`header-wireguard` making all UDP packets look like genuine WireGuard traffic.
Useful when you want WireGuard-like traffic patterns without the WireGuard protocol.

- **Files:** `server/02-vless-kcp-headerwireguard.json`, `client/02-vless-kcp-headerwireguard.json`

### Scenario 3: VLESS+TCP + FinalMask `header-custom`

VLESS over TCP with custom binary headers via FinalMask TCP layer.
Demonstrates TCP-side `header-custom` with `clients`/`servers`/`errors` phases.

- **Files:** `server/03-vless-tcp-headercustom.json`, `client/03-vless-tcp-headercustom.json`

### Scenario 4: WireGuard + FinalMask `header-wireguard`

Real WireGuard tunnel with an additional WireGuard-like header camouflage layer
via FinalMask. This wraps WireGuard packets within a WireGuard-mimicking header —
essentially "WireGuard inside WireGuard-looking" for deep obfuscation.

- **Files:** `server/04-wg-headerwireguard.json`, `client/04-wg-headerwireguard.json`

### Scenario 5: WireGuard + FinalMask stacked (header-custom + noise + salamander)

Real WireGuard with multiple stacked FinalMask layers: a custom header, random
noise bursts, and Salamander obfuscation. This maximizes unpredictability of
the traffic signature.

- **Files:** `server/05-wg-stacked.json`, `client/05-wg-stacked.json`

### Scenario 6: WireGuard + FinalMask `header-dtls`

WireGuard tunnel disguised as DTLS 1.2 (encrypted WebRTC/VoIP traffic).
Zero-config camouflage — every UDP packet gets a DTLS record header.

- **Files:** `server/06-wg-headerdtls.json`, `client/06-wg-headerdtls.json`

### Scenario 7: WireGuard Multi-Peer + FinalMask `header-custom`

Single WireGuard server supporting multiple clients (peers), each with their
own key pair, all sharing the same FinalMask header-custom configuration.

- **Files:** `server/07-wg-multipeer.json`

### Scenario 8: WireGuard Multi-Inbound — Strong Obfuscation (4 inbounds)

Single server running **FOUR** WireGuard inbounds, each with stacked strong obfuscation:

| Port | Layers | Obfuscation Strength |
|------|--------|---------------------|
| 51820 | `header-wechat` + `noise` | WeChat look + random noise bursts |
| 51821 | `header-custom` + `mkcp-aes128gcm` | **AES-128-GCM encrypts payload** (SS AEAD equivalent) |
| 51822 | `noise` + `salamander` | Hysteria2 XOR keystream + noise |
| 51823 | `header-custom` + `sudoku` | Substitution cipher + random padding + custom header |

No weak approximations — every inbound uses real payload-level encryption
(mkcp-aes128gcm, salamander, sudoku) or stacked layers. `header-shadowsocks`
does not exist natively; `mkcp-aes128gcm` is the actual SS AEAD equivalent.

- **Files:** `server/08-wg-multi-header.json`, `client/08-wg-multi-header.json`

---

## Key Generation

Generate WireGuard key pairs:

```bash
# Using Xray-core built-in command
xray x25519

# Or using wg
wg genkey | tee privatekey | wg pubkey > publickey
```

Generate FinalMask Sudoku password (if using sudoku):

```bash
xray x25519  # can reuse the output as password
```

---

## Architecture Notes

```
┌─────────────────────────────────────────────────┐
│                  Application                     │
├─────────────────────────────────────────────────┤
│  WireGuard TUN (encrypt/decrypt WG packets)     │
├─────────────────────────────────────────────────┤
│  FinalMask (UDP: header-custom, noise, etc.)    │
├─────────────────────────────────────────────────┤
│  Raw UDP Socket                                 │
└─────────────────────────────────────────────────┘
```

- **Inbound** (server): FinalMask wraps the UDP listener → strips camouflage → decrypts WireGuard
- **Outbound** (client): Encrypt WireGuard → FinalMask adds camouflage → sends to server

---

## Security Notes

- WireGuard is NOT designed for firewall bypass — use FinalMask to mask its distinct signature
- `header-wireguard` is **not** real WireGuard encryption; it only mimics WireGuard packet structure
- Always use strong WireGuard keys and regularly rotate them
- Combine with REALITY or XHTTP for transport-layer security if needed
- The `header-*` types that have "No config" (dtls, srtp, utp, wechat, wireguard) are
  zero-configuration camouflage types that prepend fixed protocol-like headers

## Available header-* Types Quick Reference

| UDP Type | TCP Type | Needs Config | Mimics |
|----------|----------|:---:|--------|
| `header-custom` | `header-custom` | ✅ | Custom binary headers |
| `header-dns` | — | ✅ | DNS queries |
| `header-dtls` | — | ❌ | DTLS 1.2 (WebRTC) |
| `header-srtp` | — | ❌ | SRTP (FaceTime) |
| `header-utp` | — | ❌ | uTP (BitTorrent) |
| `header-wechat` | — | ❌ | WeChat Video |
| `header-wireguard` | — | ❌ | WireGuard packets |
| `mkcp-original` | — | ❌ | Legacy mKCP obfuscation |
| `mkcp-aes128gcm` | — | ✅ | AES-128-GCM seed |
| `noise` | — | ✅ | Random noise bursts |
| `salamander` | — | ✅ | Hysteria2 obfuscation |
| `sudoku` | `sudoku` | ✅ | Sudoku-based obfuscation |
| `xdns` | — | ✅ | DNS TXT tunneling |
| `xicmp` | — | ✅ | ICMP tunneling |
| — | `fragment` | ✅ | TCP fragmentation |

## References

- [FinalMask Documentation](https://xtls.github.io/en/config/transports/finalmask.html)
- [WireGuard Inbound Documentation](https://xtls.github.io/en/config/inbounds/wireguard.html)
- [WireGuard Outbound Documentation](https://xtls.github.io/en/config/outbounds/wireguard.html)
- [Xray-core v26.3.27 Release](https://github.com/XTLS/Xray-core/releases/tag/v26.3.27)
