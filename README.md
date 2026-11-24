# Kerov Tunnel v2.2 (6-Core Edition)

Multi-core tunnel manager & smart benchmark CLI for Ubuntu 22.04+ (amd64 / arm64).

## Included Cores
**Reverse (Iran = Server | Foreign = Client)**
- BrokenNode — 12 transports + presets + IP-Spoofing
- DaggerConnect v4.3.1 offline — 13 transports + Cloudflare CDN + IPX TUN + DC6
- Backhaul Premium — tcp, tcpmux, xtcpmux, ws, wss, wsmux, wssmux, xwsmux, anytls, tun/ipx

**Direct (Iran = Client | Foreign = Server)**
- paqet-plus — Raw TCP + KCP/smux + auto iptables NOTRACK/RST drop
- GRE over IPsec L2 — StrongSwan IKEv2 + GRETAP
- Kerov-UDP — udp2raw FakeTCP + WireGuard

## Install
Online:
```bash
curl -fsSL https://raw.githubusercontent.com/Mahansimon/kerov-tunnel/main/setup-kerov.sh | sudo bash
```

Offline (Iran server without GitHub access):
```bash
# On the foreign server
sudo bash make-offline-bundle.sh
# Copy kerov-tunnel-full-offline.zip to the Iran server, then:
unzip kerov-tunnel-full-offline.zip && cd kerov-tunnel && sudo bash kerov-install.sh
```

## Usage
```bash
sudo kerov
```
1. On the **Iran** server: `Create Tunnel` → `Iran Server` → choose direction and engine. A `kerov://` sync link is printed.
2. On the **Foreign** server: `Create Tunnel` → `Foreign Server` → paste the link.
3. Manage, benchmark, monitor and configure the watchdog (Telegram alerts) from the main menu.

## Files
| Path | Purpose |
|------|---------|
| `/opt/kerov/kerov.py` | CLI (`/usr/local/bin/kerov`) |
| `/etc/kerov/` | Tunnel metadata, TLS, watchdog, benchmark history |
| `/etc/sysctl.d/99-kerov.conf` | BBR & buffer tuning |

## Uninstall
`sudo kerov` → Uninstall, then type `uninstall`.

## Security notes
- The `kerov://` link contains tunnel secrets and keys. Share it only over a trusted channel.
- Config files are written with mode `0600`.
