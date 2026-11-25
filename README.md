# Kerov Tunnel v2.2.2 (6-Core Edition)

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

## Install this ZIP

Copy the ZIP to both servers and extract it. For an existing Kerov installation,
update the CLI without downloading packages or restarting existing tunnels:

```bash
unzip Kerov-Tunnel-v2.2.2-GRE-L2.zip -d kerov-v2.2.2
cd kerov-v2.2.2/kerov-tunnel
sudo bash kerov-install.sh --cli-only
sudo kerov
```

For a fresh full installation on an Ubuntu server with access to its package
repositories, run `sudo bash kerov-install.sh` in the extracted directory.
For a fresh offline CLI install, `--cli-only` needs `python3`, `iproute2`, systemd,
`flock` (util-linux), and the Python packages `rich`, `PyYAML`, and `psutil`.
These are normally present if Kerov already runs. If the Python packages are missing,
prepare wheels on an internet-connected machine with the same Linux architecture
and Python version, then transfer the directory to the offline server:

```bash
# On the connected machine
python3 -m pip download --only-binary=:all: -d kerov-wheels rich PyYAML psutil

# On the offline server, with pip installed
sudo python3 -m pip install --no-index --find-links ./kerov-wheels \
  --target /opt/kerov rich PyYAML psutil
sudo bash kerov-install.sh --cli-only
```

## GRE over IPsec L2 without port forwarding

1. On Iran, select **Create Tunnel → Iran Server → Direct Tunnels → GRE over IPsec L2**.
2. Enter the endpoint and private addresses. Answer **No** (the default) when asked
   whether to enable port forwarding on the Iran server.
3. On Foreign, select **Create Tunnel → Foreign Server** and paste the new sync link.

Kerov sets up strongSwan IKEv2 and assigns the private `/30` addresses to GRETAP.
When the port mapping list is empty, the GRE scripts apply no DNAT or MASQUERADE rules.
Existing GRE services retain their generated rules after a CLI update. To switch
an existing instance, delete it through **Manage Tunnels** on both servers so its
old scripts clean up the NAT rules, then recreate it and use the new sync link.

Use `sudo ipsec statusall` to check for an installed CHILD_SA for the instance.
Ping the peer's private address to check traffic across the tunnel.

## Manual Tunnel

1. On Iran, select **Create Tunnel → Iran Server → Manual Tunnel (Private IP Only)**.
   Enter a name and two distinct RFC 1918 IPv4 addresses.
2. Copy the generated `kerov://` link. On Foreign, select
   **Create Tunnel → Foreign Server** and paste that link.
3. Each server receives its own `/32` address on a dummy interface. Its systemd
   unit reapplies the address on boot. **IP CONFIGURED** refers to local address
   setup. Configure your own tunnel and the routes or allowed peer addresses
   needed to carry traffic between the two private IPs.

Manual Tunnel does not create a GRE/IPsec interface, change IP forwarding, add a
peer route, configure NAT, or forward any ports. Manage or remove each address
instance from **Manage Tunnels** on the corresponding server.

## Install
Online:
```bash
curl -fsSL https://raw.githubusercontent.com/Mahansimon/kerov-tunnel/main/setup-kerov.sh | sudo bash
```

Offline (Iran server without GitHub access):
```bash
# On the foreign server (creates ./kerov-tunnel-full-offline.zip in the current directory)
curl -fsSL https://raw.githubusercontent.com/Mahansimon/kerov-tunnel/main/setup-kerov.sh | sudo bash -s -- --offline
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
