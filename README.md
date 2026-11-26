# Kerov Tunnel v2.3.4

Multi-core tunnel manager & smart benchmark CLI for Ubuntu 22.04+ (amd64 / arm64).

## Tunnel Engines
**Reverse (Iran = Server | Foreign = Client)**
- BrokenNode — 12 transports + presets + IP-Spoofing
- DaggerConnect v4.3.1 offline — 13 transports + Cloudflare CDN + IPX TUN + DC6
- Backhaul Premium — tcp, tcpmux, xtcpmux, ws, wss, wsmux, wssmux, xwsmux, anytls, tun/ipx
- LeechTunnel — 14 transports, including TUN (amd64)

**Direct (Iran = Client | Foreign = Server)**
- paqet-plus — Raw TCP + KCP/smux + auto iptables NOTRACK/RST drop
- GRE over IPsec L2 — StrongSwan IKEv2 + GRETAP
- Kerov-UDP — udp2raw FakeTCP + WireGuard
- LeechTunnel — 14 transports, including TUN (amd64)
- QS-Tunnel — TCP upload via SOCKS5 and UDP or OBFS download (amd64)
- ICMP Tunnel — IPv4 ICMP with a local SOCKS5 listener (amd64, separate core)

## Install this ZIP

Copy the ZIP to both servers and extract it. For an existing Kerov installation,
update the CLI and install the bundled LeechTunnel and QS-Tunnel cores without
downloading packages or restarting existing tunnels:

```bash
unzip Kerov-Tunnel-v2.3.4.zip -d kerov-v2.3.4
cd kerov-v2.3.4/kerov-tunnel
sudo bash kerov-install.sh --cli-only
sudo kerov
```

For a fresh full installation on an Ubuntu server with access to its package
repositories, run `sudo bash kerov-install.sh` in the extracted directory.
For a fresh offline CLI install, `--cli-only` needs `python3`, `iproute2`, systemd,
and the Python packages `rich`, `PyYAML`, and `psutil`.
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

## LeechTunnel, QS-Tunnel and ICMP Tunnel

Use the same Kerov version on both servers. On Iran, select **Create Tunnel →
Iran Server**, then choose the engine and enter the settings. On Foreign, select
**Create Tunnel → Foreign Server** and paste the sync link. Share the sync link
privately because it contains the shared keys. Use **Manage Tunnels** for service
controls, logs and configuration. **RUNNING** describes the local service.
Confirm traffic separately using the port forward or SOCKS5 listener.
Smart Benchmark can measure all three engines using an existing managed tunnel.

### LeechTunnel

Choose **Reverse** for the listener on Iran or **Direct** for the listener on
Foreign. Select the transport by its number. The Leech menu follows the
supplied configurator:

| Transport menu | Options |
|---|---|
| Stream and packet transports | `tcp`, `tcpmux`, `xtcpmux`, `ws`, `wss`, `wsmux`, `wssmux`, `xwsmux`, `anytls`, `kcp`, `http`, `https`, `quantum` |
| TUN encapsulation | `tcp`, `ipx`, `icmpx`, `udpx` |
| TUN/IPX profile | `icmp`, `ipip`, `udp`, `tcp`, `gre`, `bip` |

For port forwarding, define at least one TCP mapping for the stream transports.
Each mapping listens on the listener host and connects to the target port on the
dialer's side. Kerov creates a per-instance certificate for the TLS listener.
The Leech license prompt defaults to the key in the supplied configurator.
Use your issued key if required by your build.

KCP uses a UDP control port. The UDPX endpoints use the same UDP wire port on
both hosts. IPX and ICMPX need the selected IP protocol to be reachable between
the two hosts, and both raw endpoints need their own reachable IPv4 addresses.
TUN needs access to `/dev/net/tun`. On a VPS, enable TUN in the provider settings
if needed. For Quantum and IPX, install the distribution's libpcap runtime.
Use distinct TUN addresses in the same private subnet and test by pinging the
peer's private TUN IPv4. The TUN wizard accepts optional TCP mappings.

#### UDP over TCP and backup listeners

Select Leech transport `tcp` and answer **Yes** to **Enable UDP over TCP**.
Kerov enables the upstream UDP relay on the listener for the configured port
mappings. Allow UDP on the forwarded listener ports and run a UDP service on
the corresponding dialer-side target port. The control connection stays TCP.

Enter backup listener endpoints as comma-separated `IPv4:port` or
`hostname:port` when creating the tunnel. The dialer receives the primary
endpoint followed by the backups. If you enable health-scored failover, Leech
also probes available endpoints every 15 seconds. Backups use the same
transport, token, encryption key and port mappings as the primary. On each
backup host, open **Create Tunnel → Leech Backup Listener**, paste the original
sync link, and select that host's endpoint. Start the primary and backup
services before testing failover. Raw TUN encapsulations IPX, ICMPX and UDPX
are configured as endpoint pairs.

### QS-Tunnel

Choose **Direct → QS-Tunnel** and select the number for `udp`, `obfs`, `udp+spoof`, or
`obfs+spoof`. The latter two require a UDP source IPv4 assigned to the Foreign
server, plus a host and provider that permit the core's raw packet mode.
`udp` modes send the download payload without OBFS encryption. The Iran service
limits plain UDP downloads to the configured Foreign IPv4 or source override.

Supply an existing, reachable SOCKS5 server for upload traffic. It must support
unauthenticated SOCKS5 connections and be able to connect to the Foreign QS TCP
port. Enter the upload proxy's egress IPv4 as seen by Foreign. The Foreign
service restricts uploads to that source. Allow inbound download UDP to the
configured public IPv4 and port on Iran. If Iran is behind NAT, forward that
UDP port to the Iran server.

Test traffic using the local SOCKS5 endpoint on Iran:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://example.org/
```

### ICMP Tunnel

Use a Linux amd64 core that you are authorized to run under the Q-TEAM license.
Install it on both servers before selecting **Direct → ICMP Tunnel**:

```bash
sudo install -D -m 0755 ./ICMPTunnel-linux-amd64 /usr/local/lib/kerov/cores/ICMPTunnel
```

Before configuring either side, verify IPv4 ICMP reachability. The upstream
installer sets `net.ipv4.icmp_echo_ignore_all=1` on each host. Kerov checks that
setting during provisioning. It affects ordinary IPv4 ping replies system-wide.
On a dedicated host where this is intended, apply the setting persistently:

```bash
printf '%s\n' 'net.ipv4.icmp_echo_ignore_all = 1' | sudo tee /etc/sysctl.d/98-kerov-icmp.conf
sudo sysctl -p /etc/sysctl.d/98-kerov-icmp.conf
```

The API port and Iran SOCKS5 port are restricted to loopback by service-scoped
firewall rules. QS and ICMP use `iptables` and `ip6tables` where their services
install inbound rules. Recreate the instance if changing its guarded ports,
so the systemd rules and the configuration stay in sync.
Test traffic through the Iran SOCKS5 endpoint, port 1010 by default.

## Benchmark a running Leech, QS or ICMP tunnel

1. Open **Smart Benchmark → Benchmark Managed Tunnel** and select a running
   tunnel. For QS or ICMP, begin on the SOCKS5 client. For Leech port forwarding,
   begin on the listener and choose a mapping whose peer target TCP port is
   unused. For Leech TUN, begin on either endpoint.
2. Open **Smart Benchmark → Peer Agent** on the other endpoint and paste the
   private `kerov-test://` link. The temporary echo listens on peer loopback
   or the peer's private TUN address.
3. Once the echo is ready, start measuring on the first server. Kerov measures
   connection/echo RTT, jitter, failed probes and 3 MiB TCP transfers in each
   direction. The result appears in **Benchmark History**. The existing matrix
   runs through the coordinator option.

The probe uses the selected tunnel's existing data path. For Leech UDP over
TCP, test a UDP application against the corresponding mapped port separately.
For a failover comparison, point the benchmark agent at the endpoint serving
the active path and repeat the measurement after switching endpoints.

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

## Remove retired Private IP instances

After upgrading from an earlier release, select a **Retired Private IP** entry
in **Manage Tunnels** and confirm removal. Repeat on each host that has an
instance. The upgrade itself leaves installed instances in place.

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
