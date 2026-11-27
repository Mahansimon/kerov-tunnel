# Kerov Tunnel v2.3.14

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
update the CLI and install the bundled cores without downloading packages or
restarting existing tunnels.

```bash
unzip Kerov-Tunnel-v2.3.14.zip -d kerov-v2.3.14
cd kerov-v2.3.14/kerov-tunnel
sudo bash kerov-install.sh --offline
sudo kerov
```

For a fresh full installation on an Ubuntu server with access to its package
repositories, run `sudo bash kerov-install.sh` in the extracted directory.
For a fresh offline CLI install, `--offline` needs `python3`, `iproute2`, systemd,
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
sudo bash kerov-install.sh --offline
```

The offline option skips OS package installation and network downloads. It
installs C-Tunnel and the bundled BrokenNode, DaggerConnect, Backhaul Premium,
paqet-plus, LeechTunnel and QS-Tunnel binaries for their supported architectures. paqet-plus v1.0.0-alpha.41 is bundled
for Linux amd64 and arm64, with per-binary SHA-256 checks during installation and
its MIT license in `cores/`. Linux amd64 builds of QS-Tunnel and BrokenNode are
included. On a fresh offline host, DaggerConnect also needs an installed libpcap
runtime. A new offline ICMP installation needs the local binary
passed with `--icmp-core`. Older engines that have not already been installed
may need the full Kerov installer and distribution packages.

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

Keep **QS upload route** set to `auto` to use the bundled loopback-only upload
relay. Kerov starts it with the QS client for both regular tunnels and temporary
benchmarks. The relay only accepts connections to the configured Foreign QS TCP
endpoint. Use the Iran public IPv4 as seen from Foreign. If the direct TCP
route is unavailable or it exits from a different IPv4, enter an existing
unauthenticated SOCKS5 address and its actual egress IPv4 instead. The Foreign
service restricts uploads to that source.

Allow inbound download UDP to the advertised public IPv4 and port on Iran. If
Iran is behind NAT, forward that UDP port to the Iran server. A new sync link
with `auto` activates the bundled relay. Existing QS services keep their
configured upload proxy. To switch an existing pair, create and sync a QS
instance with `auto`, using free ports or replacing the old pair.

Test traffic using the local SOCKS5 endpoint on Iran:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://example.org/
```

### ICMP Tunnel

On Linux amd64, Kerov automatically installs the ICMP core. It reuses an
existing installed core or imports the upstream executable from
`/usr/local/bin/ICMPTunnel`. Otherwise it downloads Q-TEAM's pinned v1.1.0
release directly and verifies its SHA-256 before installing it. Use the core
under the Q-TEAM license. The binary is distributed by Q-TEAM.

If GitHub is unreachable, use your authorized local binary on each server:

```bash
sudo bash kerov-install.sh --cli-only --icmp-core /path/to/ICMPTunnel-linux-amd64
```

For a fresh install, omit `--cli-only`. Stop the standalone upstream ICMP service
before running the Kerov ICMP tunnel or its temporary benchmark.

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

## C-Tunnel

`cores/ctunnel/` contains the unmodified official C-Tunnel v2.1.0 CLI and engine
binaries for Linux amd64, arm64 and armv7, the kernel helper, the systemd files,
the upstream installer, and the corresponding source archive. Kerov verifies
the official SHA-256 manifest and the assets it installs. On a server with
systemd, install only the C-Tunnel core directly from the ZIP by running
`sudo bash kerov-install.sh --ctunnel-core-only` from the extracted project
directory. This option also works without Kerov's Python dependencies. Install
`iproute2` and `iptables` for native methods and forwarding that require them.

The native panel and watchdog files are included for standalone use. Kerov's
installer leaves those standalone services inactive and uses its own management
menu. ARMv7 support here is for C-Tunnel and does not extend to every Kerov core.

Based on C-Tunnel by CIAUB  
https://github.com/CIAUB/C-Tunnel

[Official release](https://github.com/CIAUB/C-Tunnel/releases/tag/v2.1.0) ·
[Corresponding upstream source](https://github.com/CIAUB/C-Tunnel/tree/v2.1.0)

On Iran choose **Create Tunnel → Iran Server → Direct or Reverse → C-Tunnel**.
Apply the generated Kerov sync link on the Foreign server. Direct offers 28
active methods and Reverse offers 25. The Direct-only methods are `ip6gre`,
`eoip`, and `vxlan`. The official v2.1.0 catalog retired legacy methods for
new creation. `ip6gre` needs IPv6 underlay addresses on both servers.

The C-Tunnel wizard exposes native transport ports, forwarding, MTU, profiles,
ECMP lanes, TLS / WebSocket host, padding, EoIP ID, VXLAN VNI, traffic limits
and backup transport where applicable. Manage Tunnels uses native service
controls for C-Tunnel. The C-Tunnel agent handles automatic profiles, quotas and
failover. Port mappings are served by the Iran endpoint in both directions.

**Smart Benchmark → Iran Server → C-Tunnel Native** runs the native catalog
on an existing two-server benchmark session. Full Mode appends the native
suite after the 94 Kerov cases, and Custom Cores accepts `ctunnel`. The
native suite displays its own report and skips methods that lack the required
path or host support. The upstream automatic suite does not test the IPv6
underlay of `ip6gre`. Use **Benchmark Managed Tunnel** after creating the
IPv6 tunnel to measure traffic through it.

## Terminal appearance

Kerov uses a warm red, amber and cream palette for its menus, prompts and
benchmark. Menu choices are left-aligned in one column. The main menu displays
a large KerovTunnel wordmark when there is room. Adjust font size in your local
terminal or SSH client.

## Smart Benchmark display

The terminal board shows the current case and recent results while the test
runs. **Echo** counts successful replies out of five. **OK** means all echoes
and both transfers succeeded. **Unstable** flags missing echoes or an incomplete
transfer.
The results table includes direction, download, upload, RTT, jitter, echo loss and
grade, with a stacked layout for narrower terminals.

## Benchmark before creating a tunnel

Update both servers to v2.3.14. Use **Smart Benchmark → Iran Server → Full Mode**
for the 96-case matrix, or select `leech,qs,icmp` under **Custom Cores** to test
just those three engines. On Foreign, use **Peer Agent** with the generated
`kerov-test://` link.

The original 45 cases remain in the matrix. Dagger TUN adds the BIP and IPIP profiles. Leech adds 44 cases across Direct and
Reverse, including its TUN encapsulations and IPX profiles. QS adds four cases
and ICMP adds one. Kerov creates temporary endpoints for these engines, runs
echo and throughput probes through each one, and stops the endpoints after each
case. Temporary endpoints do not appear in Manage Tunnels.

QS uses the same `auto` upload default as tunnel creation. The benchmark reports
upload reachability separately from authenticated echo failures. QS spoof
variants use an IPv4 assigned on Foreign. ICMP needs the separate core on both hosts and the
sysctl described above. Use **Benchmark Managed Tunnel** for an already
configured ICMP instance. Leech tests use its configured license, selected
carrier and the host capabilities that carrier requires. Setup errors appear
below the results table. The test uses the coordinator TCP port and scoped
temporary transport ports in the 49200–50799 range as needed by each case.
The benchmark does not change provider firewall rules. The peer has up to five
minutes to connect. Each transfer has a 100-second budget and tolerates up to
25 seconds of inactivity. A failed case is scored and the matrix continues
while the control connection stays up.

For BrokenNode IP-Spoofing, enable the optional cases in **Full Mode** or
**Custom Cores** with `brokennode` selected to test both Direct and Reverse.
**Direct Only** and **Reverse Only** add their respective direction. Each
selected carrier (`udp`, `tcp`, `icmp`, or `gre`) gets a separate test in
each selected direction. Direct probes from Foreign and uses a temporary
authenticated echo listener on Iran. For Direct, update both ends to v2.3.14.

Dagger TUN matrix cases use the core's IPX configuration and dial the peer's
private address through the temporary TUN interface. This covers TCP, UDP,
ICMP, GRE, IPIP and BIP profiles. The matrix uses temporary endpoints and
carrier ports where applicable. Use a managed benchmark to measure an existing
Dagger instance with its own configuration and ports.

**Echo loss** reports failed small TCP echo probes. Download and upload have
their own results. A transfer can fail when echo loss is zero. An unmeasured
echo loss is shown as a dash. QS throughput uses 256 KiB per direction in
acknowledged 8 KiB blocks to prevent the test from overrunning its asymmetric
UDP return path. Its reported rates measure that transfer pattern.

BrokenNode QUIC and QUICD, Backhaul, and paqet-plus use synchronized temporary
endpoints. QUIC and QUICD use the same ALPN as managed tunnels. Backhaul uses
the same config generator as managed tunnels. Backhaul and Leech TUN measure
through the TUN addresses, including the return path. The benchmark waits for
an authenticated echo before it collects samples. Startup errors and recent
core messages are shown separately from missing echo responses.

The carrier ports still need to be reachable between servers. BrokenNode
QUIC/QUICD use the case's temporary UDP port. paqet-plus needs IPv4 Ethernet
routing on each host. Leech and QS raw modes depend on the host and provider
supporting the selected carrier. ICMP remains subject to the core and host
requirements above.

## Benchmark Kerov-UDP

Update both servers to v2.3.14. The Kerov-UDP row in **Quick Mode**, **Full
Mode**, **Direct Only**, and **Custom Cores** uses temporary kernel WireGuard
interfaces over udp2raw FakeTCP. The benchmark exchanges temporary public
keys and measures TCP echo, download and upload through the WireGuard link.
It waits for a real authenticated echo before collecting samples. When setup
fails or the echo does not return, the row shows the failure and its diagnostics.

Install WireGuard kernel support, `wireguard-tools`, `iproute2`, `iptables`,
and `udp2raw` on both servers. The full installer attempts to install these
tools and the udp2raw core. The offline installer can install a supplied
`cores/udp2raw` binary for the server's architecture. The FakeTCP carrier uses
the Foreign server's temporary TCP port (49200 plus the case's zero-based
matrix position). The WireGuard UDP port is local to each server. The test
removes its temporary interfaces and firewall rules after the case.

## Benchmark a running Dagger TUN

On either server, select **Smart Benchmark → Benchmark Managed Tunnel** and
choose the running Dagger TUN instance. Paste the generated link in **Peer
Agent** on the other server, then confirm the test on the first server. The
echo listener uses the tunnel's private peer IPv4 and TUN interface. The default
echo TCP port is 49500 and can be changed to an unused port. The test does not
create a replacement tunnel or change the running service.

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
