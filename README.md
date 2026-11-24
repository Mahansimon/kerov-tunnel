# Kerov Tunnel v1.3 (6-Core Edition)

Multi-core tunnel manager & smart benchmark CLI for Ubuntu 22.04+.

## Included Cores
- **Reverse (Iran = Server | Foreign = Client):**
  - BrokenNode (12 transports + presets + IP-Spoofing)
  - DaggerConnect v4.3.1 offline (13 transports + Cloudflare CDN + IPX TUN + DC6)
  - Backhaul Premium (10 transports: tcp, tcpmux, xtcpmux, ws, wss, wsmux, wssmux, xwsmux, anytls, tun/ipx)
- **Direct (Iran = Client | Foreign = Server):**
  - paqet-plus (Raw TCP + KCP/smux + auto iptables NOTRACK/RST drop)
  - GRE over IPsec Layer 2 (StrongSwan IKEv2 + GRETAP)
  - Kerov-UDP Special (udp2raw FakeTCP + WireGuard)

## Quick Setup

Run this command on your Ubuntu server:

```bash
curl -fsSL https://raw.githubusercontent.com/Mahansimon/kerov-tunnel/main/setup-kerov.sh | sudo bash
```
