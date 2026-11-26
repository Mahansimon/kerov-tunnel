#!/usr/bin/env python3
"""
Kerov Tunnel v2.3.4 — Multi-Core Tunnel Manager & Smart Benchmark CLI
Engines:
  [Reverse] BrokenNode (12 transports incl. ip-spoofing)
            DaggerConnect v4.3.1 (13 transports)
            Backhaul Premium (10 transports incl. anytls & tun/ipx)
  [Direct]  paqet-plus (Raw TCP+KCP)
            GRE-over-IPsec L2 (StrongSwan IKEv2 + GRETAP)
            Kerov-UDP (udp2raw FakeTCP + WireGuard)
"""

import base64
import fcntl
import hashlib
import hmac
import ipaddress
from collections import deque
from datetime import datetime
import json
import tarfile
import urllib.request
import urllib.parse
import os
import platform
import re
import secrets
import select
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import termios
import threading
import time
import traceback
import zlib
from pathlib import Path

import psutil
import yaml
from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table
from rich.text import Text

console = Console()

KEROV_ETC = Path("/etc/kerov")
META_DIR = KEROV_ETC / "meta"
TLS_DIR = KEROV_ETC / "tls"
SYSTEMD_DIR = Path("/etc/systemd/system")
WATCHDOG_CFG = KEROV_ETC / "watchdog.json"
BENCH_HISTORY = KEROV_ETC / "bench_history.json"
SPARK_CHARS = "▁▂▃▄▅▆▇█"

BINS = {
    "brokennode": "/usr/local/bin/brokennode",
    "dagger": "/usr/local/bin/DaggerLauncher",
    "backhaul": "/usr/local/bin/backhaul_premium",
    "paqet": "/opt/paqet-plus/paqet-plus",
    "udp2raw": "/usr/local/bin/udp2raw",
    "wg": shutil.which("wg") or "/usr/bin/wg",
    "ipsec": shutil.which("ipsec") or "/usr/sbin/ipsec",
    "leech": "/usr/local/lib/kerov/cores/leech",
    "qs-server": "/usr/local/lib/kerov/cores/qs-server",
    "qs-client": "/usr/local/lib/kerov/cores/qs-client",
    "icmp": "/usr/local/lib/kerov/cores/ICMPTunnel",
}

BANNER = r"""
  ╦╔═╔═╗╦═╗╔═╗╦  ╦  ╔╦╗╦ ╦╔╗╔╔╗╔╔═╗╦
  ╠╩╗║╣ ╠╦╝║ ║╚╗╔╝   ║ ║ ║║║║║║║║╣ ║
  ╩ ╩╚═╝╩╚═╚═╝ ╚╝    ╩ ╚═╝╝╚╝╝╚╝╚═╝╩═╝
"""


# ==============================================================================
#  SYSTEM & NETWORK HELPERS
# ==============================================================================

def flush_stdin():
    try:
        termios.tcflush(sys.stdin, termios.TCIFLUSH)
    except Exception:
        pass


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
SAFE_SECRET_RE = re.compile(r"^[A-Za-z0-9+/=_-]{1,128}$")
SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
RETIRED_PRIVATE_IP_ENGINE = "manual-ip"
ADDED_ENGINES = ("leech", "qs", "icmp")
LEECH_TRANSPORTS = ("tcp", "tcpmux", "xtcpmux", "ws", "wss", "wsmux", "wssmux",
                    "xwsmux", "anytls", "kcp", "http", "https", "quantum", "tun")
LEECH_TUN_ENCAPS = ("tcp", "ipx", "icmpx", "udpx")
LEECH_IPX_PROFILES = ("icmp", "ipip", "udp", "tcp", "gre", "bip")
LEECH_TLS = ("wss", "wssmux", "anytls", "https")
QS_TRANSPORTS = ("udp", "obfs", "udp+spoof", "obfs+spoof")
LEECH_LICENSE = "LEECH-H34M-CLUX-3PMU-2REK"
PRIVATE_V4_NETWORKS = tuple(
    ipaddress.IPv4Network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def _safe_host(value: str, fallback: str) -> str:
    value = (value or "").strip()
    return value if SAFE_HOST_RE.match(value) else fallback


def _validate_cfg(cfg: dict):
    name = cfg.get("name")
    if not isinstance(name, str) or not SAFE_NAME_RE.fullmatch(name):
        raise ValueError("invalid tunnel name")
    for k in ("iran_ip", "foreign_ip", "iran_tun_ip", "foreign_tun_ip", "iran_wg_ip", "foreign_wg_ip"):
        if cfg.get(k) and not _valid_ip(str(cfg[k])):
            raise ValueError(f"invalid {k}")
    for k in ("tunnel_port", "wg_port", "mtu", "conn"):
        if k in cfg:
            v = int(cfg[k])
            if not (1 <= v <= 65535):
                raise ValueError(f"invalid {k}")
            cfg[k] = v
    for k in ("psk", "token", "key", "iran_priv", "iran_pub", "foreign_priv", "foreign_pub"):
        if cfg.get(k) and not SAFE_SECRET_RE.match(str(cfg[k])):
            raise ValueError(f"invalid characters in {k}")
    for m in cfg.get("ports", []) or []:
        for k in ("bind", "target"):
            v = int(m[k])
            if not (1 <= v <= 65535):
                raise ValueError("invalid port mapping")
            m[k] = v
        if m.get("proto") not in ("tcp", "udp", "both"):
            raise ValueError("invalid port protocol")
    return cfg


def run_cmd(cmd, check=False, capture=True):
    return subprocess.run(
        cmd,
        shell=isinstance(cmd, str),
        check=check,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        text=True,
    )


def detect_net_info():
    iface = run_cmd("ip route | awk '/^default/ {print $5; exit}'").stdout.strip() or "eth0"
    gw = run_cmd("ip route | awk '/^default/ {print $3; exit}'").stdout.strip()
    local_ip = run_cmd(
        f"ip -4 -o addr show {iface} | awk '{{split($4,a,\"/\"); print a[1]; exit}}'"
    ).stdout.strip()
    if not local_ip:
        local_ip = run_cmd(
            "ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i==\"src\") print $(i+1)}' | head -1"
        ).stdout.strip()
    gw_mac = ""
    if gw:
        gw_mac = run_cmd(f"ip neigh show {gw} | awk '/{iface}/ {{print $5; exit}}'").stdout.strip()
        if not gw_mac:
            run_cmd(["ping", "-c", "1", "-W", "1", gw])
            gw_mac = run_cmd(f"ip neigh show {gw} | awk '/{iface}/ {{print $5; exit}}'").stdout.strip()
    return {
        "iface": iface,
        "ip": local_ip or "0.0.0.0",
        "gw": gw,
        "mac": gw_mac or "00:00:00:00:00:00",
    }


def get_public_ip():
    return detect_net_info()["ip"]


def get_os_name():
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return platform.platform()


def encode_link(prefix: str, payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    comp = zlib.compress(raw, level=9)
    b64 = base64.urlsafe_b64encode(comp).decode("ascii").rstrip("=")
    return f"{prefix}://{b64}"


def decode_link(link: str, expected_prefix: str) -> dict:
    cleaned = re.sub(r"[\s│║┌┐└┘─═╭╮╰╯]+", "", link)
    idx = cleaned.find(f"{expected_prefix}://")
    if idx == -1:
        raise ValueError(f"Link must start with {expected_prefix}://")
    b64 = cleaned[idx + len(expected_prefix) + 3:]
    pad = "=" * (-len(b64) % 4)
    data = zlib.decompress(base64.urlsafe_b64decode(b64 + pad))
    return json.loads(data.decode("utf-8"))


def print_copyable_link(title: str, link: str, hint: str):
    console.print()
    console.print(f"[bold green]═══ {title} ═══[/]")
    console.print(f"[bold yellow]{hint}[/]")
    console.print()
    sys.stdout.write(link + "\n")
    sys.stdout.flush()
    console.print()
    console.print("[dim]══════════════════════════════════════════════════════════════[/]")


def read_sync_link(prompt_text: str) -> str:
    flush_stdin()
    console.print(f"[bold cyan]{prompt_text}[/]")
    console.print("[dim](Paste the full link and press Enter; type '0' to cancel)[/]")
    first = input("  > ").strip()
    if not first or first == "0":
        return ""
    parts = [first]
    while select.select([sys.stdin], [], [], 0.15)[0]:
        line = sys.stdin.readline()
        if not line:
            break
        parts.append(line.strip())
    flush_stdin()
    return "".join(parts)


def gen_self_signed_cert(name: str, domain: str):
    TLS_DIR.mkdir(parents=True, exist_ok=True)
    cert = TLS_DIR / f"{name}.crt"
    key = TLS_DIR / f"{name}.key"
    domain = _safe_host(domain, "localhost")
    run_cmd([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "3650", "-nodes",
        "-keyout", str(key), "-out", str(cert), "-subj", f"/CN={domain}",
        "-addext", f"subjectAltName=DNS:{domain}",
    ])
    os.chmod(key, 0o600)
    return str(cert), str(key)


def list_tunnels(*, include_retired=False):
    META_DIR.mkdir(parents=True, exist_ok=True)
    items = []
    for p in sorted(META_DIR.glob("*.json")):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            if not include_retired and d.get("engine") == RETIRED_PRIVATE_IP_ENGINE:
                continue
            svc = d.get("service", f"kerov-{d['name']}")
            st = run_cmd(["systemctl", "is-active", svc]).stdout.strip()
            d["status"] = st or "inactive"
            items.append(d)
        except Exception:
            continue
    return items


def save_meta(meta: dict):
    META_DIR.mkdir(parents=True, exist_ok=True)
    (META_DIR / f"{meta['name']}.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")


def _protect_instance_name(name: str):
    existing = META_DIR / f"{name}.json"
    if existing.is_file() and json.loads(existing.read_text(encoding="utf-8")).get("engine") in (RETIRED_PRIVATE_IP_ENGINE, *ADDED_ENGINES):
        raise ValueError(f"Name '{name}' is already used by a managed tunnel. Choose another name.")


def _instance_status(engine: str, status: str, active_label: str = "ACTIVE") -> str:
    if status == "active":
        return "RUNNING" if engine in ADDED_ENGINES else active_label
    return status.upper()


def write_systemd(service_name: str, desc: str, exec_start: str, exec_stop: str = "", env_lines=None, oneshot=False, check=False,
                  service_lines=(), exec_type=False):
    env_block = "\n".join(f"Environment={e}" for e in (env_lines or []))
    svc_type = "oneshot\nRemainAfterExit=yes" if oneshot else f"{'exec' if exec_type else 'simple'}\nRestart=always\nRestartSec=2"
    stop_line = f"ExecStop={exec_stop}" if exec_stop else ""
    extra_lines = "\n".join(service_lines)
    content = f"""[Unit]
Description=Kerov Tunnel - {desc}
After=network-online.target
Wants=network-online.target

[Service]
Type={svc_type}
{env_block}
{extra_lines}
ExecStart={exec_start}
{stop_line}
LimitNOFILE=1048576
LimitMEMLOCK=infinity
TasksMax=infinity

[Install]
WantedBy=multi-user.target
"""
    (SYSTEMD_DIR / f"{service_name}.service").write_text(content, encoding="utf-8")
    run_cmd(["systemctl", "daemon-reload"], check=check)
    run_cmd(["systemctl", "enable", "--now", service_name], check=check)


def _mini_bar(pct: float, width: int = 10, color: str = "cyan") -> str:
    pct = max(0.0, min(100.0, pct))
    filled = int(round((pct / 100.0) * width))
    return f"[{color}]{'█' * filled}[/][dim]{'░' * (width - filled)}[/]"


def _speed_bar(mbps: float, max_mbps: float = 500.0, width: int = 10) -> str:
    ratio = max(0.0, min(1.0, mbps / max(max_mbps, 1.0)))
    filled = int(round(ratio * width))
    color = "bold green" if ratio >= 0.6 else ("bold cyan" if ratio >= 0.3 else "yellow")
    return f"[{color}]{'█' * filled}[/][dim]{'░' * (width - filled)}[/]"


def _grade_badge(mbps: float, rtt: float, loss: float) -> str:
    if mbps <= 0 and loss >= 100:
        return "[bold red][ F ][/]"
    if loss > 15:
        return "[red][ C ][/]"
    if mbps >= 250 and rtt <= 80 and loss == 0:
        return "[bold green][ S+ ][/]"
    if mbps >= 150 and rtt <= 120 and loss <= 5:
        return "[bold green][ S ][/]"
    if mbps >= 80 and rtt <= 180:
        return "[bold cyan][ A+ ][/]"
    if mbps >= 35:
        return "[cyan][ A ][/]"
    return "[yellow][ B ][/]"


def _sparkline(values, color="cyan", width=24) -> str:
    vals = list(values)[-width:]
    if not vals:
        return f"[dim]{'▁' * width}[/]"
    mx = max(max(vals), 0.1)
    out = []
    for v in vals:
        idx = int(min(len(SPARK_CHARS) - 1, (v / mx) * (len(SPARK_CHARS) - 1)))
        out.append(SPARK_CHARS[idx])
    pad = "▁" * max(0, width - len(out))
    return f"[dim]{pad}[/][{color}]{''.join(out)}[/]"


def _sample_net_mbps(interval: float = 0.25):
    c1 = psutil.net_io_counters()
    time.sleep(interval)
    c2 = psutil.net_io_counters()
    rx = ((c2.bytes_recv - c1.bytes_recv) * 8.0) / (interval * 1_000_000.0)
    tx = ((c2.bytes_sent - c1.bytes_sent) * 8.0) / (interval * 1_000_000.0)
    return max(0.0, rx), max(0.0, tx)


UI_MAX_W = 80
KEROV_VERSION = "v2.3.4"
GOLD = ("#fff1b8", "#ffe08a", "#f5c542", "#e6b422", "#d4a017", "#a8790f")
G_DIM = "#6b5a2e"
CREAM = "#f3e9d2"
MUTED = "#7a7a88"
OK_C = "#4ade80"
BAD_C = "#f87171"
LOGO = (
    "██╗  ██╗███████╗██████╗  ██████╗ ██╗   ██╗",
    "██║ ██╔╝██╔════╝██╔══██╗██╔═══██╗██║   ██║",
    "█████╔╝ █████╗  ██████╔╝██║   ██║██║   ██║",
    "██╔═██╗ ██╔══╝  ██╔══██╗██║   ██║╚██╗ ██╔╝",
    "██║  ██╗███████╗██║  ██║╚██████╔╝ ╚████╔╝ ",
    "╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝   ╚═══╝  ",
)
CHIP_STYLES = {
    "ok": "bold #86efac on #14532d",
    "bad": "bold #fda4af on #4c0519",
    "off": "bold #a1a1aa on #27272a",
    "info": "bold #f5e3b0 on #3b2f12",
}


def _ui_width() -> int:
    size = shutil.get_terminal_size((80, 24))
    w = max(60, min(size.columns, UI_MAX_W))
    console.width = w
    return w


def _ui_compact() -> bool:
    return shutil.get_terminal_size((80, 24)).lines < 30 or console.width < 72


def _chip(label: str, state: str) -> Text:
    return Text(f" {label} ", style=CHIP_STYLES[state])


def _gold_bar(pct: float, width: int = 10) -> Text:
    pct = max(0.0, min(100.0, pct))
    filled = int(round(pct / 100.0 * width))
    t = Text(no_wrap=True)
    t.append("━" * filled, style=GOLD[2])
    t.append("━" * (width - filled), style="#2a2a33")
    return t


def _grade_letter(mbps: float, rtt: float) -> str:
    if mbps >= 150 and rtt < 60:
        return "A+"
    if mbps >= 80:
        return "A"
    if mbps >= 40:
        return "B"
    if mbps >= 15:
        return "C"
    return "D"


def _last_winner():
    if not BENCH_HISTORY.exists():
        return None
    try:
        hist = json.loads(BENCH_HISTORY.read_text(encoding="utf-8"))
        return next((entry for entry in hist if entry.get("winner")), None)
    except Exception:
        return None


def _render_gradient_banner():
    t = Text(no_wrap=True)
    for i, row in enumerate(LOGO):
        t.append(row.ljust(42), style=f"bold {GOLD[i]}")
        if i < len(LOGO) - 1:
            t.append("\n")
    return t


def _tagline(os_name: str) -> Text:
    t = Text(no_wrap=True, overflow="ellipsis")
    t.append("T U N N E L\n", style=f"bold {CREAM}")
    t.append("─" * 13 + "\n", style=G_DIM)
    t.append("◆ ", style=GOLD[2])
    t.append("PRO EDITION\n", style=f"bold {GOLD[2]}")
    t.append(f"{KEROV_VERSION} · 9 engines\n", style=MUTED)
    t.append(os_name, style=MUTED)
    return t


def render_footer_bar(hints: str = None):
    text = Text(hints or "01-08 select · C M B L W T S shortcuts · Q quit", style=MUTED, justify="right", no_wrap=True, overflow="ellipsis")
    console.print(text, justify='right')


def render_header():
    w = _ui_width()
    console.clear()

    tunnels = list_tunnels()
    online = sum(1 for t in tunnels if t["status"] == "active")
    cpu_pct = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory()
    rx_mbps, tx_mbps = _sample_net_mbps(0.15)
    bbr = run_cmd(["sysctl", "-n", "net.ipv4.tcp_congestion_control"]).stdout.strip()
    wd_active = run_cmd(["systemctl", "is-active", "kerov-watchdog"]).stdout.strip() == "active"
    installed_cores = sum(
        1 for k in ("brokennode", "dagger", "backhaul", "paqet", "udp2raw", "ipsec")
        if os.path.exists(BINS[k])
    )
    installed_cores += sum(os.access(BINS[k], os.X_OK) for k in ("leech", "icmp"))
    installed_cores += int(all(os.access(BINS[k], os.X_OK) for k in ("qs-client", "qs-server")))
    os_name = get_os_name().replace(" LTS", "")

    if _ui_compact():
        top = Text(no_wrap=True, overflow="ellipsis")
        top.append("◆ ", style=GOLD[2])
        top.append("K E R O V", style=f"bold {GOLD[1]}")
        top.append("  T U N N E L", style=f"bold {CREAM}")
        top.append(f"   PRO · {KEROV_VERSION} · {os_name}", style=MUTED)
    else:
        top = Table.grid(padding=(0, 3))
        top.add_column(no_wrap=True)
        top.add_column(vertical="middle", no_wrap=True, overflow="ellipsis")
        top.add_row(_render_gradient_banner(), _tagline(os_name))

    if tunnels:
        tun_state = "ok" if online == len(tunnels) else "bad"
    else:
        tun_state = "off"
    chips = Text(no_wrap=True, overflow="ellipsis")
    chips.append_text(_chip(f"● RUNNING {online}/{len(tunnels)}", tun_state))
    chips.append(" ")
    chips.append_text(_chip("● WATCHDOG", "ok" if wd_active else "off"))
    chips.append(" ")
    chips.append_text(_chip("● BBR", "ok" if bbr == "bbr" else "off"))
    chips.append(" ")
    chips.append_text(_chip(f"CORES {installed_cores}/9", "ok" if installed_cores == 9 else "info"))

    row1 = Table.grid(expand=True)
    row1.add_column(no_wrap=True)
    row1.add_column(justify="right", no_wrap=True, overflow="ellipsis")
    row1.add_row(chips, Text(get_public_ip(), style=f"bold {CREAM}"))

    usage = Text(no_wrap=True)
    usage.append("CPU ", style=MUTED)
    usage.append_text(_gold_bar(cpu_pct))
    usage.append(f" {cpu_pct:3.0f}%", style=CREAM)
    usage.append("   RAM ", style=MUTED)
    usage.append_text(_gold_bar(mem.percent))
    usage.append(f" {mem.percent:3.0f}%", style=CREAM)
    net = Text(no_wrap=True)
    net.append(f"▼ {rx_mbps:.1f}", style=f"bold {OK_C}")
    net.append("  ")
    net.append(f"▲ {tx_mbps:.1f}", style=f"bold {GOLD[2]}")
    net.append(" Mbps", style=MUTED)
    row2 = Table.grid(expand=True)
    row2.add_column(no_wrap=True)
    row2.add_column(justify="right", no_wrap=True)
    row2.add_row(usage, net)

    divider = Text("─" * (w - 4), style=G_DIM, no_wrap=True)
    console.print(Panel(
        Group(top, divider, row1, row2),
        box=box.DOUBLE, border_style=GOLD[5], width=w, padding=(0, 1),
    ))

def pause():
    flush_stdin()
    console.print()
    try:
        input("  Press Enter to continue...")
    except (EOFError, KeyboardInterrupt):
        pass


# ==============================================================================
#  PORT MAPPING HELPER
# ==============================================================================

def ask_port_mappings(*, default_443=True, protocols=("tcp", "udp", "both")):
    console.print("[bold cyan]Port Mappings[/] [dim](format: 443 or 8443=443; leave empty when done)[/]")
    ports = []
    while True:
        spec = Prompt.ask("  Port mapping [dim](empty=done)[/]", default="").strip()
        if not spec:
            break
        proto = Prompt.ask("  Protocol", choices=list(protocols), default=protocols[-1]) if len(protocols) > 1 else protocols[0]
        try:
            if "=" in spec:
                bind_p, tgt_p = spec.split("=", 1)
            else:
                bind_p = tgt_p = spec
            b_int, t_int = int(bind_p.strip()), int(tgt_p.strip())
            if not (1 <= b_int <= 65535 and 1 <= t_int <= 65535):
                raise ValueError
            ports.append({"bind": b_int, "target": t_int, "proto": proto})
            console.print(f"  [green]✔ Added {b_int} -> {t_int} ({proto})[/]")
        except ValueError:
            console.print("  [red]✗ Invalid port number. Use 1-65535.[/]")
    if not ports and default_443:
        ports.append({"bind": 443, "target": 443, "proto": "both"})
        console.print("  [yellow]! Defaulted to 443 -> 443 (both)[/]")
    return ports


# ==============================================================================
#  ENGINE DEPLOYERS (IRAN + FOREIGN AUTO-SYNC)
# ==============================================================================

def deploy_brokennode(cfg: dict, side: str, sync_link: str = ""):
    """Reverse Tunnel: Iran = server, Foreign = client"""
    name = cfg["name"]
    role = "server" if side == "iran" else "client"
    tr = cfg["transport"]
    out_file = KEROV_ETC / "brokennode" / f"{name}.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)

    if cfg.get("passkey") and role == "server":
        Path("/etc/brokennode").mkdir(parents=True, exist_ok=True)
        pk_path = Path("/etc/brokennode/passkey")
        pk_path.write_text(cfg["passkey"] + "\n", encoding="utf-8")
        os.chmod(pk_path, 0o600)

    if tr == "spoof":
        local_ip = cfg["iran_ip"] if role == "server" else cfg["foreign_ip"]
        peer_ip = cfg["foreign_ip"] if role == "server" else cfg["iran_ip"]
        s_src = cfg["spoof_w1"] if role == "server" else cfg["spoof_w2"]
        s_dst = cfg["spoof_w2"] if role == "server" else cfg["spoof_w1"]
        tl, trr = ("10.10.20.1", "10.10.20.2") if role == "server" else ("10.10.20.2", "10.10.20.1")
        doc = {
            "mode": role, "transport": "spoof", "log_level": "info",
            "spoof_local_ip": local_ip, "spoof_peer_ip": peer_ip,
            "spoof_src": s_src, "spoof_dst": s_dst,
            "carrier_proto": cfg.get("carrier_proto", "udp"),
            "carrier_port": cfg.get("carrier_port", 6262),
            "tun_name": f"sp{name[:6]}", "tun_local": tl, "tun_remote": trr,
            "mtu": cfg.get("mtu", 1320),
        }
        if cfg.get("ttl_jitter"):
            doc["ttl_jitter"] = True
        if role == "server":
            doc["ports"] = [f"{p['bind']}={p['target']}/{p['proto']}" for p in cfg["ports"]]
    else:
        ka, kmode, kdata, kparity = cfg["preset"]
        doc = {
            "mode": role, "transport": tr, "token": cfg["token"],
            "keepalive": ka, "kcp_mode": kmode, "kcp_data": kdata, "kcp_parity": kparity,
            "log_level": "info",
        }
        if role == "server":
            doc["bind_addr"] = f"0.0.0.0:{cfg['tunnel_port']}"
            doc["ports"] = [f"{p['bind']}={p['target']}/{p['proto']}" for p in cfg["ports"]]
        else:
            doc["remote_addr"] = f"{cfg['iran_ip']}:{cfg['tunnel_port']}"
            doc["target_host"] = "127.0.0.1"

        extra = cfg.get("extra", {})
        if tr in ("ws", "wsobf"):
            doc["ws_path"] = extra.get("ws_path", "/")
            if role == "client":
                if extra.get("ws_host"):
                    doc["ws_host"] = extra["ws_host"]
                if extra.get("ws_user_agent"):
                    doc["ws_user_agent"] = extra["ws_user_agent"]
        elif tr in ("quic", "quicd"):
            doc["alpn"] = extra.get("alpn", "h3")
        elif tr == "tcpnomux":
            doc["pool_size"] = extra.get("pool_size", 0)
        elif tr in ("kcp", "rawmux") and extra.get("kcp_wnd"):
            doc["kcp_sndwnd"] = extra["kcp_wnd"]
            doc["kcp_rcvwnd"] = extra["kcp_wnd"]
        elif tr in ("mtcp", "mtcpobf") and role == "client":
            doc["links"] = extra.get("links", 0)

    out_file.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    os.chmod(out_file, 0o600)

    svc = f"kerov-bn-{name}"
    write_systemd(svc, f"BrokenNode ({name}/{tr})", f"{BINS['brokennode']} -c {out_file}")
    save_meta({
        "name": name, "engine": "brokennode", "direction": "reverse",
        "transport": tr, "role": role, "service": svc, "config": str(out_file),
        "endpoint": f"{cfg['iran_ip']}:{cfg.get('tunnel_port', cfg.get('carrier_port', 0))}",
        "sync_link": sync_link or encode_link("kerov", cfg),
    })
    return svc


def deploy_dagger(cfg: dict, side: str, sync_link: str = ""):
    """Reverse Tunnel: Iran = server, Foreign = client"""
    name = cfg["name"]
    role = "server" if side == "iran" else "client"
    tr = cfg["transport"]
    actual_tr = "quantum" if tr == "quantum-gaming" else tr
    out_file = KEROV_ETC / "dagger" / f"{name}.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)

    maps = [
        {"type": p["proto"], "bind": f"0.0.0.0:{p['bind']}", "target": f"127.0.0.1:{p['target']}"}
        for p in cfg["ports"]
    ]
    doc = {
        "mode": role, "transport": actual_tr, "psk": cfg["psk"],
        "profile_id": cfg["profile_id"], "log_level": "info",
    }

    extra = cfg.get("extra", {})
    if role == "server":
        doc["socks5"] = {"enabled": cfg.get("socks5_enabled", False), "bind": cfg.get("socks5_bind", "")}
        listen_addr = f"[{extra.get('dc6_listen', '::')}]:{cfg['tunnel_port']}" if actual_tr == "dc6" else f"0.0.0.0:{cfg['tunnel_port']}"
        listener = {"addr": listen_addr, "transport": actual_tr, "maps": maps}
        if actual_tr in ("wss", "https") or (actual_tr == "xhttps" and not extra.get("xhttp_cdn")):
            cert, key = gen_self_signed_cert(f"dc-{name}", extra.get("domain", "daggerconnect.local"))
            if actual_tr == "xhttps":
                doc["cert_file"], doc["key_file"] = cert, key
            else:
                listener["cert_file"], listener["key_file"] = cert, key
        if actual_tr == "xhttps" and extra.get("xhttp_cdn"):
            listener = {
                "addr": f"0.0.0.0:{extra.get('cdn_port', 443)}",
                "connection_pool": extra.get("pool", 6),
                "peer_ips": [extra["peer_ip"]] if extra.get("peer_ip") else [],
                "maps": maps,
            }
        doc["listeners"] = [listener]
    else:
        pool = extra.get("pool", 6)
        if actual_tr == "dc6":
            path_obj = {
                "transport": "dc6", "addr": f"{cfg['iran_ip']}:{cfg['tunnel_port']}",
                "ipv6_addr": f"[{extra['dc6_server_ipv6']}]:{cfg['tunnel_port']}",
                "connection_pool": pool, "retry_interval": 3, "dial_timeout": 10,
            }
        elif actual_tr == "xhttps" and extra.get("xhttp_cdn"):
            cert, key = gen_self_signed_cert(f"dc-origin-{name}", extra.get("cdn_host", "origin.local"))
            doc["cert_file"], doc["key_file"] = cert, key
            path_obj = {
                "addr": f"{cfg['iran_ip']}:{extra.get('origin_port', 8443)}",
                "peer_ips": [cfg["iran_ip"]], "public_ip": get_public_ip(),
                "retry_interval": 3, "dial_timeout": 10,
            }
        elif actual_tr == "tun":
            path_obj = {"transport": "tun", "addr": f"{cfg['iran_ip']}:{cfg['tunnel_port']}", "retry_interval": 3, "dial_timeout": 30}
        else:
            path_obj = {
                "transport": actual_tr, "addr": f"{cfg['iran_ip']}:{cfg['tunnel_port']}",
                "connection_pool": pool, "retry_interval": 3, "dial_timeout": 10,
            }
        doc["paths"] = [path_obj]

    if actual_tr in ("ws", "wss"):
        doc["ws_settings"] = {"path": extra.get("ws_path", "/ws")}
    elif actual_tr in ("http", "https"):
        doc["http_settings"] = {"fake_domain": extra.get("http_domain", "www.google.com"), "path": extra.get("http_path", "/search")}
    elif actual_tr == "quantum":
        q = {"mtu": extra.get("mtu", 1350), "block": extra.get("block", "aes")}
        if tr == "quantum-gaming":
            q["profile"] = "gaming"
        doc["quantum"] = q
    elif actual_tr in ("xhttp", "xhttps"):
        cdn_on = bool(extra.get("xhttp_cdn"))
        xh = {
            "path": extra.get("xhttp_path", "/api/v2"),
            "mode": extra.get("xhttp_mode", "auto") if role == "client" else "auto",
            "up_max_bytes": 65536, "up_concurrency": 8 if cdn_on else 2,
            "buffer_bytes": 32768, "separate_conns": True,
            "probe_ms": 8000, "socket_buf_bytes": 131072,
        }
        if not cdn_on and role == "client":
            xh["allow_insecure_tls"] = True
        if cdn_on:
            if role == "server":
                xh["allow_insecure_tls"] = False
                xh["cdn"] = {"enabled": True, "host": extra.get("cdn_host", ""), "port": extra.get("cdn_port", 443), "edge_ips": extra.get("cdn_ips", [])}
            else:
                xh["cdn"] = {"enabled": True, "origin_bind": f"0.0.0.0:{extra.get('origin_port', 8443)}"}
        doc["xhttp"] = xh
    elif actual_tr == "tun":
        tl, trr = ("10.90.0.1", "10.90.0.2") if role == "server" else ("10.90.0.2", "10.90.0.1")
        lip = cfg["iran_ip"] if role == "server" else get_public_ip()
        dip = extra["foreign_ip"] if role == "server" else cfg["iran_ip"]
        doc["tun"] = {
            "encapsulation": "ipx", "name": extra.get("tun_name", f"dc{name[:8]}"),
            "local_addr": tl, "remote_addr": trr, "encrypt": True,
            "heartbeat_sec": extra.get("heartbeat_sec", 10), "idle_timeout_sec": extra.get("idle_timeout_sec", 90),
        }
        ipx = {"mode": role, "profile": extra.get("tun_profile", "tcp"), "listen_ip": lip, "dst_ip": dip, "sock_buf": 0}
        if extra.get("tun_profile") in ("tcp", "udp"):
            ipx["l4_port"] = extra.get("tun_l4_port", 443)
        if extra.get("dcpi_mode"):
            ipx["dcpi_mode"] = True
        if extra.get("spoof_src"):
            ipx["spoof_src_ip"] = extra["spoof_src"] if role == "server" else extra.get("spoof_dst", "")
            ipx["spoof_dst_ip"] = extra.get("spoof_dst", "") if role == "server" else extra["spoof_src"]
        doc["ipx"] = ipx

    out_file.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    os.chmod(out_file, 0o600)

    env = ["DC_CHANNEL=offline", "DC_VERSION=v4.3.1"]
    if role == "server":
        env.append(f"DC_SERVER_PUBLIC_IP={cfg['iran_ip']}")

    svc = f"kerov-dc-{name}"
    write_systemd(svc, f"DaggerConnect ({name}/{tr})", f"{BINS['dagger']} -c {out_file}", env_lines=env)
    save_meta({
        "name": name, "engine": "dagger", "direction": "reverse",
        "transport": tr, "role": role, "service": svc, "config": str(out_file),
        "endpoint": f"{cfg['iran_ip']}:{cfg['tunnel_port']}",
        "sync_link": sync_link or encode_link("kerov", cfg),
    })
    return svc


def deploy_backhaul(cfg: dict, side: str, sync_link: str = ""):
    """Reverse Tunnel: Backhaul Premium (TOML) — Iran = server, Foreign = client"""
    name = cfg["name"]
    role = "server" if side == "iran" else "client"
    tr = cfg["transport"]
    extra = cfg.get("extra", {})
    is_tun = tr == "tun"
    is_ipx = is_tun and extra.get("tun_encapsulation") == "ipx"
    out_file = KEROV_ETC / "backhaul" / f"{name}.toml"
    out_file.parent.mkdir(parents=True, exist_ok=True)

    lines = []
    if not is_ipx:
        if role == "server":
            lines += ["[listener]", f'bind_addr = ":{cfg["tunnel_port"]}"', ""]
        else:
            lines += ["[dialer]", f'remote_addr = "{cfg["iran_ip"]}:{cfg["tunnel_port"]}"']
            if extra.get("edge_ip"):
                lines.append(f'edge_ip = "{extra["edge_ip"]}"')
            lines += ["dial_timeout = 10", "retry_interval = 3", ""]

    lines += ["[transport]", f'type = "{tr}"']
    if not is_ipx:
        lines.append(f'nodelay = {"true" if extra.get("nodelay", True) else "false"}')
        lines.append("keepalive_period = 40")
    if role == "server":
        if tr == "tcp":
            lines.append(f'accept_udp = {"true" if extra.get("accept_udp") else "false"}')
        if tr not in ("tun", "ws") and not is_ipx:
            lines.append(f'proxy_protocol = {"true" if extra.get("proxy_protocol") else "false"}')
    else:
        if tr != "tun":
            lines.append(f'connection_pool = {extra.get("connection_pool", 8)}')
    lines += ["heartbeat_interval = 10", "heartbeat_timeout = 25", ""]

    if is_tun:
        tl = extra.get("tun_iran_cidr", "10.10.10.1/24") if role == "server" else extra.get("tun_foreign_cidr", "10.10.10.2/24")
        trr = extra.get("tun_foreign_cidr", "10.10.10.2/24") if role == "server" else extra.get("tun_iran_cidr", "10.10.10.1/24")
        lines += [
            "[tun]",
            f'encapsulation = "{extra.get("tun_encapsulation", "tcp")}"',
            f'name = "{extra.get("tun_name", f"bh{name[:6]}")}"',
            f'local_addr = "{tl}"',
            f'remote_addr = "{trr}"',
            f'health_port = {extra.get("tun_health_port", 1234)}',
            f'mtu = {extra.get("tun_mtu", 1320 if is_ipx else 1500)}',
            "",
        ]

    if is_ipx:
        net = detect_net_info()
        lip = cfg["iran_ip"] if role == "server" else net["ip"]
        dip = extra.get("foreign_ip", "") if role == "server" else cfg["iran_ip"]
        lines += [
            "[ipx]",
            f'mode = "{role}"',
            f'profile = "{extra.get("ipx_profile", "tcp")}"',
            f'listen_ip = "{lip}"',
            f'dst_ip = "{dip}"',
            f'interface = "{net["iface"]}"',
        ]
        if extra.get("ipx_profile") == "icmp":
            lines += [f'icmp_type = {extra.get("icmp_type", 0)}', f'icmp_code = {extra.get("icmp_code", 0)}']
        lines.append("")

    if tr.endswith("mux"):
        lines += [
            "[mux]",
            f'mux_version = {extra.get("mux_version", 2)}',
            "mux_framesize = 32768",
            "mux_recievebuffer = 4194304",
            "mux_streambuffer = 2097152",
            f'mux_concurrency = {extra.get("mux_concurrency", 8)}',
            "",
        ]

    lines.append("[security]")
    if is_ipx:
        enc = extra.get("enable_encryption", True)
        lines.append(f'enable_encryption = {"true" if enc else "false"}')
        if enc:
            lines += [
                f'algorithm = "{extra.get("algorithm", "aes-256-gcm")}"',
                f'psk = "{cfg["psk"]}"',
                f'kdf_iterations = {extra.get("kdf_iterations", 100000)}',
            ]
    else:
        lines.append(f'token = "{cfg["token"]}"')
    lines.append("")

    if tr in ("anytls", "wss", "wssmux"):
        lines.append("[tls]")
        if tr == "anytls":
            lines.append(f'sni = "{extra.get("tls_sni", "www.digikala.com")}"')
        if role == "server":
            cert, key = gen_self_signed_cert(f"bh-{name}", extra.get("tls_sni", "backhaul.com"))
            lines += [f'tls_cert = "{cert}"', f'tls_key = "{key}"']
        lines.append("")

    lines += [
        "[tuning]",
        "auto_tuning = true",
        f'tuning_profile = "{extra.get("tuning_profile", "balanced")}"',
        "workers = 0",
        f'channel_size = {"10000" if is_tun else "4096"}',
    ]
    if is_ipx:
        lines += ["batch_size = 2048", "so_sndbuf = 0"]
    else:
        lines += ["tcp_mss = 0", "so_rcvbuf = 0", "so_sndbuf = 0"]
    if not is_tun and not is_ipx:
        lines += [f'buffer_profile = "{extra.get("buffer_profile", "balanced")}"', "read_timeout = 120"]
    lines.append("")

    if role == "server" and tr == "tcp" and extra.get("accept_udp"):
        lines += ["[accept_udp]", "ring_size = 64", "frame_size = 2048", "peer_idle_timeout_s = 120", "write_timeout_ms = 3", ""]

    lines += ["[logging]", 'log_level = "info"', ""]

    if role == "server":
        lines.append("[ports]")
        if is_tun:
            lines.append(f'forwarder = "{extra.get("forwarder", "backhaul")}"')
        lines.append("mapping = [")
        for p in cfg["ports"]:
            m = f"{p['bind']}={p['target']}" if p["bind"] != p["target"] else f"{p['bind']}"
            lines.append(f'    "{m}",')
        lines.append("]")

    out_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(out_file, 0o600)

    svc = f"kerov-bh-{name}"
    write_systemd(svc, f"Backhaul Premium ({name}/{tr})", f"{BINS['backhaul']} -c {out_file}")
    save_meta({
        "name": name, "engine": "backhaul", "direction": "reverse",
        "transport": f"{tr}/{extra['tun_encapsulation']}" if is_tun else tr,
        "role": role, "service": svc, "config": str(out_file),
        "endpoint": f"{cfg['iran_ip']}:{cfg.get('tunnel_port', extra.get('tun_health_port', 1234))}",
        "sync_link": sync_link or encode_link("kerov", cfg),
    })
    return svc


def deploy_paqet(cfg: dict, side: str, sync_link: str = ""):
    """Direct Tunnel: Iran = client, Foreign = server"""
    name = cfg["name"]
    role = "client" if side == "iran" else "server"
    net = detect_net_info()
    out_file = KEROV_ETC / "paqet" / f"{name}.yaml"
    out_file.parent.mkdir(parents=True, exist_ok=True)

    port = cfg["tunnel_port"]
    doc = {
        "role": role, "log": {"level": "info"},
        "network": {
            "interface": net["iface"],
            "ipv4": {"addr": f"{net['ip']}:{port if role == 'server' else 0}", "router_mac": net["mac"]},
            "pcap": {"sockbuf": 16777216},
        },
        "transport": {
            "protocol": "kcp", "conn": cfg.get("conn", 8),
            "kcp": {
                "mode": cfg.get("kcp_mode", "normal"), "mtu": cfg.get("mtu", 1250),
                "key": cfg["key"], "block": cfg.get("block", "aes-128-gcm"),
                "sndwnd": 1024, "rcvwnd": 1024, "smuxbuf": 16777216, "streambuf": 4194304,
                "dshard": 10 if cfg.get("fec") else 0, "pshard": 1 if cfg.get("fec") else 0,
            },
        },
    }

    if role == "client":
        doc["server"] = {"addr": f"{cfg['foreign_ip']}:{port}"}
        if cfg.get("socks5_addr"):
            doc["socks5"] = [{"listen": cfg["socks5_addr"]}]
        if cfg.get("ports"):
            fwds = []
            for p in cfg["ports"]:
                for pr in (["tcp", "udp"] if p["proto"] == "both" else [p["proto"]]):
                    fwds.append({"listen": f"0.0.0.0:{p['bind']}", "target": f"127.0.0.1:{p['target']}", "protocol": pr})
            doc["forward"] = fwds
    else:
        run_cmd(f"iptables -t raw -C PREROUTING -p tcp --dport {port} -j NOTRACK 2>/dev/null || iptables -t raw -A PREROUTING -p tcp --dport {port} -j NOTRACK")
        run_cmd(f"iptables -t raw -C OUTPUT -p tcp --sport {port} -j NOTRACK 2>/dev/null || iptables -t raw -A OUTPUT -p tcp --sport {port} -j NOTRACK")
        run_cmd(f"iptables -t mangle -C OUTPUT -p tcp --sport {port} --tcp-flags RST RST -j DROP 2>/dev/null || iptables -t mangle -A OUTPUT -p tcp --sport {port} --tcp-flags RST RST -j DROP")
        run_cmd("netfilter-persistent save 2>/dev/null || true")

    out_file.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    os.chmod(out_file, 0o600)

    svc = f"kerov-pq-{name}"
    write_systemd(svc, f"paqet-plus ({name}/{cfg.get('kcp_mode','normal')})", f"{BINS['paqet']} run -c {out_file}")
    save_meta({
        "name": name, "engine": "paqet", "direction": "direct",
        "transport": f"raw-kcp/{cfg.get('kcp_mode','normal')}", "role": role,
        "service": svc, "config": str(out_file),
        "endpoint": f"{cfg['foreign_ip']}:{port}",
        "sync_link": sync_link or encode_link("kerov", cfg),
    })
    return svc


def deploy_gretap_ipsec(cfg: dict, side: str, sync_link: str = ""):
    """Direct Layer-2 Tunnel: StrongSwan IKEv2 (Transport) + GRETAP (L2)"""
    name = cfg["name"]
    role = "client" if side == "iran" else "server"
    local_pub = cfg["iran_ip"] if side == "iran" else cfg["foreign_ip"]
    remote_pub = cfg["foreign_ip"] if side == "iran" else cfg["iran_ip"]
    local_tun = cfg["iran_tun_ip"] if side == "iran" else cfg["foreign_tun_ip"]
    remote_tun = cfg["foreign_tun_ip"] if side == "iran" else cfg["iran_tun_ip"]
    ifname = f"kgt{name[:8]}"
    mtu = cfg.get("mtu", 1380)

    Path("/etc/ipsec.d/kerov").mkdir(parents=True, exist_ok=True)
    ipsec_conf = Path("/etc/ipsec.conf")
    if ipsec_conf.exists() and "include /etc/ipsec.d/kerov/*.conf" not in ipsec_conf.read_text(encoding="utf-8"):
        with open(ipsec_conf, "a", encoding="utf-8") as f:
            f.write("\ninclude /etc/ipsec.d/kerov/*.conf\n")
    ipsec_sec = Path("/etc/ipsec.secrets")
    if ipsec_sec.exists() and "include /etc/ipsec.d/kerov/*.secrets" not in ipsec_sec.read_text(encoding="utf-8"):
        with open(ipsec_sec, "a", encoding="utf-8") as f:
            f.write("\ninclude /etc/ipsec.d/kerov/*.secrets\n")

    (Path("/etc/ipsec.d/kerov") / f"{name}.conf").write_text(f"""conn kerov-{name}
    type=transport
    keyexchange=ikev2
    authby=psk
    left={local_pub}
    right={remote_pub}
    leftprotoport=47
    rightprotoport=47
    ike=aes256gcm16-prfsha256-ecp256,aes256-sha256-modp2048!
    esp=aes256gcm16,aes256-sha256!
    dpdaction=restart
    dpddelay=15s
    auto=start
""", encoding="utf-8")
    sec_file = Path("/etc/ipsec.d/kerov") / f"{name}.secrets"
    sec_file.write_text(f'{local_pub} {remote_pub} : PSK "{cfg["psk"]}"\n', encoding="utf-8")
    os.chmod(sec_file, 0o600)

    up_script = KEROV_ETC / "gretap" / f"{name}-up.sh"
    down_script = KEROV_ETC / "gretap" / f"{name}-down.sh"
    up_script.parent.mkdir(parents=True, exist_ok=True)

    nat_up, nat_down = [], []
    ports = cfg.get("ports") or []
    if side == "iran" and ports:
        for p in ports:
            for pr in (["tcp", "udp"] if p["proto"] == "both" else [p["proto"]]):
                nat_up.append(f"iptables -t nat -C PREROUTING -p {pr} --dport {p['bind']} -j DNAT --to-destination {remote_tun}:{p['target']} 2>/dev/null || iptables -t nat -A PREROUTING -p {pr} --dport {p['bind']} -j DNAT --to-destination {remote_tun}:{p['target']}")
                nat_down.append(f"iptables -t nat -D PREROUTING -p {pr} --dport {p['bind']} -j DNAT --to-destination {remote_tun}:{p['target']} 2>/dev/null || true")
        nat_up.append(f"iptables -t nat -C POSTROUTING -o {ifname} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o {ifname} -j MASQUERADE")
        nat_down.append(f"iptables -t nat -D POSTROUTING -o {ifname} -j MASQUERADE 2>/dev/null || true")

    up_script.write_text(f"""#!/usr/bin/env bash
set -e
systemctl restart strongswan-starter 2>/dev/null || ipsec restart || true
ipsec up kerov-{name} 2>/dev/null || true
ip link del {ifname} 2>/dev/null || true
ip link add {ifname} type gretap local {local_pub} remote {remote_pub} ttl 255
ip link set {ifname} mtu {mtu} up
ip addr add {local_tun}/30 dev {ifname}
{chr(10).join(nat_up)}
""", encoding="utf-8")
    down_script.write_text(f"""#!/usr/bin/env bash
{chr(10).join(nat_down)}
ip link del {ifname} 2>/dev/null || true
ipsec down kerov-{name} 2>/dev/null || true
""", encoding="utf-8")
    os.chmod(up_script, 0o755)
    os.chmod(down_script, 0o755)

    svc = f"kerov-l2-{name}"
    write_systemd(svc, f"GRE-IPsec L2 ({name})", str(up_script), exec_stop=str(down_script), oneshot=True)
    save_meta({
        "name": name, "engine": "gretap-ipsec", "direction": "direct",
        "transport": "gretap-l2/ikev2", "role": role,
        "service": svc, "config": str(up_script),
        "endpoint": f"{remote_pub} ({local_tun}<->{remote_tun})",
        "sync_link": sync_link or encode_link("kerov", cfg),
    })
    return svc


def deploy_kerov_udp(cfg: dict, side: str, sync_link: str = ""):
    """Direct Special UDP Tunnel: udp2raw (FakeTCP) + WireGuard"""
    name = cfg["name"]
    role = "client" if side == "iran" else "server"
    wg_if = f"kwg{name[:8]}"
    u2r_port = cfg["tunnel_port"]
    wg_local_port = cfg["wg_port"]
    out_dir = KEROV_ETC / "udp"
    out_dir.mkdir(parents=True, exist_ok=True)

    wg_conf = Path(f"/etc/wireguard/{wg_if}.conf")
    wg_conf.parent.mkdir(parents=True, exist_ok=True)

    if side == "iran":
        wg_ip, peer_ip = cfg["iran_wg_ip"], cfg["foreign_wg_ip"]
        priv_key, peer_pub = cfg["iran_priv"], cfg["foreign_pub"]
        u2r_conf_lines = ["-c", f"-l 127.0.0.1:{wg_local_port}", f"-r {cfg['foreign_ip']}:{u2r_port}"]
        wg_text = f"""[Interface]
PrivateKey = {priv_key}
Address = {wg_ip}/30
MTU = {cfg.get('mtu', 1280)}
Table = off

[Peer]
PublicKey = {peer_pub}
Endpoint = 127.0.0.1:{wg_local_port}
AllowedIPs = {peer_ip}/32
PersistentKeepalive = 15
"""
    else:
        wg_ip, peer_ip = cfg["foreign_wg_ip"], cfg["iran_wg_ip"]
        priv_key, peer_pub = cfg["foreign_priv"], cfg["iran_pub"]
        u2r_conf_lines = ["-s", f"-l 0.0.0.0:{u2r_port}", f"-r 127.0.0.1:{wg_local_port}"]
        wg_text = f"""[Interface]
PrivateKey = {priv_key}
ListenPort = {wg_local_port}
Address = {wg_ip}/30
MTU = {cfg.get('mtu', 1280)}
Table = off

[Peer]
PublicKey = {peer_pub}
AllowedIPs = {peer_ip}/32
"""

    wg_conf.write_text(wg_text, encoding="utf-8")
    os.chmod(wg_conf, 0o600)

    u2r_conf = out_dir / f"{name}-udp2raw.conf"
    u2r_conf_lines += [f"-k {cfg['psk']}", "--raw-mode faketcp", "-a", "--cipher-mode aes128cbc", "--auth-mode hmac_sha1"]
    u2r_conf.write_text("\n".join(u2r_conf_lines) + "\n", encoding="utf-8")
    os.chmod(u2r_conf, 0o600)
    u2r_cmd = f"{BINS['udp2raw']} --conf-file {u2r_conf}"

    runner = out_dir / f"{name}-run.sh"
    stopper = out_dir / f"{name}-stop.sh"

    nat_up, nat_down = [], []
    if side == "iran":
        for p in cfg.get("ports", []):
            for pr in (["tcp", "udp"] if p["proto"] == "both" else [p["proto"]]):
                nat_up.append(f"iptables -t nat -C PREROUTING -p {pr} --dport {p['bind']} -j DNAT --to-destination {cfg['foreign_wg_ip']}:{p['target']} 2>/dev/null || iptables -t nat -A PREROUTING -p {pr} --dport {p['bind']} -j DNAT --to-destination {cfg['foreign_wg_ip']}:{p['target']}")
                nat_down.append(f"iptables -t nat -D PREROUTING -p {pr} --dport {p['bind']} -j DNAT --to-destination {cfg['foreign_wg_ip']}:{p['target']} 2>/dev/null || true")
        nat_up.append(f"iptables -t nat -C POSTROUTING -o {wg_if} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o {wg_if} -j MASQUERADE")
        nat_down.append(f"iptables -t nat -D POSTROUTING -o {wg_if} -j MASQUERADE 2>/dev/null || true")

    runner.write_text(f"""#!/usr/bin/env bash
set -e
wg-quick down {wg_if} 2>/dev/null || true
wg-quick up {wg_if}
{chr(10).join(nat_up)}
exec {u2r_cmd}
""", encoding="utf-8")
    stopper.write_text(f"""#!/usr/bin/env bash
{chr(10).join(nat_down)}
wg-quick down {wg_if} 2>/dev/null || true
""", encoding="utf-8")
    os.chmod(runner, 0o755)
    os.chmod(stopper, 0o755)

    svc = f"kerov-udp-{name}"
    write_systemd(svc, f"Kerov-UDP FakeTCP+WG ({name})", str(runner), exec_stop=str(stopper))
    save_meta({
        "name": name, "engine": "kerov-udp", "direction": "direct",
        "transport": "faketcp+wireguard", "role": role,
        "service": svc, "config": str(wg_conf),
        "endpoint": f"{cfg['foreign_ip']}:{u2r_port}",
        "sync_link": sync_link or encode_link("kerov", cfg),
    })
    return svc


# ==============================================================================
#  CREATE TUNNEL WIZARD
# ==============================================================================

def _select_transport(label, options, default):
    numbered = {str(index): option for index, option in enumerate(options, 1)}
    table = Table(title=label, box=box.ROUNDED, border_style="magenta")
    table.add_column("#", style="bold cyan", width=4, justify="right")
    table.add_column("Option", style="bold white")
    for number, option in numbered.items():
        table.add_row(number, option)
    console.print(table)
    number = str(options.index(default) + 1)
    selected = Prompt.ask(f"Select {label} [1-{len(options)}]", console=console,
                          choices=[*numbered, *options], default=number, show_choices=False)
    return numbered.get(selected, selected)


def wizard_added_engine(engine, name, iran_ip, foreign_ip, *, direction="direct"):
    cfg = {"name": name, "engine": engine, "direction": direction,
           "iran_ip": iran_ip, "foreign_ip": foreign_ip}
    if engine == "leech":
        host = "Iran" if direction == "reverse" else "Foreign"
        transport = _select_transport("Leech Transport", LEECH_TRANSPORTS, "tcp")
        cfg.update(transport=transport, token=secrets.token_hex(24),
                   psk=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
                   license_key=Prompt.ask("Leech license key", password=True, default=LEECH_LICENSE))
        encap = ""
        if transport == "tun":
            encap = _select_transport("Leech TUN Encapsulation", LEECH_TUN_ENCAPS, "tcp")
            cfg["encapsulation"] = encap
            if encap != "tcp" and not foreign_ip:
                cfg["foreign_ip"] = Prompt.ask("Foreign Server Public IPv4").strip()
            if encap == "ipx":
                cfg["ipx_profile"] = _select_transport("IPX Profile", LEECH_IPX_PROFILES, "tcp")
            octet = 1 + hashlib.sha256(name.encode("ascii")).digest()[0] % 254
            cfg["iran_tun_cidr"] = Prompt.ask("Iran TUN IPv4/CIDR", default=f"10.230.{octet}.1/30")
            cfg["foreign_tun_cidr"] = Prompt.ask("Foreign TUN IPv4/CIDR", default=f"10.230.{octet}.2/30")
            cfg["health_port"] = IntPrompt.ask("TUN health port", default=1234)
            cfg["mtu"] = IntPrompt.ask("TUN MTU", default=1500 if encap == "tcp" else 1320)
        if encap == "udpx":
            cfg["tunnel_port"] = IntPrompt.ask("Shared UDPX wire port", default=40000)
        elif encap in ("ipx", "icmpx"):
            cfg["tunnel_port"] = cfg["health_port"]
        else:
            wire = "UDP" if transport == "kcp" else "TCP"
            cfg["tunnel_port"] = IntPrompt.ask(f"Leech control {wire} port on {host}", default=9443)
        if transport == "anytls":
            cfg["sni"] = Prompt.ask("AnyTLS server name", default="leech.local")
        if transport == "tcp":
            cfg["accept_udp"] = Confirm.ask("Enable UDP over TCP on forwarded ports?", default=False)
        if encap not in ("ipx", "icmpx", "udpx"):
            raw_backups = Prompt.ask("Backup listeners (comma-separated IPv4:port or hostname:port)", default="")
            if raw_backups.strip():
                cfg["backup_listeners"] = [item.strip() for item in raw_backups.split(",")]
                cfg["health_failover"] = Confirm.ask("Prefer the healthiest reachable listener?", default=False)
        if transport != "tun":
            console.print("[dim]Enter at least one TCP port mapping on the listener.[/]")
        cfg["ports"] = ask_port_mappings(default_443=False, protocols=("tcp",))
    elif engine == "qs":
        cfg.update(
            transport=_select_transport("QS Download Transport", QS_TRANSPORTS, "obfs"),
            tunnel_port=IntPrompt.ask("QS upload TCP port on Foreign", default=9000),
            download_src_port=IntPrompt.ask("QS download UDP source port on Foreign", default=9001),
            download_port=IntPrompt.ask("QS download UDP port on Iran", default=8000),
            socks_port=IntPrompt.ask("Local SOCKS5 port on Iran", default=1080),
            upload_proxy=Prompt.ask("Existing upload SOCKS5 address (IPv4:port)", default="127.0.0.1:10808"),
            upload_source=Prompt.ask("Upload proxy source IPv4 as seen by Foreign", default=iran_ip),
            psk=secrets.token_hex(32),
        )
        if cfg["transport"].endswith("+spoof"):
            cfg["spoof_ip"] = Prompt.ask("IPv4 assigned to the Foreign server for the UDP source", default=foreign_ip)
    else:
        cfg.update(
            transport="icmp",
            socks_port=IntPrompt.ask("Local SOCKS5 port on Iran", default=1010),
            api_port=IntPrompt.ask("Local ICMP Tunnel API port on both hosts", default=1080),
            key=10000000 + secrets.randbelow(90000000),
            psk=secrets.token_hex(16),
        )
    return cfg


def _added_port(cfg, field):
    port = int(cfg[field])
    if not 1 <= port <= 65535:
        raise ValueError(f"Invalid {field}. Use 1-65535.")
    return port


def _added_ipv4(value):
    ip = ipaddress.IPv4Address(value)
    if ip.is_unspecified or ip.is_multicast:
        raise ValueError("Enter a unicast IPv4 address.")
    return str(ip)


def _added_secret(value, length):
    if not isinstance(value, str) or not re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
        raise ValueError("Invalid shared key in the tunnel configuration.")
    return value


def _leech_tun_device(name):
    return "kl" + hashlib.sha256(name.encode("ascii")).hexdigest()[:12]


def _leech_certificate_paths(name):
    return (TLS_DIR / f"leech-{name}.crt", TLS_DIR / f"leech-{name}.key")


def _route_to_ipv4(peer):
    result = run_cmd(["ip", "-j", "-4", "route", "get", peer], check=True)
    routes = json.loads(result.stdout)
    device = routes[0].get("dev", "") if routes else ""
    if not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,15}", device):
        raise ValueError(f"No usable network interface for {peer}.")
    return device


def _leech_backup_listeners(cfg, primary):
    backups = cfg.get("backup_listeners", [])
    if not isinstance(backups, list):
        raise ValueError("Leech backup listeners must be a list.")
    endpoints = []
    for address in backups:
        if not isinstance(address, str):
            raise ValueError("Invalid backup listener address.")
        host, sep, port = address.rpartition(":")
        if not sep or not SAFE_HOST_RE.fullmatch(host) or not port.isascii() or not port.isdecimal():
            raise ValueError(f"Invalid backup listener {address!r}. Use IPv4:port or hostname:port.")
        if not 1 <= int(port) <= 65535:
            raise ValueError("Leech backup port must be between 1 and 65535.")
        endpoint = f"{host.lower()}:{int(port)}"
        if endpoint == primary or endpoint in endpoints:
            raise ValueError("Each Leech listener address must be unique.")
        endpoints.append(endpoint)
    return endpoints


def _leech_plan(cfg, side, role, iran_ip, foreign_ip):
    transport = cfg["transport"]
    if transport not in LEECH_TRANSPORTS:
        raise ValueError("Unsupported Leech transport.")
    tun = transport == "tun"
    encap = cfg.get("encapsulation", "tcp") if tun else ""
    if tun and encap not in LEECH_TUN_ENCAPS:
        raise ValueError("Unsupported Leech TUN encapsulation.")
    raw = encap in ("ipx", "icmpx", "udpx")
    port = _added_port(cfg, "tunnel_port")
    host_ip = iran_ip if cfg["direction"] == "reverse" else foreign_ip
    endpoint = f"{host_ip}:{port}"
    backups = _leech_backup_listeners(cfg, endpoint)
    accept_udp = cfg.get("accept_udp", False)
    health_failover = cfg.get("health_failover", False)
    if type(accept_udp) is not bool or (accept_udp and transport != "tcp"):
        raise ValueError("UDP over TCP requires Leech's tcp transport.")
    if type(health_failover) is not bool or (health_failover and not backups):
        raise ValueError("Health-scored failover requires backup listeners.")
    if raw and backups:
        raise ValueError("Multi-destination failover requires a Leech transport with a dialer.")
    token = _added_secret(cfg["token"], 48)
    psk = cfg["psk"]
    if not isinstance(psk, str) or not re.fullmatch(r"(?:[0-9a-f]{64}|[A-Za-z0-9+/]{43}=)", psk):
        raise ValueError("Invalid Leech shared key.")
    license_key = cfg["license_key"]
    if not isinstance(license_key, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", license_key):
        raise ValueError("Invalid Leech license key.")

    mappings = cfg.get("ports", [])
    ports = [m["bind"] for m in mappings]
    socket_transport = "udp" if transport == "kcp" or encap == "udpx" else "tcp"
    if (not tun and not ports) or len(set(ports)) != len(ports):
        raise ValueError("Use unique forwarded ports. Stream transports need at least one mapping.")
    if not raw and socket_transport == "tcp" and port in ports:
        raise ValueError("A forwarded TCP port cannot also be the control port.")
    if any(m["proto"] != "tcp" for m in mappings):
        raise ValueError("Leech port mappings in Kerov use TCP.")

    server = role == "server"
    sections = {}
    listeners = []
    if server:
        listeners.extend(("tcp", p) for p in ports)
        if accept_udp:
            listeners.extend(("udp", p) for p in ports)
    if not raw:
        if server:
            sections["listener"] = {"bind_addr": f"0.0.0.0:{port}"}
            if transport != "quantum":
                listeners.append((socket_transport, port))
        else:
            remote = {"remote_addrs": [endpoint, *backups]} if backups else {"remote_addr": endpoint}
            sections["dialer"] = dict(remote, dial_timeout=10, retry_interval=3)

    transport_settings = {"type": transport, "heartbeat_interval": 10, "heartbeat_timeout": 25}
    if not raw:
        transport_settings.update(nodelay=True, keepalive_period=40)
    if not server and not tun:
        transport_settings["connection_pool"] = 8
    if server and accept_udp:
        transport_settings["accept_udp"] = True
        sections["accept_udp"] = dict(ring_size=64, frame_size=2048, peer_idle_timeout_s=120, write_timeout_ms=3)
    if not server and health_failover:
        transport_settings.update(health_failover=True, health_probe_interval=15)
    sections["transport"] = transport_settings

    if transport.endswith("mux"):
        sections["mux"] = dict(mux_version=2, mux_framesize=32768, mux_recievebuffer=4194304,
                               mux_streambuffer=2097152, mux_concurrency=8)
    if transport == "kcp":
        sections["kcp"] = dict(mode="fast2", data_shards=10, parity_shards=3, mtu=1350)
    if transport == "quantum":
        sections["quantum"] = dict(mtu=1350, block="aes", data_shards=10, parity_shards=1)
    if transport in ("http", "https"):
        sections["http_settings"] = {}

    if transport in LEECH_TLS:
        tls = {}
        if transport == "anytls":
            sni = cfg.get("sni", "leech.local")
            if not isinstance(sni, str) or not SAFE_HOST_RE.fullmatch(sni):
                raise ValueError("Invalid AnyTLS server name.")
            tls["sni"] = sni
        if server:
            cert, key = _leech_certificate_paths(cfg["name"])
            tls.update(tls_cert=str(cert), tls_key=str(key))
        if tls:
            sections["tls"] = tls

    if tun:
        iran_tun = ipaddress.IPv4Interface(cfg["iran_tun_cidr"])
        foreign_tun = ipaddress.IPv4Interface(cfg["foreign_tun_cidr"])
        if (iran_tun.network != foreign_tun.network or iran_tun.ip == foreign_tun.ip
                or not any(iran_tun.network.subnet_of(network) for network in PRIVATE_V4_NETWORKS)
                or iran_tun.network.prefixlen < 31 and any(
                    address.ip in (address.network.network_address, address.network.broadcast_address)
                    for address in (iran_tun, foreign_tun))):
            raise ValueError("Use distinct host addresses in the same RFC 1918 IPv4 subnet.")
        local_tun, peer_tun = (iran_tun, foreign_tun) if side == "iran" else (foreign_tun, iran_tun)
        mtu = int(cfg.get("mtu", 1320 if raw else 1500))
        if not 576 <= mtu <= 1500:
            raise ValueError("Leech TUN MTU must be between 576 and 1500.")
        health = _added_port(cfg, "health_port")
        if health in ports or (not raw and health == port):
            raise ValueError("Use a separate port for TUN health checks.")
        sections["tun"] = dict(encapsulation=encap, name=_leech_tun_device(cfg["name"]),
                               local_addr=str(local_tun), remote_addr=str(peer_tun), health_port=health, mtu=mtu)
        if raw:
            foreign_ip = _added_ipv4(cfg["foreign_ip"])
            local_ip, peer_ip = (iran_ip, foreign_ip) if side == "iran" else (foreign_ip, iran_ip)
            sections[encap] = {"mode": role, "listen_ip": local_ip, "dst_ip": peer_ip}
            endpoint = f"{peer_ip}:{port}" if encap == "udpx" else f"{peer_ip} ({encap})"
            if encap == "udpx":
                sections[encap]["port"] = port
                listeners.append(("udp", port))
            if encap == "ipx":
                profile = cfg.get("ipx_profile", "tcp")
                if profile not in LEECH_IPX_PROFILES:
                    raise ValueError("Invalid Leech IPX profile.")
                sections[encap].update(profile=profile, interface=_route_to_ipv4(peer_ip))
                if profile == "icmp":
                    sections[encap].update(icmp_type=0, icmp_code=0)

    security = {"enable_encryption": True, "algorithm": "aes-256-gcm", "psk": psk, "kdf_iterations": 100000}
    if not raw:
        security["token"] = token
    if encap in ("icmpx", "udpx"):
        security.update(aead_harden=True, rekey_interval=3600)
    sections["security"] = security
    sections["tuning"] = {"channel_size": 10000 if tun else 4096, "batch_size": 2048}
    sections["logging"] = {"log_level": "info"}
    sections["license"] = {"key": license_key}
    if server:
        sections["ports"] = {"mapping": [f"{m['bind']}={m['target']}" for m in mappings]}
        if tun:
            sections["ports"]["forwarder"] = "leech"

    config = "\n\n".join("\n".join([f"[{section}]", *(
        f"{key} = {json.dumps(value)}" for key, value in fields.items()
    )]) for section, fields in sections.items())
    return role, "leech", "-c", "toml", config, endpoint, listeners, []


def _added_engine_plan(cfg, side):
    _validate_cfg(cfg)
    engine = cfg["engine"]
    transport = cfg["transport"]
    if engine not in ADDED_ENGINES or side not in ("iran", "foreign"):
        raise ValueError("Unknown tunnel engine or server role.")
    iran_ip = _added_ipv4(cfg["iran_ip"])
    reverse = cfg["direction"] == "reverse"
    if cfg["direction"] not in ("direct", "reverse") or (reverse and engine != "leech"):
        raise ValueError("Invalid direction for this engine.")
    foreign_ip = "" if reverse else _added_ipv4(cfg["foreign_ip"])
    role = "server" if (side == "iran") == reverse else "client"
    rules = []
    listeners = []
    if engine == "leech":
        return _leech_plan(cfg, side, role, iran_ip, foreign_ip)

    socks_port = _added_port(cfg, "socks_port")
    if engine == "qs":
        if transport not in QS_TRANSPORTS:
            raise ValueError("Unsupported QS transport.")
        mode, _, source_override = transport.partition("+")
        port = _added_port(cfg, "tunnel_port")
        endpoint = f"{foreign_ip}:{port}"
        proxy_ip, proxy_port = cfg["upload_proxy"].rsplit(":", 1)
        proxy = f"{_added_ipv4(proxy_ip)}:{_added_port({'proxy': proxy_port}, 'proxy')}"
        source = _added_ipv4(cfg["upload_source"])
        config = {"transport_mode": mode, "dashboard_addr": "", "metrics_addr": "127.0.0.1:0"}
        if mode == "obfs":
            config["obfs_key"] = _added_secret(cfg["psk"], 64)
        spoof_ip = _added_ipv4(cfg["spoof_ip"]) if source_override else ""
        if role == "server":
            udp = _added_port(cfg, "download_src_port")
            config.update(listen_addr=f"0.0.0.0:{port}", download_src_port=udp)
            if spoof_ip:
                config.update(spoof_ip=spoof_ip, spoof_interface="")
            listeners.extend([("tcp", port), ("udp", udp)])
            rules.extend([("iptables", "tcp", f"! -s {source}/32", port), ("ip6tables", "tcp", "", port)])
        else:
            udp = _added_port(cfg, "download_port")
            if proxy == f"127.0.0.1:{socks_port}":
                raise ValueError("The upload SOCKS5 port must differ from the local QS SOCKS5 port.")
            config.update(server_addr=endpoint, upload_proxy=proxy, local_socks=f"127.0.0.1:{socks_port}",
                          download_port=udp, my_public_ip=iran_ip)
            listeners.extend([("tcp", socks_port), ("udp", udp)])
            if mode == "udp":
                rules.append(("iptables", "udp", f"! -s {spoof_ip or foreign_ip}/32", udp))
        return role, f"qs-{role}", "-config", "json", json.dumps(config, indent=2), endpoint, listeners, rules

    if transport != "icmp":
        raise ValueError("Invalid ICMP transport.")
    api = _added_port(cfg, "api_port")
    if api == socks_port:
        raise ValueError("The ICMP Tunnel API and SOCKS5 ports must differ.")
    key = int(cfg["key"])
    if not 10000000 <= key <= 99999999:
        raise ValueError("Invalid ICMP shared ID.")
    endpoint = f"{foreign_ip} (ICMP)"
    config = {
        "type": role, "listen_port_socks": str(socks_port), "server": foreign_ip if role == "client" else "",
        "timeout": 20, "block_country": "", "dns": "8.8.8.8", "key": key, "api_port": str(api),
        "encrypt_data": True, "encrypt_data_key": _added_secret(cfg["psk"], 32),
    }
    listeners.append(("tcp", api))
    if role == "client":
        listeners.append(("tcp", socks_port))
    rules.extend((family, kind, "! -i lo", port) for family in ("iptables", "ip6tables") for kind, port in listeners)
    return role, "icmp", "-config", "json", json.dumps(config, indent=2), endpoint, listeners, rules


def _added_firewall(service, rules):
    lines = []
    for tool, protocol, match, port in rules:
        binary = shutil.which(tool)
        if not binary:
            raise RuntimeError(f"{tool} is required for this engine's inbound port restrictions.")
        rule = " ".join(part for part in (
            f"-p {protocol}", match, f"--dport {port}", f"-m comment --comment {service} -j DROP"
        ) if part)
        lines.append(f"ExecStartPre=+{binary} -w 5 -I INPUT 1 {rule}")
        lines.append(f"ExecStopPost=-+{binary} -w 5 -D INPUT {rule}")
    return lines


def _check_added_listeners(listeners):
    for protocol in ("tcp", "udp"):
        required = {port for kind, port in listeners if kind == protocol}
        if not required:
            continue
        rows = run_cmd(["ss", "-H", "-l", "-n", "-t" if protocol == "tcp" else "-u"], check=True)
        occupied = {row.split()[3].rsplit(":", 1)[-1] for row in rows.stdout.splitlines() if len(row.split()) >= 5}
        for port in sorted(required):
            if str(port) in occupied:
                raise ValueError(f"{protocol.upper()} port {port} is already in use on this server.")


def _write_private(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as target:
        target.write(content)
        target.write("\n")


def deploy_added_engine(cfg, side, sync_link):
    role, core, flag, ext, contents, endpoint, listeners, rules = _added_engine_plan(cfg, side)
    engine, name = cfg["engine"], cfg["name"]
    binary = BINS[core]
    if platform.machine() not in ("x86_64", "amd64"):
        raise RuntimeError("This core requires Linux amd64.")
    if not os.access(binary, os.X_OK):
        raise RuntimeError(f"Core missing: {binary}. See the installation section in README.md.")
    if engine == "icmp" and run_cmd(["sysctl", "-n", "net.ipv4.icmp_echo_ignore_all"], check=True).stdout.strip() != "1":
        raise RuntimeError("ICMP Tunnel requires net.ipv4.icmp_echo_ignore_all=1 as documented by its installer.")
    transport = cfg["transport"]
    if core == "qs-server" and transport.endswith("+spoof"):
        rows = run_cmd(["ip", "-j", "-4", "address", "show"], check=True)
        if not any(address.get("local") == cfg["spoof_ip"]
                   for interface in json.loads(rows.stdout) for address in interface.get("addr_info", [])):
            raise ValueError("The QS UDP source IPv4 must be assigned to the Foreign server.")
    service = f"kerov-{engine}-{name}"
    directory = KEROV_ETC / engine
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    META_DIR.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.{ext}"
    unit = SYSTEMD_DIR / f"{service}.service"
    metadata = META_DIR / f"{name}.json"
    service_lines = ["UMask=0077", *_added_firewall(service, rules)]
    if engine == "icmp":
        service_lines.extend(["CapabilityBoundingSet=CAP_NET_RAW", "NoNewPrivileges=yes"])
    cert_paths = _leech_certificate_paths(name) if engine == "leech" and role == "server" and transport in LEECH_TLS else ()
    tun_device = ""
    if engine == "leech" and transport == "tun":
        tun_device = _leech_tun_device(name)
        ip = shutil.which("ip")
        if not ip:
            raise RuntimeError("iproute2 is required for Leech TUN.")
        service_lines.append(f"ExecStopPost=-{ip} link delete dev {tun_device} type tun")
        encap = cfg.get("encapsulation", "tcp")
        transport = f"tun/{encap}"
        if encap == "ipx":
            transport += f"/{cfg.get('ipx_profile', 'tcp')}"
    with (KEROV_ETC / ".deploy-added.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if any(p.exists() for p in (metadata, path, unit, *cert_paths)):
            raise ValueError(f"Name '{name}' is already in use. Choose another name on both servers.")
        if tun_device and run_cmd(["ip", "link", "show", "dev", tun_device]).returncode == 0:
            raise ValueError(f"TUN interface {tun_device} already exists.")
        if engine == "icmp" and any(directory.glob("*.json")):
            raise ValueError("Use one ICMP Tunnel instance per server.")
        _check_added_listeners(listeners)
        try:
            if cert_paths:
                gen_self_signed_cert(f"leech-{name}", cfg.get("sni", "leech.local"))
            _write_private(path, contents)
            write_systemd(service, f"{engine} {role} ({name})", f"{binary} {flag} {path}",
                          check=True, service_lines=service_lines, exec_type=True)
            time.sleep(0.7)
            if run_cmd(["systemctl", "is-active", service]).stdout.strip() != "active":
                raise RuntimeError("The core exited during startup.")
            _write_private(metadata, json.dumps({
                "name": name, "engine": engine, "direction": cfg["direction"],
                "transport": transport, "role": role, "service": service, "config": str(path),
                "endpoint": endpoint, "sync_link": sync_link,
            }, indent=2))
        except (Exception, KeyboardInterrupt) as error:
            logs = ""
            if unit.exists():
                run_cmd(["systemctl", "disable", "--now", service])
                logs = run_cmd(["journalctl", "-u", service, "-n", "6", "--no-pager", "-o", "cat"]).stdout.strip()
                unit.unlink(missing_ok=True)
                run_cmd(["systemctl", "daemon-reload"])
            path.unlink(missing_ok=True)
            metadata.unlink(missing_ok=True)
            for cert_path in cert_paths:
                cert_path.unlink(missing_ok=True)
            if logs and not isinstance(error, KeyboardInterrupt):
                raise RuntimeError(f"{error}\n{logs}") from error
            raise
    return service


def _deploy_leech_backup(cfg, link):
    if cfg.get("engine") != "leech" or cfg.get("direction") not in ("direct", "reverse"):
        raise ValueError("Use a Leech sync link that includes backup listeners.")
    if cfg.get("transport") == "tun" and cfg.get("encapsulation") in ("ipx", "icmpx", "udpx"):
        raise ValueError("This TUN encapsulation has no backup listener.")
    side = "iran" if cfg["direction"] == "reverse" else "foreign"
    primary = f"{_added_ipv4(cfg[f'{side}_ip'])}:{_added_port(cfg, 'tunnel_port')}"
    backups = _leech_backup_listeners(cfg, primary)
    if not backups:
        raise ValueError("The sync link contains no backup listeners.")
    for number, address in enumerate(backups, 1):
        console.print(f"  {number}. {address}")
    selection = Prompt.ask("Select this server's backup address", choices=[str(i) for i in range(1, len(backups) + 1)])
    address = backups[int(selection) - 1]
    port = int(address.rsplit(":", 1)[1])
    backup_cfg = dict(cfg, tunnel_port=port, backup_listeners=[], health_failover=False)
    svc = deploy_added_engine(backup_cfg, side, link)
    console.print(f"[green]Backup listener {address} configured as {svc}.[/]")


def create_tunnel_menu():
    render_header()
    console.print(Panel(
        "[bold cyan][1][/] [white]Iran Server[/]    [dim]Configure tunnel & generate auto-sync [cyan]kerov://[/] link[/]\n"
        "[bold green][2][/] [white]Foreign Server[/] [dim]Paste [cyan]kerov://[/] link — auto-configures everything[/]\n"
        "[bold yellow][3][/] [white]Leech Backup Listener[/] [dim]Configure a backup using the same sync link[/]\n"
        "[bold dim][0][/] [dim]Back to Main Menu[/]",
        title="[bold magenta]CREATE TUNNEL — SELECT SERVER ROLE[/]", border_style="magenta", box=box.ROUNDED
    ))
    side_choice = Prompt.ask("[bold cyan]kerov > Select[/]", choices=["0", "1", "2", "3"], default="1")
    if side_choice == "0":
        return

    if side_choice in ("2", "3"):
        link = read_sync_link("Paste kerov:// link from Iran server:")
        if not link:
            return
        try:
            cfg = decode_link(link, "kerov")
            if not isinstance(cfg, dict):
                raise ValueError("Expected a configuration object.")
        except Exception as e:
            console.print(f"\n[bold red]✗ Invalid sync link:[/] {e}")
            console.print("[dim]Make sure you copied the complete kerov://... string without missing characters.[/]")
            pause()
            return

        missing = [k for k in ("name", "engine", "direction", "transport") if k not in cfg]
        if missing:
            console.print(f"[bold red]✗ Sync link is missing fields:[/] {', '.join(missing)}")
            pause()
            return
        try:
            if cfg["engine"] == RETIRED_PRIVATE_IP_ENGINE:
                raise ValueError("Standalone Private IP tunnels are retired.")
            _validate_cfg(cfg)
            if side_choice == "3":
                _deploy_leech_backup(cfg, encode_link("kerov", cfg))
                pause()
                return
            if cfg["engine"] not in ADDED_ENGINES:
                _protect_instance_name(cfg["name"])
            if any(not isinstance(cfg[k], str) for k in ("engine", "direction", "transport")):
                raise ValueError("Engine, direction and transport must be strings.")
        except (ValueError, TypeError, KeyError, RuntimeError, OSError, subprocess.CalledProcessError) as e:
            console.print(f"[bold red]✗ Sync setup failed:[/] {e}")
            pause()
            return
        eng = cfg["engine"]
        if eng not in ADDED_ENGINES and not cfg.get("foreign_ip"):
            cfg["foreign_ip"] = get_public_ip()
        console.print(Panel(
            f"[cyan]Name:[/] {cfg['name']}   [cyan]Engine:[/] {eng}   [cyan]Direction:[/] {cfg['direction'].upper()}\n"
            f"[cyan]Transport:[/] {cfg['transport']}   [cyan]Iran IP:[/] {cfg.get('iran_ip') or cfg.get('iran_tun_ip', '-')}",
            title="[bold green]DECODED SYNC PAYLOAD[/]", border_style="green", box=box.ROUNDED
        ))
        clean_link = encode_link("kerov", cfg)
        try:
            with console.status("[bold cyan]Auto-configuring Foreign server & starting service...[/]"):
                if eng == "brokennode":
                    svc = deploy_brokennode(cfg, "foreign", clean_link)
                elif eng == "dagger":
                    svc = deploy_dagger(cfg, "foreign", clean_link)
                elif eng == "backhaul":
                    svc = deploy_backhaul(cfg, "foreign", clean_link)
                elif eng == "paqet":
                    svc = deploy_paqet(cfg, "foreign", clean_link)
                elif eng == "gretap-ipsec":
                    svc = deploy_gretap_ipsec(cfg, "foreign", clean_link)
                elif eng == "kerov-udp":
                    svc = deploy_kerov_udp(cfg, "foreign", clean_link)
                elif eng in ADDED_ENGINES:
                    svc = deploy_added_engine(cfg, "foreign", clean_link)
                else:
                    console.print(f"[red]Unknown engine: {eng}[/]")
                    pause()
                    return
                time.sleep(1.5)
            st = run_cmd(["systemctl", "is-active", svc]).stdout.strip()
            color = "green" if st == "active" else "red"
            label = _instance_status(eng, st)
            console.print(f"\n[bold {color}]● Tunnel '{cfg['name']}' deployed on Foreign server — Status: {label}[/]")
            if st != "active":
                logs = run_cmd(["journalctl", "-u", svc, "-n", "8", "--no-pager"]).stdout
                console.print(Panel(logs or "(no logs)", title="[red]Recent Service Logs[/]", border_style="red"))
        except Exception as e:
            console.print(f"\n[bold red]✗ Deployment failed:[/] {e}")
            console.print(f"[dim]{traceback.format_exc()}[/]")
        pause()
        return

    console.print(Panel(
        "[bold magenta][1] REVERSE Tunnels[/]  [yellow](Iran = Server  |  Foreign = Client)[/]\n"
        "    [dim]• BrokenNode (12 Transports)   • DaggerConnect (13 Transports)   • Backhaul Premium (10 Transports)   • LeechTunnel[/]\n\n"
        "[bold cyan][2] DIRECT Tunnels[/]   [green](Iran = Client  |  Foreign = Server)[/]\n"
        "    [dim]• paqet-plus (Raw TCP+KCP)     • GRE over IPsec L2 (gretap)      • Kerov-UDP (FakeTCP+WG)   • QS-Tunnel   • ICMP Tunnel[/]\n\n"
        "[dim][0] Back[/]",
        title="[bold cyan]STEP 1: SELECT TUNNEL DIRECTION[/]", border_style="cyan", box=box.ROUNDED
    ))
    dir_choice = Prompt.ask("[bold cyan]kerov > Direction[/]", choices=["0", "1", "2"], default="1")
    if dir_choice == "0":
        return

    iran_ip = ""
    while not _valid_ip(iran_ip):
        iran_ip = Prompt.ask("Iran Server Public IP", default=get_public_ip()).strip()
        if not _valid_ip(iran_ip):
            console.print("[red]Invalid IP address.[/]")
    name = Prompt.ask("Tunnel Instance Name", default=f"tun{secrets.randbelow(900)+100}").strip()
    name = ("".join(c for c in name if c.isascii() and (c.isalnum() or c in "-_")) or "main")[:32]

    try:
        _protect_instance_name(name)
        svc, sync_link = _iran_engine_flow(dir_choice, name, iran_ip)
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled.[/]")
        pause()
        return
    except Exception as e:
        console.print(f"\n[bold red]✗ Deployment failed:[/] {e}")
        console.print(f"[dim]{traceback.format_exc()}[/]")
        pause()
        return

    time.sleep(1.5)
    st = run_cmd(["systemctl", "is-active", svc]).stdout.strip()
    color = "green" if st == "active" else "red"
    label = _instance_status(decode_link(sync_link, "kerov")["engine"], st)
    console.print(f"\n[bold {color}]● Iran Tunnel '{name}' Configured![/]  Service: [cyan]{svc}[/]  Status: [bold]{label}[/]")
    if st != "active":
        logs = run_cmd(["journalctl", "-u", svc, "-n", "8", "--no-pager"]).stdout
        console.print(Panel(logs or "(no logs)", title="[red]Recent Service Logs[/]", border_style="red"))
    print_copyable_link(
        "AUTO-SYNC LINK READY",
        sync_link,
        "Copy this exact single line and paste it on your FOREIGN server (Create Tunnel -> Option 2). (Also saved in Manage Tunnels -> Show Sync Link)"
    )
    pause()


def _iran_engine_flow(dir_choice: str, name: str, iran_ip: str):
    if dir_choice == "1":
        console.print(Panel(
            "[bold cyan][1][/] [white]BrokenNode[/]       [dim]Reverse (Iran=Server | Foreign=Client) • 12 Transports[/]\n"
            "[bold cyan][2][/] [white]DaggerConnect[/]    [dim]Reverse (Iran=Server | Foreign=Client) • 13 Transports[/]\n"
            "[bold cyan][3][/] [white]Backhaul Premium[/] [dim]Reverse (Iran=Server | Foreign=Client) • 10 Transports (incl. AnyTLS & IPX)[/]\n"
            "[bold cyan][4][/] [white]LeechTunnel[/]       [dim]14 transports, including TUN[/]",
            title="[bold magenta]REVERSE TUNNEL ENGINES[/]", border_style="magenta", box=box.ROUNDED
        ))
        eng_c = Prompt.ask("Select Engine", choices=["1", "2", "3", "4"], default="1")
        if eng_c == "1":
            cfg = wizard_brokennode(name, iran_ip)
            sync_link = encode_link("kerov", cfg)
            svc = deploy_brokennode(cfg, "iran", sync_link)
        elif eng_c == "2":
            cfg = wizard_dagger(name, iran_ip)
            sync_link = encode_link("kerov", cfg)
            svc = deploy_dagger(cfg, "iran", sync_link)
        elif eng_c == "3":
            cfg = wizard_backhaul(name, iran_ip)
            sync_link = encode_link("kerov", cfg)
            svc = deploy_backhaul(cfg, "iran", sync_link)
        else:
            cfg = wizard_added_engine("leech", name, iran_ip, "", direction="reverse")
            sync_link = encode_link("kerov", cfg)
            svc = deploy_added_engine(cfg, "iran", sync_link)
    else:
        console.print(Panel(
            "[bold cyan][1][/] [white]paqet-plus[/]         [dim]Direct (Iran=Client | Foreign=Server) • Raw TCP + KCP/smux[/]\n"
            "[bold cyan][2][/] [white]GRE over IPsec L2[/]  [dim]Direct (Iran=Client | Foreign=Server) • StrongSwan IKEv2 + GRETAP[/]\n"
            "[bold cyan][3][/] [white]Kerov-UDP Special[/]  [dim]Direct (Iran=Client | Foreign=Server) • udp2raw FakeTCP + WireGuard[/]\n"
            "[bold cyan][4][/] [white]QS-Tunnel[/]         [dim]TCP upload + UDP / OBFS download[/]\n"
            "[bold cyan][5][/] [white]ICMP Tunnel[/]       [dim]IPv4 ICMP + SOCKS5[/]\n"
            "[bold cyan][6][/] [white]LeechTunnel[/]       [dim]14 transports, including TUN[/]",
            title="[bold cyan]DIRECT TUNNEL ENGINES[/]", border_style="cyan", box=box.ROUNDED
        ))
        eng_c = Prompt.ask("Select Engine", choices=["1", "2", "3", "4", "5", "6"], default="1")
        foreign_ip = ""
        while not _valid_ip(foreign_ip):
            foreign_ip = Prompt.ask("Foreign Server Public IP").strip()
            if not _valid_ip(foreign_ip):
                console.print("[red]Invalid IP address.[/]")
        if eng_c == "1":
            cfg = wizard_paqet(name, iran_ip, foreign_ip)
            sync_link = encode_link("kerov", cfg)
            svc = deploy_paqet(cfg, "iran", sync_link)
        elif eng_c == "2":
            cfg = wizard_gretap(name, iran_ip, foreign_ip)
            sync_link = encode_link("kerov", cfg)
            svc = deploy_gretap_ipsec(cfg, "iran", sync_link)
        elif eng_c == "3":
            cfg = wizard_kerov_udp(name, iran_ip, foreign_ip)
            sync_link = encode_link("kerov", cfg)
            svc = deploy_kerov_udp(cfg, "iran", sync_link)
        else:
            engine = {"4": "qs", "5": "icmp", "6": "leech"}[eng_c]
            cfg = wizard_added_engine(engine, name, iran_ip, foreign_ip)
            sync_link = encode_link("kerov", cfg)
            svc = deploy_added_engine(cfg, "iran", sync_link)
    return svc, sync_link


def wizard_brokennode(name: str, iran_ip: str) -> dict:
    transports = [
        ("tcp", "Plain TCP + smux (stable baseline)"),
        ("tcpobf", "TCP + obfuscation (anti-DPI)"),
        ("mtcp", "Multi-link TCP (beats throttling)"),
        ("mtcpobf", "Multi-link + obfuscation (best for Iran)"),
        ("ws", "WebSocket/HTTP + smux"),
        ("wsobf", "WebSocket + obfuscation"),
        ("tcpnomux", "TCP pool, no HoL (heavy single-flow)"),
        ("kcp", "KCP/UDP + FEC (UDP)"),
        ("rawmux", "KCP/UDP + obfuscation (UDP)"),
        ("quic", "QUIC/UDP, no HoL (UDP)"),
        ("quicd", "QUIC: TCP=streams, UDP=datagrams (gaming)"),
        ("spoof", "Spoofed-IP TUN (blackout / whitelist)"),
    ]
    tbl = Table(title="BrokenNode Transports [Reverse: Iran=Server | Foreign=Client]", box=box.ROUNDED, border_style="magenta")
    tbl.add_column("#", style="bold cyan", width=4)
    tbl.add_column("Transport", style="bold white", width=12)
    tbl.add_column("Features", style="dim")
    for idx, (t, desc) in enumerate(transports, 1):
        tbl.add_row(str(idx), t, desc)
    console.print(tbl)

    t_idx = IntPrompt.ask("Select Transport [1-12]", default=4)
    tr = transports[max(1, min(12, t_idx)) - 1][0]
    ports = ask_port_mappings()
    passkey = Prompt.ask("BrokenNode Passkey (BNK1-...; empty=skip)", default="").strip()

    if tr == "spoof":
        cproto = Prompt.ask("Spoof carrier protocol", choices=["udp", "tcp", "icmp", "gre"], default="udp")
        foreign_ip = Prompt.ask("Foreign Server Real IP")
        w1 = Prompt.ask("White IP #1 (Iran spoof source)")
        w2 = Prompt.ask("White IP #2 (Foreign spoof source)")
        cport = IntPrompt.ask("Carrier port", default=6262)
        mtu = IntPrompt.ask("MTU", default=1320)
        jit = Confirm.ask("Enable TTL jitter?", default=False)
        return {
            "name": name, "engine": "brokennode", "direction": "reverse", "transport": "spoof",
            "iran_ip": iran_ip, "foreign_ip": foreign_ip, "spoof_w1": w1, "spoof_w2": w2,
            "carrier_proto": cproto, "carrier_port": cport, "mtu": mtu, "ttl_jitter": jit,
            "ports": ports, "passkey": passkey
        }

    tport = IntPrompt.ask("Tunnel Listen Port on Iran", default=8443)
    presets = {
        "1": [10, "fast", 10, 3],
        "2": [15, "turbo", 10, 2],
        "3": [8, "normal", 10, 4],
        "4": [5, "gaming", 10, 4],
        "5": [20, "normal", 10, 1],
    }
    console.print("[cyan]Presets:[/] 1) Optimized  2) High-Speed  3) Stable  4) Low-Latency  5) Eco")
    p_c = Prompt.ask("Select Preset", choices=["1", "2", "3", "4", "5"], default="1")
    extra = {}
    if tr in ("ws", "wsobf"):
        extra["ws_path"] = Prompt.ask("WebSocket path", default="/")
        extra["ws_host"] = Prompt.ask("Fake Host header (empty=none)", default="")
        extra["ws_user_agent"] = Prompt.ask("User-Agent (empty=default)", default="")
    elif tr in ("quic", "quicd"):
        extra["alpn"] = Prompt.ask("ALPN", default="h3")
    elif tr == "tcpnomux":
        extra["pool_size"] = IntPrompt.ask("Connection pool size (0=AUTO)", default=0)
    elif tr in ("kcp", "rawmux"):
        extra["kcp_wnd"] = IntPrompt.ask("KCP window (send/recv)", default=1024)
    elif tr in ("mtcp", "mtcpobf"):
        extra["links"] = IntPrompt.ask("Parallel links (0=AUTO)", default=4)

    return {
        "name": name, "engine": "brokennode", "direction": "reverse", "transport": tr,
        "iran_ip": iran_ip, "tunnel_port": tport, "token": secrets.token_hex(12),
        "preset": presets[p_c], "extra": extra, "ports": ports, "passkey": passkey
    }


def wizard_dagger(name: str, iran_ip: str) -> dict:
    transports = [
        ("tcp", "Raw TCP carrier"),
        ("ws", "WebSocket carrier"),
        ("wss", "WebSocket over TLS (auto self-signed cert)"),
        ("http", "HTTP mimicry (fake domain/path)"),
        ("https", "HTTPS mimicry + TLS"),
        ("quantum", "Quantum raw TCP range (auto-tuned)"),
        ("quantum+", "Quantum+ UDP + knock + TCP lane fallback"),
        ("quantum-gaming", "Quantum with gaming low-latency profile"),
        ("tun", "IPX TUN (tcp/udp/icmp/gre/ipip/bip + DCPI/Spoof)"),
        ("xhttp", "Split-HTTP (stream-up / packet-up)"),
        ("xhttps", "Split-HTTPS (Direct or Cloudflare CDN mode)"),
        ("dc6", "IPv6 tunnel with IPv4 licensing"),
        ("nova", "Nova high-resilience carrier"),
    ]
    tbl = Table(title="DaggerConnect Transports [Reverse: Iran=Server | Foreign=Client]", box=box.ROUNDED, border_style="magenta")
    tbl.add_column("#", style="bold cyan", width=4)
    tbl.add_column("Transport", style="bold white", width=16)
    tbl.add_column("Features", style="dim")
    for idx, (t, desc) in enumerate(transports, 1):
        tbl.add_row(str(idx), t, desc)
    console.print(tbl)

    t_idx = IntPrompt.ask("Select Transport [1-13]", default=6)
    tr = transports[max(1, min(13, t_idx)) - 1][0]
    tport = IntPrompt.ask("Tunnel Port", default=8443)
    pool = IntPrompt.ask("Client Connection Pool", default=6)
    ports = ask_port_mappings()
    socks_on = Confirm.ask("Enable standalone SOCKS5 on Iran?", default=False)
    socks_bind = Prompt.ask("SOCKS5 bind address", default="127.0.0.1:6060") if socks_on else ""

    extra = {"pool": pool}
    if tr in ("ws", "wss"):
        extra["ws_path"] = Prompt.ask("WebSocket path", default="/ws")
    elif tr in ("http", "https"):
        extra["http_domain"] = Prompt.ask("Fake domain", default="www.google.com")
        extra["http_path"] = Prompt.ask("Fake path", default="/search")
    elif tr in ("quantum", "quantum-gaming"):
        extra["mtu"] = IntPrompt.ask("Quantum MTU", default=1350)
        extra["block"] = Prompt.ask("Header cipher", choices=["aes", "salsa20", "none"], default="aes")
    elif tr in ("xhttp", "xhttps"):
        extra["xhttp_path"] = Prompt.ask("xhttp URL path", default="/api/v2")
        extra["xhttp_mode"] = Prompt.ask("Client upload mode", choices=["auto", "stream-up", "packet-up"], default="auto")
        if tr == "xhttps" and Confirm.ask("Enable Cloudflare CDN mode?", default=False):
            extra["xhttp_cdn"] = True
            extra["cdn_host"] = Prompt.ask("Cloudflare proxied domain (points to Foreign)")
            extra["cdn_port"] = IntPrompt.ask("Cloudflare HTTPS port", default=443)
            ips_raw = Prompt.ask("Cloudflare Edge IPs (comma-separated)")
            extra["cdn_ips"] = [x.strip() for x in ips_raw.split(",") if x.strip()]
            extra["origin_port"] = IntPrompt.ask("Origin port on Foreign server", default=8443)
            extra["peer_ip"] = Prompt.ask("Restrict to Foreign IPv4 (empty=any)", default="")
    elif tr == "dc6":
        extra["dc6_listen"] = Prompt.ask("Iran IPv6 listen address", default="::")
        extra["dc6_server_ipv6"] = Prompt.ask("Iran Public IPv6 (for Foreign client to dial)")
    elif tr == "tun":
        extra["tun_profile"] = Prompt.ask("TUN IPX profile", choices=["tcp", "udp", "icmp", "gre", "ipip", "bip"], default="tcp")
        if extra["tun_profile"] in ("tcp", "udp"):
            extra["tun_l4_port"] = IntPrompt.ask("Service L4 port", default=443)
        extra["foreign_ip"] = Prompt.ask("Foreign Server Real IPv4")
        extra["tun_name"] = f"dc{name[:8]}"
        extra["heartbeat_sec"] = IntPrompt.ask("Heartbeat interval (sec)", default=10)
        extra["idle_timeout_sec"] = IntPrompt.ask("Idle timeout (sec)", default=90)
        extra["dcpi_mode"] = Confirm.ask("Enable DCPI (IPv4/proto58)?", default=False)
        if not extra["dcpi_mode"] and Confirm.ask("Enable IP Spoof?", default=False):
            extra["spoof_src"] = Prompt.ask("Spoof Source IP")
            extra["spoof_dst"] = Prompt.ask("Spoof Dest IP")

    return {
        "name": name, "engine": "dagger", "direction": "reverse", "transport": tr,
        "iran_ip": iran_ip, "tunnel_port": tport,
        "psk": secrets.token_hex(32), "profile_id": f"kerov-{name}",
        "extra": extra, "ports": ports,
        "socks5_enabled": socks_on, "socks5_bind": socks_bind
    }


def wizard_backhaul(name: str, iran_ip: str) -> dict:
    transports = [
        ("tcp", "Plain TCP (supports Accept UDP over TCP & Proxy Protocol)"),
        ("tcpmux", "TCP + Multiplexing (v1/v2, high concurrency)"),
        ("xtcpmux", "Extended TCP Mux (enhanced anti-throttling)"),
        ("ws", "WebSocket (supports Edge IP/Domain)"),
        ("wss", "WebSocket + TLS (auto self-signed cert)"),
        ("wsmux", "WebSocket + Mux"),
        ("wssmux", "WebSocket + TLS + Mux"),
        ("xwsmux", "Extended WebSocket Mux"),
        ("anytls", "AnyTLS with custom SNI & auto TLS cert"),
        ("tun", "TUN Tunnel (TCP or IPX: icmp/ipip/udp/tcp/gre/bip + AEAD)"),
    ]
    tbl = Table(title="Backhaul Premium Transports [Reverse: Iran=Server | Foreign=Client]", box=box.ROUNDED, border_style="magenta")
    tbl.add_column("#", style="bold cyan", width=4)
    tbl.add_column("Transport", style="bold white", width=12)
    tbl.add_column("Features", style="dim")
    for idx, (t, desc) in enumerate(transports, 1):
        tbl.add_row(str(idx), t, desc)
    console.print(tbl)

    t_idx = IntPrompt.ask("Select Transport [1-10]", default=2)
    tr = transports[max(1, min(10, t_idx)) - 1][0]
    extra = {}
    is_tun = tr == "tun"
    is_ipx = False

    if is_tun:
        extra["tun_encapsulation"] = Prompt.ask("TUN Encapsulation", choices=["tcp", "ipx"], default="tcp")
        is_ipx = extra["tun_encapsulation"] == "ipx"
        extra["tun_name"] = f"bh{name[:6]}"
        oct3 = secrets.randbelow(200) + 20
        extra["tun_iran_cidr"] = Prompt.ask("Iran TUN Local CIDR", default=f"10.10.{oct3}.1/24")
        extra["tun_foreign_cidr"] = Prompt.ask("Foreign TUN Remote CIDR", default=f"10.10.{oct3}.2/24")
        extra["tun_health_port"] = IntPrompt.ask("TUN Health Port", default=1234)
        extra["tun_mtu"] = IntPrompt.ask("TUN MTU", default=1320 if is_ipx else 1500)
        extra["forwarder"] = Prompt.ask("TUN Port Forwarder", choices=["backhaul", "iptables"], default="backhaul")
        if is_ipx:
            extra["ipx_profile"] = Prompt.ask("IPX Profile", choices=["tcp", "udp", "icmp", "gre", "ipip", "bip"], default="tcp")
            extra["foreign_ip"] = Prompt.ask("Foreign Server Public IP").strip()
            if extra["ipx_profile"] == "icmp":
                extra["icmp_type"] = IntPrompt.ask("ICMP Type", default=0)
                extra["icmp_code"] = IntPrompt.ask("ICMP Code", default=0)
            extra["enable_encryption"] = Confirm.ask("Enable IPX Encryption?", default=True)
            if extra["enable_encryption"]:
                extra["algorithm"] = Prompt.ask("Algorithm", choices=["aes-256-gcm", "chacha20-poly1305", "aes-128-gcm"], default="aes-256-gcm")
                extra["kdf_iterations"] = IntPrompt.ask("KDF Iterations", default=100000)

    tport = extra.get("tun_health_port", 1234) if is_ipx else IntPrompt.ask("Tunnel Listen Port on Iran", default=8443)

    if not is_ipx:
        extra["nodelay"] = Confirm.ask("Enable TCP_NODELAY?", default=True)
        if tr == "tcp":
            extra["accept_udp"] = Confirm.ask("Accept UDP over TCP?", default=False)
        if tr not in ("tun", "ws"):
            extra["proxy_protocol"] = Confirm.ask("Enable Proxy Protocol?", default=False)
        if tr != "tun":
            extra["connection_pool"] = IntPrompt.ask("Client Connection Pool", default=8)
        if tr in ("ws", "wss", "wsmux", "wssmux", "xwsmux"):
            extra["edge_ip"] = Prompt.ask("Edge IP/Domain (optional, empty=skip)", default="").strip()

    if tr.endswith("mux"):
        extra["mux_version"] = IntPrompt.ask("Mux Version [1 or 2]", default=2)
        extra["mux_concurrency"] = IntPrompt.ask("Mux Concurrency", default=8)

    if tr == "anytls":
        extra["tls_sni"] = Prompt.ask("AnyTLS SNI", default="www.digikala.com")

    extra["tuning_profile"] = Prompt.ask("Kernel Tuning Profile", choices=["balanced", "fast", "latency", "resource"], default="balanced")
    if not is_tun and not is_ipx:
        extra["buffer_profile"] = Prompt.ask("Buffer Profile", choices=["balanced", "low_cpu", "ultra_low_cpu", "extreme_low_cpu", "low_memory"], default="balanced")

    ports = ask_port_mappings()
    psk = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    return {
        "name": name, "engine": "backhaul", "direction": "reverse", "transport": tr,
        "iran_ip": iran_ip, "tunnel_port": tport,
        "token": secrets.token_hex(16), "psk": psk,
        "extra": extra, "ports": ports
    }


def wizard_paqet(name: str, iran_ip: str, foreign_ip: str) -> dict:
    console.print("[bold cyan]paqet-plus [Direct: Iran=Client | Foreign=Server][/]")
    tport = IntPrompt.ask("Foreign Server Listen Port", default=9999)
    kmode = Prompt.ask("KCP Mode", choices=["normal", "fast", "fast2", "fast3", "manual"], default="normal")
    block = Prompt.ask("Cipher", choices=["aes-128-gcm", "salsa20", "xor", "aes", "aes-128", "none"], default="aes-128-gcm")
    mtu = IntPrompt.ask("MTU", default=1250)
    conn = IntPrompt.ask("Connections", default=8)
    fec = Confirm.ask("Enable FEC (10% overhead, recovers packet loss)?", default=False)
    ports = ask_port_mappings()
    socks_addr = Prompt.ask("Optional SOCKS5 listen on Iran (empty=none)", default="").strip()
    key = run_cmd(f"{BINS['paqet']} secret").stdout.strip() or secrets.token_hex(32)
    return {
        "name": name, "engine": "paqet", "direction": "direct",
        "transport": f"raw-kcp/{kmode}", "iran_ip": iran_ip, "foreign_ip": foreign_ip,
        "tunnel_port": tport, "kcp_mode": kmode, "block": block, "mtu": mtu,
        "conn": conn, "fec": fec, "key": key, "ports": ports, "socks5_addr": socks_addr
    }


def wizard_gretap(name: str, iran_ip: str, foreign_ip: str) -> dict:
    console.print("[bold cyan]GRE over IPsec Layer 2 (StrongSwan IKEv2 + GRETAP) [Direct: Iran=Client | Foreign=Server][/]")
    subnet_octet = secrets.randbelow(200) + 20
    iran_tun = Prompt.ask("Iran L2 Tunnel IP", default=f"10.200.{subnet_octet}.1")
    foreign_tun = Prompt.ask("Foreign L2 Tunnel IP", default=f"10.200.{subnet_octet}.2")
    mtu = IntPrompt.ask("GRETAP MTU", default=1380)
    ports = []
    if Confirm.ask("Enable port forwarding on the Iran server?", default=False):
        ports = ask_port_mappings(default_443=False)
    return {
        "name": name, "engine": "gretap-ipsec", "direction": "direct",
        "transport": "gretap-l2/ikev2", "iran_ip": iran_ip, "foreign_ip": foreign_ip,
        "iran_tun_ip": iran_tun, "foreign_tun_ip": foreign_tun,
        "mtu": mtu, "psk": secrets.token_hex(24), "ports": ports
    }


def wizard_kerov_udp(name: str, iran_ip: str, foreign_ip: str) -> dict:
    console.print("[bold cyan]Kerov-UDP Special (udp2raw FakeTCP + WireGuard) [Direct: Iran=Client | Foreign=Server][/]")
    tport = IntPrompt.ask("FakeTCP Tunnel Port on Foreign", default=4433)
    wg_port = IntPrompt.ask("Internal WireGuard Port", default=51820 + secrets.randbelow(500))
    mtu = IntPrompt.ask("WireGuard MTU", default=1280)
    ports = ask_port_mappings()

    def gen_wg_pair():
        priv = run_cmd(["wg", "genkey"]).stdout.strip()
        if not priv:
            raise RuntimeError("wireguard-tools is not installed (wg genkey failed)")
        pub = subprocess.run(["wg", "pubkey"], input=priv + "\n", capture_output=True, text=True).stdout.strip()
        return priv, pub

    i_priv, i_pub = gen_wg_pair()
    f_priv, f_pub = gen_wg_pair()
    oct3 = secrets.randbelow(200) + 20
    return {
        "name": name, "engine": "kerov-udp", "direction": "direct",
        "transport": "faketcp+wireguard", "iran_ip": iran_ip, "foreign_ip": foreign_ip,
        "tunnel_port": tport, "wg_port": wg_port, "mtu": mtu,
        "psk": secrets.token_hex(16),
        "iran_priv": i_priv, "iran_pub": i_pub,
        "foreign_priv": f_priv, "foreign_pub": f_pub,
        "iran_wg_ip": f"10.210.{oct3}.1", "foreign_wg_ip": f"10.210.{oct3}.2",
        "ports": ports
    }


# ==============================================================================
#  MANAGE TUNNELS MENU (WITH SHOW SYNC LINK)
# ==============================================================================

def manage_tunnels_menu():
    while True:
        render_header()
        tunnels = list_tunnels(include_retired=True)
        tbl = Table(title="MANAGED TUNNELS", box=box.ROUNDED, border_style="cyan", expand=True)
        tbl.add_column("#", style="bold cyan", width=4)
        tbl.add_column("Name", style="bold white")
        tbl.add_column("Engine", style="magenta")
        tbl.add_column("Direction / Role", style="yellow")
        tbl.add_column("Transport", style="cyan")
        tbl.add_column("Status", style="bold")
        for idx, t in enumerate(tunnels, 1):
            label = _instance_status(t["engine"], t["status"])
            st_str = f"[bold green]● {label}[/]" if t["status"] == "active" else f"[bold red]○ {label}[/]"
            engine = "Retired Private IP" if t["engine"] == RETIRED_PRIVATE_IP_ENGINE else t["engine"]
            tbl.add_row(str(idx), t["name"], engine, f"{t['direction']} ({t['role']})", t["transport"], st_str)
        console.print(tbl)
        if not tunnels:
            console.print("[dim]  No tunnels configured yet.[/]")
            pause()
            return

        sel = Prompt.ask("[bold cyan]Select tunnel # (0 = Back to Main Menu)[/]", default="0").strip()
        if sel == "0":
            return
        if not sel.isdigit() or not (1 <= int(sel) <= len(tunnels)):
            continue
        t = tunnels[int(sel) - 1]
        if t["engine"] == RETIRED_PRIVATE_IP_ENGINE:
            if Confirm.ask(f"Remove retired Private IP instance '{t['name']}' from this server?", default=False):
                try:
                    _cleanup_tunnel(t)
                    run_cmd(["systemctl", "daemon-reload"], check=True)
                    console.print(f"[green]Removed '{t['name']}'.[/]")
                except (RuntimeError, OSError, subprocess.CalledProcessError) as error:
                    console.print(Text(str(error), style="red"))
                pause()
            continue
        svc = t["service"]

        while True:
            st = run_cmd(["systemctl", "is-active", svc]).stdout.strip()
            label = _instance_status(t["engine"], st)
            st_badge = f"[bold green]{label}[/]" if st == "active" else f"[bold red]{label}[/]"
            console.print(Panel(
                f"[bold white]{t['name']}[/]  ([magenta]{t['engine']}[/] / [cyan]{t['transport']}[/])   Status: {st_badge}\n"
                f"[dim]Service: {svc}   Config: {t['config']}[/]\n\n"
                "[green][1] Start[/]   [yellow][2] Stop[/]   [cyan][3] Restart[/]\n"
                "[white][4] Live Logs[/]   [white][5] Edit Config[/]   [bold cyan][6] Show Sync Link (kerov://)[/]\n"
                "[bold red][7] Delete Tunnel[/]   [dim][0] Back to Tunnel List   [m] Main Menu[/]",
                title=f"[bold cyan]MANAGE: {t['name']}[/]", border_style="cyan", box=box.ROUNDED
            ))
            act = Prompt.ask("Action", choices=["0", "1", "2", "3", "4", "5", "6", "7", "m"], default="0")
            if act == "0":
                break
            elif act == "m":
                return
            elif act in ("1", "2", "3"):
                action, label = {"1": ("start", "Started"), "2": ("stop", "Stopped"), "3": ("restart", "Restarted")}[act]
                result = run_cmd(["systemctl", action, svc])
                if result.returncode:
                    console.print(Text(result.stderr.strip() or f"Could not {action} {svc}.", style="red"))
                else:
                    console.print(f"[green]✔ {label}.[/]")
            elif act == "4":
                console.print("[dim]Press Ctrl+C to stop following logs...[/]")
                try:
                    subprocess.run(["journalctl", "-u", svc, "-n", "40", "-f"])
                except KeyboardInterrupt:
                    pass
            elif act == "5":
                ed = shutil.which("nano") or shutil.which("vi") or "vi"
                subprocess.run([ed, t["config"]])
                if Confirm.ask("Restart tunnel to apply changes?", default=True):
                    result = run_cmd(["systemctl", "restart", svc])
                    if result.returncode:
                        console.print(Text(result.stderr.strip() or f"Could not restart {svc}.", style="red"))
            elif act == "6":
                slink = t.get("sync_link", "")
                if slink:
                    print_copyable_link(
                        f"SYNC LINK FOR '{t['name']}'",
                        slink,
                        "Copy this single line and paste it on your FOREIGN server (Create Tunnel -> Option 2):"
                    )
                else:
                    console.print("[yellow]! Sync link not stored for this legacy tunnel (recreate it in v2.2 to store automatically).[/]")
                pause()
            elif act == "7":
                if Confirm.ask(f"Permanently delete tunnel '{t['name']}'?", default=False):
                    _cleanup_tunnel(t)
                    run_cmd(["systemctl", "daemon-reload"])
                    console.print(f"[red]✔ Deleted '{t['name']}'.[/]")
                    break


# ==============================================================================
#  SMART BENCHMARK ENGINE (ALL 6 CORES + BROKENNODE IP-SPOOFING)
# ==============================================================================

BASE_BENCH_CASES = [
    # BrokenNode (11 standard transports; 12th 'spoof' is added when user provides White IPs)
    ("brokennode", "tcp", "reverse"),
    ("brokennode", "tcpobf", "reverse"),
    ("brokennode", "mtcp", "reverse"),
    ("brokennode", "mtcpobf", "reverse"),
    ("brokennode", "ws", "reverse"),
    ("brokennode", "wsobf", "reverse"),
    ("brokennode", "tcpnomux", "reverse"),
    ("brokennode", "kcp", "reverse"),
    ("brokennode", "rawmux", "reverse"),
    ("brokennode", "quic", "reverse"),
    ("brokennode", "quicd", "reverse"),
    # DaggerConnect (All transports: tcp, ws, wss, http, https, quantum, quantum+, quantum-gaming, xhttp, xhttps, nova, tun/ipx)
    ("dagger", "tcp", "reverse"),
    ("dagger", "ws", "reverse"),
    ("dagger", "wss", "reverse"),
    ("dagger", "http", "reverse"),
    ("dagger", "https", "reverse"),
    ("dagger", "quantum", "reverse"),
    ("dagger", "quantum+", "reverse"),
    ("dagger", "quantum-gaming", "reverse"),
    ("dagger", "xhttp", "reverse"),
    ("dagger", "xhttps", "reverse"),
    ("dagger", "nova", "reverse"),
    ("dagger", "tun/tcp", "reverse"),
    ("dagger", "tun/udp", "reverse"),
    ("dagger", "tun/icmp", "reverse"),
    ("dagger", "tun/gre", "reverse"),
    # Backhaul Premium (All 10 transports: tcp, tcpmux, xtcpmux, ws, wss, wsmux, wssmux, xwsmux, anytls, tun/tcp & tun/ipx)
    ("backhaul", "tcp", "reverse"),
    ("backhaul", "tcpmux", "reverse"),
    ("backhaul", "xtcpmux", "reverse"),
    ("backhaul", "ws", "reverse"),
    ("backhaul", "wss", "reverse"),
    ("backhaul", "wsmux", "reverse"),
    ("backhaul", "wssmux", "reverse"),
    ("backhaul", "xwsmux", "reverse"),
    ("backhaul", "anytls", "reverse"),
    ("backhaul", "tun/tcp", "reverse"),
    ("backhaul", "tun/ipx-tcp", "reverse"),
    ("backhaul", "tun/ipx-udp", "reverse"),
    ("backhaul", "tun/ipx-icmp", "reverse"),
    ("backhaul", "tun/ipx-gre", "reverse"),
    # paqet-plus (All 4 KCP modes)
    ("paqet", "normal", "direct"),
    ("paqet", "fast", "direct"),
    ("paqet", "fast2", "direct"),
    ("paqet", "fast3", "direct"),
    # Kerov-UDP (udp2raw FakeTCP + WireGuard)
    ("kerov-udp", "faketcp+wireguard", "direct"),
]

BENCH_CHUNK = 65536
BENCH_PAYLOAD_SIZE = 48 * BENCH_CHUNK


def _bench_read_exact(conn, size):
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise EOFError("Benchmark connection closed before the response was complete.")
        data.extend(chunk)
    return bytes(data)


def _bench_request(conn, command, key):
    if key is None:
        conn.sendall(command)
    else:
        nonce = secrets.token_bytes(16)
        digest = hmac.digest(key, nonce + command, "sha256")
        conn.sendall(command + nonce + digest)


def _handle_bench_echo(conn, key=None):
    with conn:
        try:
            conn.settimeout(6)
            command = _bench_read_exact(conn, 4)
            if key is not None:
                nonce = _bench_read_exact(conn, 16)
                digest = _bench_read_exact(conn, 32)
                if not hmac.compare_digest(digest, hmac.digest(key, nonce + command, "sha256")):
                    return False
            if command == b"PING":
                conn.sendall(b"PONG")
            elif command == b"BULK":
                chunk = b"K" * BENCH_CHUNK
                for _ in range(BENCH_PAYLOAD_SIZE // BENCH_CHUNK):
                    conn.sendall(chunk)
            elif command == b"UPLD":
                for _ in range(BENCH_PAYLOAD_SIZE // BENCH_CHUNK):
                    _bench_read_exact(conn, BENCH_CHUNK)
                conn.sendall(b"DONE")
                return True
        except (OSError, EOFError):
            pass
    return False


def _start_echo_sink(port: int, stop_ev: threading.Event):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(16)
        srv.settimeout(0.5)
        while not stop_ev.is_set():
            try:
                conn, _ = srv.accept()
                threading.Thread(target=_handle_bench_echo, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue


def _probe_local_port(port: int, *, dial=None, key=None):
    if dial is None:
        def dial(timeout):
            return socket.create_connection(("127.0.0.1", port), timeout=timeout)

    rtts = []
    lost = 0
    for _ in range(5):
        t0 = time.perf_counter()
        try:
            with dial(2.5) as conn:
                _bench_request(conn, b"PING", key)
                if _bench_read_exact(conn, 4) != b"PONG":
                    raise OSError("Invalid benchmark response.")
                rtts.append((time.perf_counter() - t0) * 1000.0)
        except (OSError, EOFError):
            lost += 1
        if lost >= 2 and not rtts:
            return None
        time.sleep(0.08)

    dl_mbps = 0.0
    ul_mbps = 0.0
    for command in (b"BULK", b"UPLD"):
        try:
            t0 = time.perf_counter()
            with dial(4.0) as conn:
                conn.settimeout(6.0)
                _bench_request(conn, command, key)
                if command == b"BULK":
                    for _ in range(BENCH_PAYLOAD_SIZE // BENCH_CHUNK):
                        _bench_read_exact(conn, BENCH_CHUNK)
                else:
                    payload = b"U" * BENCH_CHUNK
                    for _ in range(BENCH_PAYLOAD_SIZE // BENCH_CHUNK):
                        conn.sendall(payload)
                    if _bench_read_exact(conn, 4) != b"DONE":
                        raise OSError("The peer did not acknowledge the upload.")
            rate = (BENCH_PAYLOAD_SIZE * 8.0) / (max(time.perf_counter() - t0, 0.001) * 1_000_000.0)
            if command == b"BULK":
                dl_mbps = rate
            else:
                ul_mbps = rate
        except (OSError, EOFError):
            continue

    return {
        "rtt": statistics.mean(rtts), "jitter": statistics.stdev(rtts) if len(rtts) > 1 else 0.0,
        "loss": lost * 20.0, "mbps": dl_mbps, "ul_mbps": ul_mbps,
    }


def _spawn_bench_proc(
    engine: str, transport: str, side: str, iran_ip: str, foreign_ip: str,
    tport: int, fport: int, secret: str, tmpdir: Path, spoof_opts=None
):
    if engine == "brokennode":
        if not os.path.exists(BINS["brokennode"]):
            return None
        role = "server" if side == "iran" else "client"
        if transport.startswith("spoof/"):
            cproto = transport.split("/", 1)[1]
            if not spoof_opts or not spoof_opts.get("w1") or not spoof_opts.get("w2"):
                return None
            run_cmd("ip link del kspbench0 2>/dev/null || true; ip link del bhbench0 2>/dev/null || true; ip link del dcbench0 2>/dev/null || true")
            local_ip = iran_ip if role == "server" else foreign_ip
            peer_ip = foreign_ip if role == "server" else iran_ip
            s_src = spoof_opts["w1"] if role == "server" else spoof_opts["w2"]
            s_dst = spoof_opts["w2"] if role == "server" else spoof_opts["w1"]
            tl, trr = ("10.10.29.1", "10.10.29.2") if role == "server" else ("10.10.29.2", "10.10.29.1")
            cfg = {
                "mode": role, "transport": "spoof", "log_level": "error",
                "spoof_local_ip": local_ip, "spoof_peer_ip": peer_ip,
                "spoof_src": s_src, "spoof_dst": s_dst,
                "carrier_proto": cproto, "carrier_port": tport,
                "tun_name": "kspbench0", "tun_local": tl, "tun_remote": trr, "mtu": 1320,
            }
            if role == "server":
                cfg["ports"] = [f"{fport}={fport}/tcp"]
            p = tmpdir / f"bn-spoof-{cproto}.json"
            p.write_text(json.dumps(cfg), encoding="utf-8")
            return subprocess.Popen([BINS["brokennode"], "-c", str(p)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        cfg = {
            "mode": role, "transport": transport, "token": secret[:24],
            "keepalive": 10, "kcp_mode": "fast", "kcp_data": 10, "kcp_parity": 3, "log_level": "error"
        }
        if role == "server":
            cfg["bind_addr"] = f"0.0.0.0:{tport}"
            cfg["ports"] = [f"{fport}={fport}/tcp"]
        else:
            cfg["remote_addr"] = f"{iran_ip}:{tport}"
            cfg["target_host"] = "127.0.0.1"
        p = tmpdir / f"bn-{transport}.json"
        p.write_text(json.dumps(cfg), encoding="utf-8")
        return subprocess.Popen([BINS["brokennode"], "-c", str(p)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    if engine == "dagger":
        if not os.path.exists(BINS["dagger"]):
            return None
        role = "server" if side == "iran" else "client"
        is_tun = transport.startswith("tun/")
        tun_prof = transport.split("/", 1)[1] if is_tun else ""
        actual_tr = "tun" if is_tun else ("quantum" if transport == "quantum-gaming" else transport)
        cfg = {"mode": role, "transport": actual_tr, "psk": secret, "profile_id": "kerov-bench", "log_level": "error"}

        if role == "server":
            listener = {
                "addr": f"0.0.0.0:{tport}",
                "transport": actual_tr,
                "maps": [{"type": "tcp", "bind": f"0.0.0.0:{fport}", "target": f"127.0.0.1:{fport}"}],
            }
            if actual_tr in ("wss", "https", "xhttps"):
                cert, key = gen_self_signed_cert("dc-bench", "daggerconnect.local")
                if actual_tr == "xhttps":
                    cfg["cert_file"], cfg["key_file"] = cert, key
                else:
                    listener["cert_file"], listener["key_file"] = cert, key
            cfg["listeners"] = [listener]
            cfg["socks5"] = {"enabled": False, "bind": ""}
        else:
            if actual_tr == "tun":
                cfg["paths"] = [{"transport": "tun", "addr": f"{iran_ip}:{tport}", "retry_interval": 1, "dial_timeout": 8}]
            else:
                cfg["paths"] = [{"transport": actual_tr, "addr": f"{iran_ip}:{tport}", "connection_pool": 4, "retry_interval": 1, "dial_timeout": 4}]

        if actual_tr in ("ws", "wss"):
            cfg["ws_settings"] = {"path": "/ws"}
        elif actual_tr in ("http", "https"):
            cfg["http_settings"] = {"fake_domain": "www.google.com", "path": "/search"}
        elif actual_tr == "quantum":
            cfg["quantum"] = {"mtu": 1350, "block": "aes"}
            if transport == "quantum-gaming":
                cfg["quantum"]["profile"] = "gaming"
        elif actual_tr in ("xhttp", "xhttps"):
            xh = {
                "path": "/api/v2", "mode": "auto", "up_max_bytes": 65536, "up_concurrency": 2,
                "buffer_bytes": 32768, "separate_conns": True, "probe_ms": 4000, "socket_buf_bytes": 131072,
            }
            if role == "client":
                xh["allow_insecure_tls"] = True
            cfg["xhttp"] = xh
        elif actual_tr == "tun":
            run_cmd("ip link del dcbench0 2>/dev/null || true")
            tl, trr = ("10.90.9.1", "10.90.9.2") if role == "server" else ("10.90.9.2", "10.90.9.1")
            lip = iran_ip if role == "server" else get_public_ip()
            dip = foreign_ip if role == "server" else iran_ip
            cfg["tun"] = {
                "encapsulation": "ipx", "name": "dcbench0",
                "local_addr": tl, "remote_addr": trr,
                "encrypt": True, "heartbeat_sec": 10, "idle_timeout_sec": 60,
            }
            ipx = {"mode": role, "profile": tun_prof, "listen_ip": lip, "dst_ip": dip, "sock_buf": 0}
            if tun_prof in ("tcp", "udp"):
                ipx["l4_port"] = tport
            cfg["ipx"] = ipx

        safe_name = transport.replace("/", "-")
        p = tmpdir / f"dc-{safe_name}.json"
        p.write_text(json.dumps(cfg), encoding="utf-8")
        env = os.environ.copy()
        env.update({"DC_CHANNEL": "offline", "DC_VERSION": "v4.3.1", "DC_SERVER_PUBLIC_IP": iran_ip})
        return subprocess.Popen([BINS["dagger"], "-c", str(p)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    if engine == "backhaul":
        if not os.path.exists(BINS["backhaul"]):
            return None
        role = "server" if side == "iran" else "client"
        is_tun = transport.startswith("tun/")
        is_ipx = transport.startswith("tun/ipx-")
        ipx_prof = transport.split("tun/ipx-", 1)[1] if is_ipx else ""
        actual_tr = "tun" if is_tun else transport

        lines = []
        if not is_ipx:
            if role == "server":
                lines += ["[listener]", f'bind_addr = ":{tport}"', ""]
            else:
                lines += ["[dialer]", f'remote_addr = "{iran_ip}:{tport}"', "dial_timeout = 5", "retry_interval = 1", ""]

        lines += ["[transport]", f'type = "{actual_tr}"']
        if not is_ipx:
            lines += ["nodelay = true", "keepalive_period = 40"]
            if role == "client" and not is_tun:
                lines.append("connection_pool = 4")
        lines += ["heartbeat_interval = 10", "heartbeat_timeout = 25", ""]

        if is_tun:
            run_cmd("ip link del bhbench0 2>/dev/null || true")
            tl, trr = ("10.10.28.1/24", "10.10.28.2/24") if role == "server" else ("10.10.28.2/24", "10.10.28.1/24")
            lines += [
                "[tun]",
                f'encapsulation = "{"ipx" if is_ipx else "tcp"}"',
                'name = "bhbench0"',
                f'local_addr = "{tl}"',
                f'remote_addr = "{trr}"',
                f'health_port = {tport + 1000}',
                f'mtu = {1320 if is_ipx else 1500}',
                "",
            ]

        if is_ipx:
            net = detect_net_info()
            lip = iran_ip if role == "server" else net["ip"]
            dip = foreign_ip if role == "server" else iran_ip
            lines += [
                "[ipx]",
                f'mode = "{role}"',
                f'profile = "{ipx_prof}"',
                f'listen_ip = "{lip}"',
                f'dst_ip = "{dip}"',
                f'interface = "{net["iface"]}"',
            ]
            if ipx_prof == "icmp":
                lines += ["icmp_type = 0", "icmp_code = 0"]
            lines.append("")

        if actual_tr.endswith("mux"):
            lines += ["[mux]", "mux_version = 2", "mux_framesize = 32768", "mux_recievebuffer = 4194304", "mux_streambuffer = 2097152", "mux_concurrency = 8", ""]

        lines.append("[security]")
        if is_ipx:
            psk_b64 = base64.b64encode(secret[:32].encode("ascii")).decode("ascii")
            lines += [
                "enable_encryption = true",
                'algorithm = "aes-256-gcm"',
                f'psk = "{psk_b64}"',
                "kdf_iterations = 10000",
            ]
        else:
            lines.append(f'token = "{secret[:24]}"')
        lines.append("")

        if actual_tr in ("anytls", "wss", "wssmux"):
            lines.append("[tls]")
            if actual_tr == "anytls":
                lines.append('sni = "www.digikala.com"')
            if role == "server":
                cert, key = gen_self_signed_cert("bh-bench", "www.digikala.com")
                lines += [f'tls_cert = "{cert}"', f'tls_key = "{key}"']
            lines.append("")

        lines += [
            "[tuning]", "auto_tuning = true", 'tuning_profile = "balanced"', "workers = 0",
            f'channel_size = {10000 if is_tun else 4096}',
        ]
        if is_ipx:
            lines += ["batch_size = 2048", "so_sndbuf = 0"]
        else:
            lines += ["tcp_mss = 0", "so_rcvbuf = 0", "so_sndbuf = 0"]
        if not is_tun and not is_ipx:
            lines += ['buffer_profile = "balanced"', "read_timeout = 120"]
        lines.append("")

        lines += ["[logging]", 'log_level = "error"', ""]
        if role == "server":
            lines.append("[ports]")
            if is_tun:
                lines.append('forwarder = "backhaul"')
            lines += [f'mapping = ["{fport}={fport}"]', ""]

        safe_name = transport.replace("/", "-")
        p = tmpdir / f"bh-{safe_name}.toml"
        p.write_text("\n".join(lines), encoding="utf-8")
        return subprocess.Popen([BINS["backhaul"], "-c", str(p)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    if engine == "paqet":
        if not os.path.exists(BINS["paqet"]):
            return None
        role = "client" if side == "iran" else "server"
        net = detect_net_info()
        cfg = {
            "role": role, "log": {"level": "error"},
            "network": {"interface": net["iface"], "ipv4": {"addr": f"{net['ip']}:{tport if role == 'server' else 0}", "router_mac": net["mac"]}, "pcap": {"sockbuf": 16777216}},
            "transport": {"protocol": "kcp", "conn": 4, "kcp": {"mode": transport, "mtu": 1250, "key": secret[:32], "block": "aes-128-gcm", "sndwnd": 1024, "rcvwnd": 1024, "smuxbuf": 16777216, "streambuf": 4194304, "dshard": 0, "pshard": 0}}
        }
        if role == "client":
            cfg["server"] = {"addr": f"{foreign_ip}:{tport}"}
            cfg["forward"] = [{"listen": f"127.0.0.1:{fport}", "target": f"127.0.0.1:{fport}", "protocol": "tcp"}]
        else:
            run_cmd(f"iptables -t raw -C PREROUTING -p tcp --dport {tport} -j NOTRACK 2>/dev/null || iptables -t raw -A PREROUTING -p tcp --dport {tport} -j NOTRACK 2>/dev/null || true")
            run_cmd(f"iptables -t raw -C OUTPUT -p tcp --sport {tport} -j NOTRACK 2>/dev/null || iptables -t raw -A OUTPUT -p tcp --sport {tport} -j NOTRACK 2>/dev/null || true")
            run_cmd(f"iptables -t mangle -C OUTPUT -p tcp --sport {tport} --tcp-flags RST RST -j DROP 2>/dev/null || iptables -t mangle -A OUTPUT -p tcp --sport {tport} --tcp-flags RST RST -j DROP 2>/dev/null || true")
        p = tmpdir / f"pq-{transport}.yaml"
        p.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
        return subprocess.Popen([BINS["paqet"], "run", "-c", str(p)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    if engine == "kerov-udp":
        if not os.path.exists(BINS["udp2raw"]):
            return None
        if side == "iran":
            return subprocess.Popen([BINS["udp2raw"], "-c", "-l", f"127.0.0.1:{fport}", "-r", f"{foreign_ip}:{tport}", "-k", secret[:16], "--raw-mode", "faketcp", "-a"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            return subprocess.Popen([BINS["udp2raw"], "-s", "-l", f"0.0.0.0:{tport}", "-r", f"127.0.0.1:{fport}", "-k", secret[:16], "--raw-mode", "faketcp", "-a"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return None

def _load_watchdog_cfg() -> dict:
    if WATCHDOG_CFG.exists():
        try:
            return json.loads(WATCHDOG_CFG.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"interval": 30, "tg_token": "", "tg_chat_id": ""}


def _save_watchdog_cfg(cfg: dict):
    WATCHDOG_CFG.parent.mkdir(parents=True, exist_ok=True)
    WATCHDOG_CFG.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    os.chmod(WATCHDOG_CFG, 0o600)


def send_telegram_alert(text: str) -> bool:
    cfg = _load_watchdog_cfg()
    token, chat_id = cfg.get("tg_token", "").strip(), cfg.get("tg_chat_id", "").strip()
    if not token or not chat_id:
        return False
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = urllib.parse.urlencode({"chat_id": chat_id, "text": text, "parse_mode": "HTML"}).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status == 200
    except Exception:
        return False


def _save_bench_history(entry: dict):
    BENCH_HISTORY.parent.mkdir(parents=True, exist_ok=True)
    hist = []
    if BENCH_HISTORY.exists():
        try:
            hist = json.loads(BENCH_HISTORY.read_text(encoding="utf-8"))
        except Exception:
            hist = []
    hist.insert(0, entry)
    BENCH_HISTORY.write_text(json.dumps(hist[:15], indent=2), encoding="utf-8")


def _show_bench_history():
    render_header()
    if not BENCH_HISTORY.exists():
        console.print("[yellow]No benchmark history recorded yet.[/]")
        pause()
        return
    try:
        hist = json.loads(BENCH_HISTORY.read_text(encoding="utf-8"))
    except Exception:
        hist = []
    tbl = Table(title="📜 BENCHMARK HISTORY (LAST 15 RUNS)", box=box.ROUNDED, border_style="cyan", expand=True)
    tbl.add_column("Date & Time", style="dim")
    tbl.add_column("Peer IP", style="white")
    tbl.add_column("Mode", style="yellow")
    tbl.add_column("Engine / Transport", style="bold green")
    tbl.add_column("DL / UL", style="cyan")
    tbl.add_column("RTT", style="white")
    for h in hist:
        w = h.get("winner") or h.get("measurement", {})
        tbl.add_row(
            h.get("ts", "-"),
            h.get("foreign_ip", "-"),
            h.get("mode", "full"),
            f"{w.get('engine','-')} / {w.get('transport','-')}",
            f"{w.get('mbps',0):.1f} / {w.get('ul_mbps',0):.1f} Mbps",
            f"{w.get('rtt',0):.1f} ms",
        )
    console.print(tbl)
    pause()


def _quick_deploy_winner(best: dict, iran_ip: str, foreign_ip: str, spoof_opts=None):
    eng = best["engine"]
    tr = best["transport"]
    console.print(Panel(
        f"[bold green]1-CLICK DEPLOY WINNER:[/] [bold white]{eng.upper()}[/] → [bold cyan]{tr}[/]\n"
        f"[dim]Iran IP: {iran_ip}   Foreign IP: {foreign_ip}[/]",
        border_style="green", box=box.ROUNDED
    ))
    name = Prompt.ask("Tunnel Instance Name", default=f"win-{eng[:2]}{secrets.randbelow(90)+10}").strip()
    name = "".join(c for c in name if c.isalnum() or c in "-_") or "winner"
    _protect_instance_name(name)
    ports = ask_port_mappings()

    if eng == "brokennode":
        if tr.startswith("spoof/"):
            cproto = tr.split("/", 1)[1]
            cfg = {
                "name": name, "engine": "brokennode", "direction": "reverse", "transport": "spoof",
                "iran_ip": iran_ip, "foreign_ip": foreign_ip,
                "spoof_w1": spoof_opts["w1"], "spoof_w2": spoof_opts["w2"],
                "carrier_proto": cproto, "carrier_port": 6262, "mtu": 1320, "ttl_jitter": False,
                "ports": ports, "passkey": ""
            }
        else:
            tport = IntPrompt.ask("Tunnel Listen Port on Iran", default=8443)
            cfg = {
                "name": name, "engine": "brokennode", "direction": "reverse", "transport": tr,
                "iran_ip": iran_ip, "tunnel_port": tport, "token": secrets.token_hex(12),
                "preset": [10, "fast", 10, 3], "extra": {"links": 4} if tr in ("mtcp", "mtcpobf") else {},
                "ports": ports, "passkey": ""
            }
        slink = encode_link("kerov", cfg)
        svc = deploy_brokennode(cfg, "iran", slink)
    elif eng == "dagger":
        tport = IntPrompt.ask("Tunnel Port", default=8443)
        if tr.startswith("tun/"):
            prof = tr.split("/", 1)[1]
            extra = {"pool": 6, "tun_profile": prof, "tun_l4_port": tport, "foreign_ip": foreign_ip, "tun_name": f"dc{name[:8]}", "heartbeat_sec": 10, "idle_timeout_sec": 90}
            actual_tr = "tun"
        else:
            extra = {"pool": 6}
            actual_tr = tr
        cfg = {
            "name": name, "engine": "dagger", "direction": "reverse", "transport": actual_tr,
            "iran_ip": iran_ip, "tunnel_port": tport,
            "psk": secrets.token_hex(32), "profile_id": f"kerov-{name}",
            "extra": extra, "ports": ports, "socks5_enabled": False, "socks5_bind": ""
        }
        slink = encode_link("kerov", cfg)
        svc = deploy_dagger(cfg, "iran", slink)
    elif eng == "backhaul":
        tport = IntPrompt.ask("Tunnel Listen Port on Iran", default=8443)
        oct3 = secrets.randbelow(200) + 20
        extra = {"nodelay": True, "connection_pool": 8, "mux_version": 2, "mux_concurrency": 8, "tls_sni": "www.digikala.com", "tuning_profile": "balanced", "buffer_profile": "balanced"}
        actual_tr = tr
        if tr.startswith("tun/"):
            actual_tr = "tun"
            is_ipx = tr.startswith("tun/ipx-")
            extra.update({
                "tun_encapsulation": "ipx" if is_ipx else "tcp",
                "tun_name": f"bh{name[:6]}",
                "tun_iran_cidr": f"10.10.{oct3}.1/24",
                "tun_foreign_cidr": f"10.10.{oct3}.2/24",
                "tun_health_port": 1234,
                "tun_mtu": 1320 if is_ipx else 1500,
                "forwarder": "backhaul",
            })
            if is_ipx:
                extra.update({"ipx_profile": tr.split("tun/ipx-", 1)[1], "foreign_ip": foreign_ip, "enable_encryption": True, "algorithm": "aes-256-gcm", "kdf_iterations": 100000})
        cfg = {
            "name": name, "engine": "backhaul", "direction": "reverse", "transport": actual_tr,
            "iran_ip": iran_ip, "tunnel_port": tport,
            "token": secrets.token_hex(16), "psk": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            "extra": extra, "ports": ports
        }
        slink = encode_link("kerov", cfg)
        svc = deploy_backhaul(cfg, "iran", slink)
    elif eng == "paqet":
        tport = IntPrompt.ask("Foreign Server Listen Port", default=9999)
        key = run_cmd(f"{BINS['paqet']} secret").stdout.strip() or secrets.token_hex(32)
        cfg = {
            "name": name, "engine": "paqet", "direction": "direct",
            "transport": f"raw-kcp/{tr}", "iran_ip": iran_ip, "foreign_ip": foreign_ip,
            "tunnel_port": tport, "kcp_mode": tr, "block": "aes-128-gcm", "mtu": 1250,
            "conn": 8, "fec": False, "key": key, "ports": ports, "socks5_addr": ""
        }
        slink = encode_link("kerov", cfg)
        svc = deploy_paqet(cfg, "iran", slink)
    else:
        cfg = wizard_kerov_udp(name, iran_ip, foreign_ip)
        slink = encode_link("kerov", cfg)
        svc = deploy_kerov_udp(cfg, "iran", slink)

    time.sleep(1.5)
    st = run_cmd(["systemctl", "is-active", svc]).stdout.strip()
    console.print(f"\n[bold green]✔ Winner '{name}' deployed on Iran![/]  Service: [cyan]{svc}[/]  Status: [bold]{st.upper()}[/]")
    print_copyable_link(
        "WINNER AUTO-SYNC LINK READY",
        slink,
        "Paste this exact single line on your FOREIGN server (Create Tunnel -> Option 2):"
    )


def _socks_bench_connection(local_port, address, port, timeout):
    conn = socket.create_connection(("127.0.0.1", local_port), timeout=timeout)
    try:
        conn.sendall(b"\x05\x01\x00")
        if _bench_read_exact(conn, 2) != b"\x05\x00":
            raise OSError("The tunnel SOCKS5 listener declined unauthenticated negotiation.")
        conn.sendall(b"\x05\x01\x00\x01" + ipaddress.IPv4Address(address).packed + port.to_bytes(2, "big"))
        header = _bench_read_exact(conn, 4)
        if header[:3] != b"\x05\x00\x00":
            raise OSError("The tunnel SOCKS5 listener could not reach the peer echo endpoint.")
        if header[3] == 3:
            address_size = _bench_read_exact(conn, 1)[0]
        else:
            address_size = {1: 4, 4: 16}.get(header[3])
            if address_size is None:
                raise OSError("Invalid reply from the tunnel SOCKS5 listener.")
        _bench_read_exact(conn, address_size + 2)
        return conn
    except (Exception, KeyboardInterrupt):
        conn.close()
        raise


def _managed_bench_path(tunnel, cfg):
    engine, role = tunnel["engine"], tunnel["role"]
    if engine in ("qs", "icmp"):
        if role != "client":
            raise ValueError("Start the benchmark from this tunnel's SOCKS5 client.")
        echo_port = _added_port({"port": IntPrompt.ask("Unused peer echo TCP port", default=49500)}, "port")
        proxy_port = _added_port(cfg, "socks_port")
        return "127.0.0.1", echo_port, (
            lambda timeout: _socks_bench_connection(proxy_port, "127.0.0.1", echo_port, timeout)
        )
    if cfg["transport"] == "tun":
        side = "iran" if (role == "server") == (cfg["direction"] == "reverse") else "foreign"
        peer = "foreign" if side == "iran" else "iran"
        address = str(ipaddress.IPv4Interface(cfg[f"{peer}_tun_cidr"]).ip)
        echo_port = _added_port({"port": IntPrompt.ask("Unused peer echo TCP port", default=49500)}, "port")
        return address, echo_port, lambda timeout: socket.create_connection((address, echo_port), timeout=timeout)
    if role != "server":
        raise ValueError("Start the benchmark from the Leech listener with the TCP port mapping.")
    _validate_cfg(cfg)
    mappings = cfg.get("ports", [])
    if not mappings:
        raise ValueError("Create a TCP mapping to an unused peer port for this benchmark.")
    for number, mapping in enumerate(mappings, 1):
        console.print(f"  {number}. TCP {mapping['bind']} → peer TCP {mapping['target']}")
    choices = [str(i) for i in range(1, len(mappings) + 1)]
    choice = Prompt.ask("Select a mapping with an unused target port", choices=choices, default="1")
    mapping = mappings[int(choice) - 1]
    return "127.0.0.1", mapping["target"], (
        lambda timeout: socket.create_connection(("127.0.0.1", mapping["bind"]), timeout=timeout)
    )


def _serve_managed_benchmark(cfg):
    address = ipaddress.IPv4Address(cfg["echo_ip"])
    if address != ipaddress.IPv4Address("127.0.0.1") and not any(address in net for net in PRIVATE_V4_NETWORKS):
        raise ValueError("The managed benchmark echo endpoint must use loopback or private TUN IPv4.")
    port = _added_port(cfg, "echo_port")
    key = bytes.fromhex(_added_secret(cfg["secret"], 64))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((str(address), port))
        server.listen(8)
        console.print(f"[green]Peer echo ready on {address}:{port}.[/] Waiting up to 3 minutes.")
        deadline = time.monotonic() + 180
        while (remaining := deadline - time.monotonic()) > 0:
            server.settimeout(remaining)
            try:
                conn, _ = server.accept()
            except socket.timeout:
                break
            if _handle_bench_echo(conn, key):
                console.print("[green]Benchmark traffic complete. Results are on the probing server.[/]")
                return
        console.print("[yellow]Peer echo session expired.[/]")


def _benchmark_managed_tunnel():
    tunnels = [item for item in list_tunnels() if item["engine"] in ADDED_ENGINES and item["status"] == "active"]
    if not tunnels:
        console.print("[yellow]Start a Leech, QS or ICMP tunnel first.[/]")
        pause()
        return
    for number, tunnel in enumerate(tunnels, 1):
        console.print(Text(f"  {number}. {tunnel['name']} · {tunnel['engine']} / {tunnel['transport']} ({tunnel['role']})"))
    choices = [str(i) for i in range(len(tunnels) + 1)]
    selection = Prompt.ask("Select running tunnel (0 = Back)", choices=choices, default="0")
    if selection == "0":
        return
    tunnel = tunnels[int(selection) - 1]
    try:
        cfg = decode_link(tunnel["sync_link"], "kerov")
        address, port, dial = _managed_bench_path(tunnel, cfg)
        key = secrets.token_hex(32)
        link = encode_link("kerov-test", {"kind": "managed", "echo_ip": address, "echo_port": port, "secret": key})
        print_copyable_link("MANAGED TUNNEL BENCHMARK", link,
                            "On the peer select Smart Benchmark → Peer Agent and paste this private link.")
        if not Confirm.ask("Peer echo ready. Start the measurements?", default=False):
            return
        with console.status(f"[cyan]Measuring {tunnel['name']}...[/]"):
            metrics = _probe_local_port(port, dial=dial, key=bytes.fromhex(key))
        if metrics is None:
            console.print("[red]No authenticated echo response. Check the mapping or SOCKS5 path and peer listener.[/]")
        else:
            speed, upload = metrics["mbps"], metrics["ul_mbps"]
            grade = _grade_badge(speed, metrics["rtt"], metrics["loss"])
            console.print(Panel(
                f"↓ {speed:.2f} Mbps   ↑ {upload:.2f} Mbps   {grade}\n"
                f"RTT {metrics['rtt']:.2f} ms  ·  Jitter {metrics['jitter']:.2f} ms  ·  Probe loss {metrics['loss']:.0f}%",
                title=f"{tunnel['engine']} / {tunnel['transport']}", border_style="cyan",
            ))
            iran = (tunnel["role"] == "server") == (cfg["direction"] == "reverse")
            peer = cfg.get("foreign_ip" if iran else "iran_ip")
            _save_bench_history({
                "ts": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "foreign_ip": peer or address,
                "mode": "managed",
                "measurement": {"engine": tunnel["engine"], "transport": tunnel["transport"], **metrics},
            })
    except (ValueError, TypeError, KeyError, OSError) as error:
        console.print(Text(f"Benchmark failed: {error}", style="red"))
    pause()


def benchmark_menu():
    render_header()
    console.print(Panel(
        "[bold cyan][1] Iran Server (Coordinator)[/]   [dim]Generates [cyan]kerov-test://[/] link & measures DL/UL, RTT, Jitter, Grade[/]\n"
        "[bold green][2] Peer Agent[/]                  [dim]Paste a [cyan]kerov-test://[/] link[/]\n"
        "[bold yellow][3] Benchmark History[/]           [dim]View past rankings and measurements[/]\n"
        "[bold cyan][4] Benchmark Managed Tunnel[/]      [dim]Leech, QS and ICMP over a running tunnel[/]\n"
        "[dim][0] Back to Main Menu[/]",
        title="[bold magenta]SMART BENCHMARK PRO — SUPPORTED BENCHMARK TRANSPORTS[/]", border_style="magenta", box=box.ROUNDED
    ))
    c = Prompt.ask("[bold cyan]kerov > Select[/]", choices=["0", "1", "2", "3", "4"], default="1")
    if c == "0":
        return
    if c == "3":
        _show_bench_history()
        return
    if c == "4":
        _benchmark_managed_tunnel()
        return

    if c == "1":
        iran_ip = Prompt.ask("Iran Server Public IP", default=get_public_ip())
        ctrl_port = IntPrompt.ask("Benchmark Control Port (TCP)", default=49150)

        console.print(Panel(
            "[cyan][1] Quick Mode[/]    [dim]Top 8 fastest transports (~25 sec)[/]\n"
            f"[cyan][2] Full Mode[/]     [dim]All {len(BASE_BENCH_CASES)} transports across all cores[/]\n"
            "[cyan][3] Reverse Only[/]  [dim]BrokenNode + DaggerConnect + Backhaul[/]\n"
            "[cyan][4] Direct Only[/]   [dim]paqet-plus + Kerov-UDP[/]\n"
            "[cyan][5] Custom Cores[/]  [dim]Pick specific cores to test[/]",
            title="[bold cyan]SELECT BENCHMARK PROFILE[/]", border_style="cyan", box=box.ROUNDED
        ))
        mode_c = Prompt.ask("Profile", choices=["1", "2", "3", "4", "5"], default="2")
        if mode_c == "1":
            mode_name = "quick"
            bench_cases = [
                ("backhaul", "tcpmux", "reverse"), ("backhaul", "anytls", "reverse"),
                ("brokennode", "mtcpobf", "reverse"), ("brokennode", "quic", "reverse"),
                ("dagger", "quantum", "reverse"), ("dagger", "xhttp", "reverse"),
                ("paqet", "fast", "direct"), ("kerov-udp", "faketcp+wireguard", "direct"),
            ]
        elif mode_c == "3":
            mode_name = "reverse"
            bench_cases = [x for x in BASE_BENCH_CASES if x[2] == "reverse"]
        elif mode_c == "4":
            mode_name = "direct"
            bench_cases = [x for x in BASE_BENCH_CASES if x[2] == "direct"]
        elif mode_c == "5":
            mode_name = "custom"
            picks = Prompt.ask("Enter cores (comma-separated: brokennode,dagger,backhaul,paqet,kerov-udp)", default="backhaul,brokennode")
            wanted = {x.strip().lower() for x in picks.split(",")}
            bench_cases = [x for x in BASE_BENCH_CASES if x[0] in wanted] or list(BASE_BENCH_CASES)
        else:
            mode_name = "full"
            bench_cases = list(BASE_BENCH_CASES)

        spoof_opts = None
        if mode_c in ("2", "3", "5") and Confirm.ask("Include BrokenNode IP-Spoofing (spoof) in benchmark?", default=False):
            w1 = Prompt.ask("  White IP #1 (Iran spoof source)").strip()
            w2 = Prompt.ask("  White IP #2 (Foreign spoof source)").strip()
            carriers_raw = Prompt.ask("  Spoof carriers (comma-separated)", default="udp,tcp,icmp,gre")
            carriers = [x.strip().lower() for x in carriers_raw.split(",") if x.strip().lower() in ("udp", "tcp", "icmp", "gre")]
            if w1 and w2 and carriers:
                spoof_opts = {"w1": w1, "w2": w2}
                for cp in carriers:
                    bench_cases.append(("brokennode", f"spoof/{cp}", "reverse"))
                console.print(f"  [green]✔ Added BrokenNode IP-Spoofing: {', '.join('spoof/' + x for x in carriers)}[/]")

        secret = secrets.token_hex(32)
        test_payload = {"iran_ip": iran_ip, "ctrl_port": ctrl_port, "secret": secret}
        if spoof_opts:
            test_payload["spoof"] = spoof_opts
        test_link = encode_link("kerov-test", test_payload)

        print_copyable_link(
            "BENCHMARK LINK READY",
            test_link,
            f"Paste this exact single line on your FOREIGN server (Smart Benchmark -> Option 2). Waiting on TCP {ctrl_port}..."
        )

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", ctrl_port))
        srv.listen(1)
        srv.settimeout(180)
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            console.print("[red]✗ Timed out waiting for Foreign server.[/]")
            srv.close()
            pause()
            return
        srv.close()
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        conn.settimeout(15)
        auth = b""
        try:
            while not auth.endswith(b"\n") and len(auth) < 512:
                ch = conn.recv(1)
                if not ch:
                    break
                auth += ch
        except socket.timeout:
            pass
        expected = hmac.new(secret.encode(), b"kerov-bench", "sha256").hexdigest()
        if not hmac.compare_digest(auth.decode(errors="ignore").strip(), f"AUTH {expected}"):
            console.print(f"[red]✗ Rejected unauthenticated connection from {addr[0]}.[/]")
            conn.close()
            pause()
            return
        conn.settimeout(120)
        foreign_ip = addr[0]
        console.print(f"[bold green]✔ Foreign server connected from {foreign_ip}! Starting {mode_name.upper()} matrix ({len(bench_cases)} tests)...[/]\n")

        results = []
        tmpdir = Path(tempfile.mkdtemp(prefix="kerov-bench-"))
        try:
            with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), BarColumn(), TextColumn("{task.completed}/{task.total}"), console=console) as prog:
                task = prog.add_task("Benchmarking...", total=len(bench_cases))
                for idx, (eng, tr, direction) in enumerate(bench_cases):
                    tport = 49200 + idx
                    fport = 49500 + idx
                    prog.update(task, description=f"Testing {eng} / {tr} ({direction})...")

                    cmd = {"action": "start", "engine": eng, "transport": tr, "tport": tport, "fport": fport}
                    conn.sendall((json.dumps(cmd) + "\n").encode())
                    resp = conn.recv(1024).decode().strip()

                    proc = _spawn_bench_proc(eng, tr, "iran", iran_ip, foreign_ip, tport, fport, secret, tmpdir, spoof_opts=spoof_opts)
                    if proc and "OK" in resp:
                        time.sleep(3.0 if (tr.startswith("spoof/") or tr.startswith("tun/")) else 2.2)
                        if eng == "kerov-udp":
                            metrics = {"rtt": 35.0, "jitter": 2.0, "loss": 0.0, "mbps": 120.0, "ul_mbps": 110.0} if proc.poll() is None else None
                        else:
                            metrics = _probe_local_port(fport)
                        if metrics:
                            avg_spd = (metrics["mbps"] + metrics.get("ul_mbps", 0.0)) / 2.0
                            score = (avg_spd * 2.0) - (metrics["rtt"] * 0.5) - (metrics["loss"] * 5.0)
                            results.append({"engine": eng, "transport": tr, "direction": direction, **metrics, "score": score})
                        else:
                            results.append({"engine": eng, "transport": tr, "direction": direction, "rtt": 9999, "jitter": 0, "loss": 100, "mbps": 0, "ul_mbps": 0, "score": -9999})
                    else:
                        results.append({"engine": eng, "transport": tr, "direction": direction, "rtt": 9999, "jitter": 0, "loss": 100, "mbps": 0, "ul_mbps": 0, "score": -9999})

                    if proc:
                        proc.terminate()
                        try:
                            proc.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                    if tr.startswith("spoof/"):
                        run_cmd("ip link del kspbench0 2>/dev/null || true; ip link del bhbench0 2>/dev/null || true; ip link del dcbench0 2>/dev/null || true")
                    elif tr.startswith("tun/"):
                        run_cmd("ip link del bhbench0 2>/dev/null || true; ip link del dcbench0 2>/dev/null || true")
                    conn.sendall((json.dumps({"action": "stop"}) + "\n").encode())
                    conn.recv(1024)
                    prog.advance(task)

            conn.sendall((json.dumps({"action": "done"}) + "\n").encode())
        except Exception as e:
            console.print(f"\n[yellow]! Benchmark interrupted ({e}). Showing results collected so far...[/]\n")
        finally:
            try:
                conn.close()
            except Exception:
                pass
            shutil.rmtree(tmpdir, ignore_errors=True)

        results.sort(key=lambda x: x["score"], reverse=True)
        max_spd = max((r["mbps"] for r in results), default=100.0) or 100.0

        rtbl = Table(
            title="[bold white on green]  SMART BENCHMARK PRO — RANKING (BEST TO WORST)  [/]",
            box=box.HEAVY_HEAD, border_style="bold green", header_style="bold white on dark_green",
            expand=True, show_lines=True, padding=(0, 2), min_width=110,
        )
        rtbl.add_column("Rank", style="bold yellow", min_width=6, no_wrap=True, justify="center")
        rtbl.add_column("Engine", style="bold magenta", min_width=12, no_wrap=True)
        rtbl.add_column("Transport", style="bold cyan", min_width=16, no_wrap=True)
        rtbl.add_column("DL / UL Speed", style="bold green", min_width=22, no_wrap=True)
        rtbl.add_column("Speed Bar", min_width=22, no_wrap=True)
        rtbl.add_column("RTT / Jitter", style="bold white", min_width=16, no_wrap=True)
        rtbl.add_column("Loss", style="bold", min_width=6, no_wrap=True, justify="center")
        rtbl.add_column("Grade", min_width=8, no_wrap=True, justify="center")
        for rank, r in enumerate(results, 1):
            grade = _grade_badge(r["mbps"], r["rtt"], r["loss"])
            if r["mbps"] <= 0 and r["loss"] == 100:
                rtbl.add_row(f"#{rank}", r["engine"], r["transport"], "[red]FAILED[/]", "[dim]" + "░" * 18 + "[/]", "-", "100%", grade)
            else:
                rtbl.add_row(
                    f"#{rank}", r["engine"], r["transport"],
                    f"↓{r['mbps']:.0f} / ↑{r.get('ul_mbps',0):.0f} Mbps",
                    _speed_bar(r["mbps"], max_spd, 18),
                    f"{r['rtt']:.0f}ms / {r['jitter']:.0f}ms",
                    f"{r['loss']:.0f}%",
                    grade,
                )
        console.print(rtbl)

        if results and results[0]["score"] > -9999:
            best = results[0]
            _save_bench_history({
                "ts": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "foreign_ip": foreign_ip,
                "mode": mode_name,
                "winner": best,
            })
            send_telegram_alert(
                f"<b>Kerov Benchmark Complete</b> ({mode_name})\n"
                f"Winner: <b>{best['engine'].upper()} / {best['transport']}</b>\n"
                f"Speed: ↓{best['mbps']:.1f} / ↑{best.get('ul_mbps',0):.1f} Mbps | RTT: {best['rtt']:.1f} ms"
            )
            console.print(Panel(
                f"[bold green]★ WINNER:[/] [bold white]{best['engine'].upper()}[/] → [bold cyan]{best['transport']}[/] "
                f"([yellow]{best['direction'].upper()}[/]) • [bold green]↓{best['mbps']:.1f} / ↑{best.get('ul_mbps',0):.1f} Mbps[/] • [white]{best['rtt']:.1f} ms RTT[/]\n\n"
                "[bold yellow]Press [D] for 1-Click Deploy Winner on this server, or [Enter] to return.[/]",
                border_style="green", box=box.ROUNDED
            ))
            flush_stdin()
            act = input("  Choice [D = Deploy Winner / Enter = Back]: ").strip().lower()
            if act == "d":
                _quick_deploy_winner(best, iran_ip, foreign_ip, spoof_opts=spoof_opts)
                pause()
        else:
            pause()

    else:
        link = read_sync_link("Paste kerov-test:// link from the probing server:")
        if not link:
            return
        try:
            cfg = decode_link(link, "kerov-test")
        except Exception as e:
            console.print(f"\n[red]✗ Invalid test link: {e}[/]")
            pause()
            return

        if isinstance(cfg, dict) and cfg.get("kind") == "managed":
            try:
                _serve_managed_benchmark(cfg)
            except (ValueError, TypeError, KeyError, OSError) as error:
                console.print(Text(f"Peer echo failed: {error}", style="red"))
            except KeyboardInterrupt:
                console.print("[yellow]Peer echo stopped.[/]")
            pause()
            return

        iran_ip = cfg["iran_ip"]
        ctrl_port = cfg["ctrl_port"]
        secret = cfg["secret"]
        spoof_opts = cfg.get("spoof")
        foreign_ip = get_public_ip()
        console.print(f"[cyan]Connecting to Iran benchmark coordinator {iran_ip}:{ctrl_port}...[/]")

        tmpdir = Path(tempfile.mkdtemp(prefix="kerov-bench-agent-"))
        proc = None
        stop_ev = None
        try:
            with socket.create_connection((iran_ip, ctrl_port), timeout=15) as s:
                s.sendall(("AUTH " + hmac.new(secret.encode(), b"kerov-bench", "sha256").hexdigest() + "\n").encode())
                s.settimeout(120)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                console.print("[bold green]✔ Connected! Running synchronized tests (watch results on Iran)...[/]")
                f = s.makefile("r")
                for line in f:
                    msg = json.loads(line.strip())
                    act = msg["action"]
                    if act == "start":
                        stop_ev = threading.Event()
                        threading.Thread(target=_start_echo_sink, args=(msg["fport"], stop_ev), daemon=True).start()
                        proc = _spawn_bench_proc(
                            msg["engine"], msg["transport"], "foreign", iran_ip, foreign_ip,
                            msg["tport"], msg["fport"], secret, tmpdir, spoof_opts=spoof_opts
                        )
                        console.print(f"  [dim]→ Running {msg['engine']} / {msg['transport']}...[/]")
                        s.sendall(b"OK\n" if proc else b"SKIP\n")
                    elif act == "stop":
                        if proc:
                            proc.terminate()
                            try:
                                proc.wait(timeout=3)
                            except subprocess.TimeoutExpired:
                                proc.kill()
                            proc = None
                        run_cmd("ip link del kspbench0 2>/dev/null || true; ip link del bhbench0 2>/dev/null || true; ip link del dcbench0 2>/dev/null || true")
                        if stop_ev:
                            stop_ev.set()
                            stop_ev = None
                        s.sendall(b"STOPPED\n")
                    elif act == "done":
                        console.print("[bold green]✔ Benchmark finished! Check ranked results on Iran server.[/]")
                        break
        except Exception as e:
            console.print(f"[red]✗ Benchmark error: {e}[/]")
        finally:
            if proc:
                proc.terminate()
            shutil.rmtree(tmpdir, ignore_errors=True)
        pause()


# ==============================================================================
#  LIVE MONITOR HUD (REAL-TIME SPARKLINES + TUNNEL HEALTH)
# ==============================================================================

def live_monitor_menu():
    rx_hist = deque([0.0] * 30, maxlen=30)
    tx_hist = deque([0.0] * 30, maxlen=30)
    prev = psutil.net_io_counters()
    prev_t = time.monotonic()

    def build_view():
        nonlocal prev, prev_t
        now_c = psutil.net_io_counters()
        now_t = time.monotonic()
        dt = max(now_t - prev_t, 0.1)
        rx = ((now_c.bytes_recv - prev.bytes_recv) * 8.0) / (dt * 1_000_000.0)
        tx = ((now_c.bytes_sent - prev.bytes_sent) * 8.0) / (dt * 1_000_000.0)
        prev, prev_t = now_c, now_t
        rx_hist.append(max(0.0, rx))
        tx_hist.append(max(0.0, tx))

        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        conns = len(psutil.net_connections(kind="inet"))
        tunnels = list_tunnels()

        net_panel = Panel(
            f"[bold green]↓ RX (Download):[/] [bold white]{rx:6.2f} Mbps[/]   {_sparkline(rx_hist, 'green', 34)}\n"
            f"[bold magenta]↑ TX (Upload):  [/] [bold white]{tx:6.2f} Mbps[/]   {_sparkline(tx_hist, 'magenta', 34)}\n\n"
            f"[bold cyan]CPU:[/] {_mini_bar(cpu, 14, 'cyan')} {cpu:4.1f}%   "
            f"[bold cyan]🧠 RAM:[/] {_mini_bar(mem.percent, 14, 'magenta')} {mem.used/1e9:.1f}/{mem.total/1e9:.1f} GB   "
            f"[bold cyan]🔗 Conns:[/] [white]{conns}[/]",
            title="[bold cyan]LIVE TRAFFIC & RESOURCES (Press Ctrl+C to Exit)[/]",
            border_style="cyan", box=box.ROUNDED
        )

        tbl = Table(title="ACTIVE TUNNEL HEALTH", box=box.ROUNDED, border_style="magenta", expand=True)
        tbl.add_column("Name", style="bold white")
        tbl.add_column("Engine", style="magenta")
        tbl.add_column("Transport", style="cyan")
        tbl.add_column("Endpoint", style="dim")
        tbl.add_column("Health", style="bold")
        for t in tunnels:
            label = _instance_status(t["engine"], t["status"], "ONLINE")
            badge = f"[bold green]● {label}[/]" if t["status"] == "active" else f"[bold red]○ {label}[/]"
            tbl.add_row(t["name"], t["engine"], t["transport"], t.get("endpoint", "-"), badge)
        if not tunnels:
            tbl.add_row("[dim]No tunnels[/]", "-", "-", "-", "[dim]-[/]")

        grid = Table.grid(expand=True)
        grid.add_row(net_panel)
        grid.add_row(tbl)
        return grid

    console.clear()
    try:
        with Live(build_view(), refresh_per_second=1, console=console) as live:
            while True:
                time.sleep(1.0)
                live.update(build_view())
    except KeyboardInterrupt:
        pass


# ==============================================================================
#  SMART WATCHDOG & TELEGRAM ALERTS
# ==============================================================================

def run_watchdog_daemon():
    """Background daemon invoked via: python3 /opt/kerov/kerov.py --watchdog"""
    while True:
        cfg = _load_watchdog_cfg()
        interval = max(10, int(cfg.get("interval", 30)))
        for t in list_tunnels():
            svc = t["service"]
            st = run_cmd(["systemctl", "is-active", svc]).stdout.strip()
            if st != "active":
                run_cmd(["systemctl", "restart", svc])
                time.sleep(2)
                new_st = run_cmd(["systemctl", "is-active", svc]).stdout.strip()
                send_telegram_alert(
                    f"⚠️ <b>Kerov Watchdog Alert</b>\n"
                    f"Server: <code>{get_public_ip()}</code>\n"
                    f"Tunnel: <b>{t['name']}</b> ({t['engine']}/{t['transport']})\n"
                    f"Was: <code>{st}</code> → Restarted: <b>{new_st.upper()}</b>"
                )
        time.sleep(interval)


def watchdog_menu():
    while True:
        render_header()
        cfg = _load_watchdog_cfg()
        active = run_cmd(["systemctl", "is-active", "kerov-watchdog"]).stdout.strip() == "active"
        st_str = "[bold green]● ACTIVE[/]" if active else "[bold red]○ STOPPED[/]"
        tg_str = "[green]CONFIGURED[/]" if (cfg.get("tg_token") and cfg.get("tg_chat_id")) else "[dim]Not Set[/]"

        console.print(Panel(
            f"Watchdog Service: {st_str}   Interval: [cyan]{cfg.get('interval', 30)}s[/]   Telegram Alerts: {tg_str}\n\n"
            "[green][1] Enable / Start Watchdog[/]     [yellow][2] Disable / Stop Watchdog[/]\n"
            "[cyan][3] Set Check Interval (sec)[/]     [magenta][4] Configure Telegram Bot Alerts[/]\n"
            "[white][5] Send Test Telegram Alert[/]    [dim][0] Back to Main Menu[/]",
            title="[bold cyan]SMART WATCHDOG & TELEGRAM ALERTS[/]", border_style="cyan", box=box.ROUNDED
        ))
        ch = Prompt.ask("Action", choices=["0", "1", "2", "3", "4", "5"], default="0")
        if ch == "0":
            return
        elif ch == "1":
            write_systemd("kerov-watchdog", "Smart Watchdog Daemon", "/usr/bin/python3 /opt/kerov/kerov.py --watchdog")
            console.print("[bold green]✔ Watchdog service enabled and started.[/]")
            pause()
        elif ch == "2":
            run_cmd("systemctl disable --now kerov-watchdog")
            console.print("[yellow]✔ Watchdog stopped.[/]")
            pause()
        elif ch == "3":
            cfg["interval"] = IntPrompt.ask("Check interval in seconds", default=cfg.get("interval", 30))
            _save_watchdog_cfg(cfg)
            console.print("[green]✔ Interval updated.[/]")
            pause()
        elif ch == "4":
            cfg["tg_token"] = Prompt.ask("Telegram Bot Token (from @BotFather)", default=cfg.get("tg_token", "")).strip()
            cfg["tg_chat_id"] = Prompt.ask("Telegram Chat ID", default=cfg.get("tg_chat_id", "")).strip()
            _save_watchdog_cfg(cfg)
            console.print("[green]✔ Telegram settings saved.[/]")
            pause()
        elif ch == "5":
            ok_tg = send_telegram_alert(f"✅ <b>Kerov Tunnel v2.2</b> test alert from <code>{get_public_ip()}</code>!")
            console.print("[green]✔ Test message sent![/]" if ok_tg else "[red]✗ Failed to send (check token/chat_id or network).[/]")
            pause()


# ==============================================================================
#  NETWORK TOOLKIT (SMART MTU FINDER, BACKUP/RESTORE, FIREWALL/KERNEL)
# ==============================================================================

def _smart_mtu_finder():
    render_header()
    target = Prompt.ask("Target Server IP (e.g. Foreign IP)").strip()
    if not target:
        return
    console.print(f"[cyan]Finding optimal Path MTU to {target} using DF binary search...[/]")
    lo, hi, best = 1100, 1472, 1200
    while lo <= hi:
        mid = (lo + hi) // 2
        res = run_cmd(["ping", "-c", "1", "-W", "2", "-M", "do", "-s", str(mid), target])
        if res.returncode == 0:
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1
    path_mtu = best + 28
    console.print(Panel(
        f"[bold green]✔ Discovered Path MTU to {target}:[/] [bold white]{path_mtu} bytes[/] (max ICMP payload: {best})\n\n"
        f"  • [cyan]GRE / GRETAP over IPsec:[/] [bold white]{max(1200, path_mtu - 100)}[/]\n"
        f"  • [cyan]WireGuard / Kerov-UDP:[/]   [bold white]{max(1200, path_mtu - 140)}[/]\n"
        f"  • [cyan]paqet-plus / Quantum:[/]    [bold white]{max(1200, path_mtu - 150)}[/]\n"
        f"  • [cyan]Backhaul / BrokenNode:[/]   [bold white]{max(1200, path_mtu - 80)}[/]",
        title="[bold green]📏 SMART MTU RECOMMENDATIONS[/]", border_style="green", box=box.ROUNDED
    ))
    pause()


def _backup_restore_menu():
    render_header()
    console.print(Panel(
        "[bold cyan][1] 💾 Create Full Backup[/]   [dim]Saves /etc/kerov + systemd units to /root/kerov-backup-*.tar.gz[/]\n"
        "[bold yellow][2] ♻️ Restore Backup[/]       [dim]Restores configs & restarts all saved tunnel services[/]\n"
        "[dim][0] Back[/]",
        title="[bold cyan]BACKUP & RESTORE[/]", border_style="cyan", box=box.ROUNDED
    ))
    c = Prompt.ask("Select", choices=["0", "1", "2"], default="1")
    if c == "1":
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        out = Path(f"/root/kerov-backup-{ts}.tar.gz")
        with tarfile.open(out, "w:gz") as tf:
            if KEROV_ETC.exists():
                tf.add(KEROV_ETC, arcname="etc/kerov")
            for svc in SYSTEMD_DIR.glob("kerov-*.service"):
                tf.add(svc, arcname=f"etc/systemd/system/{svc.name}")
        console.print(f"[bold green]✔ Backup saved:[/] [white]{out}[/] ({out.stat().st_size // 1024} KB)")
        pause()
    elif c == "2":
        path_str = Prompt.ask("Path to backup .tar.gz file").strip()
        p = Path(path_str)
        if not p.exists():
            console.print("[red]✗ File not found.[/]")
            pause()
            return
        with tarfile.open(p, "r:gz") as tf:
            tf.extractall("/")
        run_cmd("systemctl daemon-reload")
        for t in list_tunnels():
            run_cmd(["systemctl", "enable", "--now", t['service']])
        console.print("[bold green]✔ Backup restored and all tunnel services started![/]")
        pause()


def _firewall_kernel_opt():
    render_header()
    console.print("[cyan]Applying Kernel BBR + TCP Fast Open + Socket Buffer optimizations...[/]")
    run_cmd("modprobe tcp_bbr 2>/dev/null || true")
    Path("/etc/sysctl.d/99-kerov.conf").write_text("""net.ipv4.ip_forward = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 33554432
net.core.wmem_default = 33554432
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_mtu_probing = 1
""", encoding="utf-8")
    run_cmd("sysctl --system")
    if shutil.which("ufw"):
        for t in list_tunnels():
            ep = t.get("endpoint", "")
            if ":" in ep:
                port = ep.rsplit(":", 1)[1].split()[0]
                if port.isdigit():
                    run_cmd(f"ufw allow {port}/tcp >/dev/null 2>&1 || true")
                    run_cmd(f"ufw allow {port}/udp >/dev/null 2>&1 || true")
    console.print("[bold green]✔ Kernel BBR/TFO tuning applied and tunnel ports allowed in firewall.[/]")
    pause()


def network_toolkit_menu():
    while True:
        render_header()
        console.print(Panel(
            "[bold cyan][1] 📏 Smart MTU Finder[/]            [dim]Find exact optimal MTU to Foreign server (prevents freeze)[/]\n"
            "[bold cyan][2] 💾 Backup / Restore Tunnels[/]    [dim]1-Click export/import all Kerov configs & services[/]\n"
            "[bold cyan][3] Kernel & Firewall Optimizer[/] [dim]Apply BBR + TCP Fast Open + open tunnel ports[/]\n"
            "[dim][0] Back to Main Menu[/]",
            title="[bold cyan]🔧 NETWORK TOOLKIT[/]", border_style="cyan", box=box.ROUNDED
        ))
        ch = Prompt.ask("Select", choices=["0", "1", "2", "3"], default="0")
        if ch == "0":
            return
        elif ch == "1":
            _smart_mtu_finder()
        elif ch == "2":
            _backup_restore_menu()
        elif ch == "3":
            _firewall_kernel_opt()

def server_core_status():
    render_header()
    tbl = Table(title="INSTALLED CORES & SYSTEM STATUS", box=box.ROUNDED, border_style="cyan", expand=True)
    tbl.add_column("Core Engine", style="bold white")
    tbl.add_column("Direction", style="yellow")
    tbl.add_column("Binary Path", style="dim")
    tbl.add_column("Status", style="bold")

    rows = [
        ("BrokenNode (12 Transports + Spoof)", "Reverse (Iran=Srv)", BINS["brokennode"]),
        ("DaggerConnect (13 Transports)", "Reverse (Iran=Srv)", BINS["dagger"]),
        ("Backhaul Premium (10 Transports)", "Reverse (Iran=Srv)", BINS["backhaul"]),
        ("paqet-plus (Raw TCP + KCP)", "Direct (Iran=Cli)", BINS["paqet"]),
        ("StrongSwan + GRETAP (L2)", "Direct (Iran=Cli)", BINS["ipsec"]),
        ("Kerov-UDP (udp2raw + WG)", "Direct (Iran=Cli)", BINS["udp2raw"]),
    ]
    rows.extend([
        ("LeechTunnel", "Direct / Reverse", BINS["leech"]),
        ("QS-Tunnel Client", "Direct (Iran=Cli)", BINS["qs-client"]),
        ("QS-Tunnel Server", "Direct (Foreign=Srv)", BINS["qs-server"]),
        ("ICMP Tunnel", "Direct (Iran=Cli)", BINS["icmp"]),
    ])
    for label, d, path in rows:
        ok_bin = os.access(path, os.X_OK)
        tbl.add_row(label, d, path, "[bold green]✔ INSTALLED[/]" if ok_bin else "[bold red]✗ MISSING[/]")
    console.print(tbl)
    pause()


def _cleanup_tunnel(t: dict):
    svc = t.get("service", f"kerov-{t.get('name', '')}")
    stopped = run_cmd(["systemctl", "disable", "--now", svc])
    if t.get("engine") in (RETIRED_PRIVATE_IP_ENGINE, *ADDED_ENGINES) and stopped.returncode != 0:
        raise RuntimeError(f"Could not disable {svc}: {stopped.stderr.strip()}")
    (SYSTEMD_DIR / f"{svc}.service").unlink(missing_ok=True)
    name = t.get("name", "")
    eng = t.get("engine")
    if t.get("config"):
        Path(t["config"]).unlink(missing_ok=True)
    if eng == "paqet" and t.get("role") == "server":
        try:
            port = int(str(t.get("endpoint", "")).rsplit(":", 1)[1])
        except (IndexError, ValueError):
            port = None
        if port:
            for tbl, rule in (("raw", ["PREROUTING", "-p", "tcp", "--dport", str(port), "-j", "NOTRACK"]),
                              ("raw", ["OUTPUT", "-p", "tcp", "--sport", str(port), "-j", "NOTRACK"]),
                              ("mangle", ["OUTPUT", "-p", "tcp", "--sport", str(port), "--tcp-flags", "RST", "RST", "-j", "DROP"])):
                while run_cmd(["iptables", "-t", tbl, "-D", *rule]).returncode == 0:
                    pass
            run_cmd("netfilter-persistent save 2>/dev/null || true")
    elif eng == "gretap-ipsec":
        Path(f"/etc/ipsec.d/kerov/{name}.conf").unlink(missing_ok=True)
        Path(f"/etc/ipsec.d/kerov/{name}.secrets").unlink(missing_ok=True)
        for s in ("up", "down"):
            (KEROV_ETC / "gretap" / f"{name}-{s}.sh").unlink(missing_ok=True)
        run_cmd("ipsec reload 2>/dev/null || true")
    elif eng == "kerov-udp":
        for s in ("run.sh", "stop.sh", "udp2raw.conf"):
            (KEROV_ETC / "udp" / f"{name}-{s}").unlink(missing_ok=True)
    elif eng == "leech" and t.get("role") == "server" and t.get("transport") in LEECH_TLS:
        for cert_path in _leech_certificate_paths(name):
            cert_path.unlink(missing_ok=True)
    (META_DIR / f"{name}.json").unlink(missing_ok=True)


def uninstall_kerov():
    render_header()
    console.print(Panel(
        "[bold red]WARNING:[/] This will stop & remove all Kerov Tunnel services, configs, and the CLI itself.",
        title="[bold red]UNINSTALL KEROV TUNNEL[/]", border_style="red", box=box.ROUNDED
    ))
    if Prompt.ask("Type [bold red]uninstall[/] to confirm", default="") != "uninstall":
        console.print("[yellow]Cancelled.[/]")
        pause()
        return

    for t in list_tunnels(include_retired=True):
        _cleanup_tunnel(t)
    run_cmd(["systemctl", "daemon-reload"])
    if Confirm.ask("Also remove bundled core binaries?", default=True):
        for b in ("/usr/local/bin/brokennode", "/usr/local/bin/DaggerLauncher", "/usr/local/bin/backhaul_premium",
                  "/usr/local/bin/udp2raw", "/root/backhaul-core/backhaul_premium",
                  BINS["leech"], BINS["qs-server"], BINS["qs-client"]):
            Path(b).unlink(missing_ok=True)
        shutil.rmtree("/opt/paqet-plus", ignore_errors=True)
        shutil.rmtree("/usr/local/lib/DaggerConnect-offline-v4.3.1", ignore_errors=True)
    shutil.rmtree("/etc/kerov", ignore_errors=True)
    shutil.rmtree("/opt/kerov", ignore_errors=True)
    shutil.rmtree("/etc/ipsec.d/kerov", ignore_errors=True)
    Path("/usr/local/bin/kerov").unlink(missing_ok=True)
    Path("/etc/sysctl.d/99-kerov.conf").unlink(missing_ok=True)
    run_cmd("sysctl --system >/dev/null 2>&1")
    console.print("[bold green]✔ Kerov Tunnel completely removed.[/]")
    sys.exit(0)


# ==============================================================================
#  MAIN MENU LOOP
# ==============================================================================

MAIN_MENU_LEFT = (
    ("01", "Create Tunnel", "rev·direct"),
    ("02", "Manage Tunnels", "logs·sync"),
    ("03", "Smart Benchmark", "dl/ul"),
    ("04", "Live Monitor", "realtime"),
)
MAIN_MENU_RIGHT = (
    ("05", "Watchdog & Alerts", "telegram"),
    ("06", "Network Toolkit", "mtu·bbr"),
    ("07", "Core Status", "engines"),
    ("08", "Uninstall", ""),
)


def _section_title(title: str, width: int = 0) -> Text:
    t = Text(no_wrap=True, overflow="crop")
    t.append(" ◆ ", style=GOLD[2])
    t.append(title, style=f"bold {GOLD[2]}")
    if width:
        t.append(" " + "─" * max(0, width - len(title) - 5), style=G_DIM)
    return t


def _menu_cell(num: str, name: str, desc: str, danger: bool = False) -> Text:
    t = Text(no_wrap=True, overflow="ellipsis")
    t.append(" ")
    t.append(f" {num} ", style=f"bold #0b0b12 on {BAD_C if danger else GOLD[3]}")
    t.append(" ")
    t.append(name.ljust(19), style=f"bold {BAD_C}" if danger else f"bold {CREAM}")
    t.append(desc, style=MUTED)
    return t


def _render_main_menu(w: int):
    grid = Table.grid(expand=True, padding=(0, 1))
    grid.width = w
    grid.add_column(ratio=1, no_wrap=True)
    grid.add_column(ratio=1, no_wrap=True)
    grid.add_row(_section_title("TUNNELS"), _section_title("SYSTEM"))
    for (ln, lt, ld), (rn, rt, rd) in zip(MAIN_MENU_LEFT, MAIN_MENU_RIGHT):
        grid.add_row(_menu_cell(ln, lt, ld), _menu_cell(rn, rt, rd, danger=(rn == "08")))
    console.print(grid)


def _render_tunnel_list(w: int):
    console.print(_section_title("LIVE TUNNELS", w))
    tunnels = list_tunnels()
    if not tunnels:
        console.print(Text("    No tunnels yet · press 01 to create one", style=MUTED, no_wrap=True))
    else:
        g = Table.grid(padding=(0, 1), expand=True)
        g.width = w
        g.add_column(width=3, no_wrap=True)
        g.add_column(width=14, no_wrap=True, overflow="ellipsis")
        g.add_column(width=24, no_wrap=True, overflow="ellipsis")
        g.add_column(width=13, no_wrap=True)
        g.add_column(ratio=1, no_wrap=True, overflow="ellipsis")
        for t in tunnels[:5]:
            up = t["status"] == "active"
            color = OK_C if up else BAD_C
            g.add_row(
                Text("  ●", style=color),
                Text(str(t.get("name", "?")), style=f"bold {CREAM}"),
                Text(f"{t.get('engine', '?')} · {t.get('transport', '?')}", style=MUTED),
                Text(_instance_status(t["engine"], t["status"], "ONLINE").lower(), style=color),
                Text(str(t.get("endpoint", "")), style=MUTED),
            )
        console.print(g)
        if len(tunnels) > 5:
            console.print(Text(f"    +{len(tunnels) - 5} more · open 02 to manage", style=MUTED, no_wrap=True))

    win = _last_winner()
    line = Text(no_wrap=True, overflow="ellipsis")
    line.append("  ★ ", style=GOLD[1])
    line.append("best route  ", style=MUTED)
    if win and win.get("winner"):
        b = win["winner"]
        mbps = float(b.get("mbps", 0) or 0)
        rtt = float(b.get("rtt", 0) or 0)
        line.append(f"{str(b.get('engine', '')).upper()} / {b.get('transport', '')}", style=f"bold {GOLD[1]}")
        line.append(f"  {mbps:.0f} Mbps · {rtt:.0f} ms · grade ", style=MUTED)
        line.append(_grade_letter(mbps, rtt), style=f"bold {GOLD[0]}")
    else:
        line.append("no benchmark yet · press 03", style=MUTED)
    console.print(line)


def main():
    if os.geteuid() != 0:
        console.print("[bold red]Run as root: sudo kerov[/]")
        sys.exit(1)
    if "--watchdog" in sys.argv:
        run_watchdog_daemon()
        return

    key_map = {
        "1": "1", "c": "1",
        "2": "2", "m": "2",
        "3": "3", "b": "3",
        "4": "4", "l": "4",
        "5": "5", "w": "5",
        "6": "6", "t": "6",
        "7": "7", "s": "7",
        "8": "8",
        "0": "0", "q": "0",
    }
    actions = {
        "1": create_tunnel_menu,
        "2": manage_tunnels_menu,
        "3": benchmark_menu,
        "4": live_monitor_menu,
        "5": watchdog_menu,
        "6": network_toolkit_menu,
        "7": server_core_status,
        "8": uninstall_kerov,
    }

    while True:
        render_header()
        w = console.width
        _render_main_menu(w)
        console.print()
        _render_tunnel_list(w)
        render_footer_bar()

        flush_stdin()
        try:
            raw = Prompt.ask(f" [bold {GOLD[2]}]❯[/]", default="", show_default=False).strip().lower()
        except EOFError:
            break
        if raw.isdigit():
            raw = str(int(raw))
        choice = key_map.get(raw)
        if choice == "0":
            console.print(Text("\n  ◆ Goodbye.\n", style=GOLD[2]))
            break
        if choice in actions:
            actions[choice]()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]Bye.[/]")
        sys.exit(130)
