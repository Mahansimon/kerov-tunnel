#!/usr/bin/env bash
# ==============================================================================
#  Kerov Tunnel v2.2.2 — All-in-One Installer (6 Cores • Offline-First • Ubuntu 22+)
# ==============================================================================
set -euo pipefail

C_C='\033[0;36m'; C_M='\033[0;35m'; C_G='\033[0;32m'; C_Y='\033[1;33m'; C_R='\033[0;31m'; C_N='\033[0m'
ok()   { echo -e "${C_G}  [✔]${C_N} $*"; }
info() { echo -e "${C_C}  [•]${C_N} $*"; }
warn() { echo -e "${C_Y}  [!]${C_N} $*"; }
err()  { echo -e "${C_R}  [✗]${C_N} $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || err "Run as root: sudo bash kerov-install.sh"

if [ -r /etc/os-release ]; then
  . /etc/os-release
  [ "${ID:-}" = "ubuntu" ] || [ "${ID_LIKE:-}" = "debian" ] || [ "${ID:-}" = "debian" ] || warn "Untested OS: ${PRETTY_NAME:-unknown}. Ubuntu 22.04+ is recommended."
fi
SRC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
CORES_DIR="$SRC_DIR/cores"
KEROV_DIR="/opt/kerov"
KEROV_ETC="/etc/kerov"

install_cli() {
  install -d "$KEROV_DIR"
  install -m 0755 "$SRC_DIR/kerov.py" "$KEROV_DIR/kerov.py"
  ln -sf "$KEROV_DIR/kerov.py" /usr/local/bin/kerov
  ok "Kerov Tunnel v2.2.2 installed! Launch anytime with: sudo kerov"
}

if [ "${1:-}" = "--cli-only" ]; then
  for dependency in python3 ip systemctl flock; do
    command -v "$dependency" >/dev/null 2>&1 || err "Required command not found: $dependency"
  done
  PYTHONPATH="$KEROV_DIR" python3 -c 'import rich, yaml, psutil' 2>/dev/null ||
    err "Install the Kerov Python dependencies (rich, PyYAML and psutil) before using --cli-only. See README.md."
  install_cli
  exit 0
fi
[ "$#" -eq 0 ] || err "Usage: sudo bash kerov-install.sh [--cli-only]"
command -v apt-get >/dev/null 2>&1 || err "apt-get not found. Ubuntu/Debian is required."

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) err "Unsupported architecture: $(uname -m)" ;;
esac

echo -e "${C_M}"
cat <<'EOF'
  ╦╔═╔═╗╦═╗╔═╗╦  ╦  ╔╦╗╦ ╦╔╗╔╔╗╔╔═╗╦
  ╠╩╗║╣ ╠╦╝║ ║╚╗╔╝   ║ ║ ║║║║║║║║╣ ║
  ╩ ╩╚═╝╩╚═╚═╝ ╚╝    ╩ ╚═╝╝╚╝╝╚╝╚═╝╩═╝
      All-in-One Installer v2.2.2
EOF
echo -e "${C_N}"

info "Installing system dependencies..."
export DEBIAN_FRONTEND=noninteractive
echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections 2>/dev/null || true
echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections 2>/dev/null || true

apt-get update -qq
apt-get install -y -qq -o DPkg::Lock::Timeout=300 \
  python3 python3-pip python3-rich python3-yaml python3-psutil \
  curl wget jq tar gzip unzip ca-certificates openssl iproute2 iputils-ping \
  iptables iptables-persistent libpcap-dev libpcap0.8 \
  strongswan strongswan-pki wireguard-tools socat nano >/dev/null 2>&1 || \
apt-get install -y -qq -o DPkg::Lock::Timeout=300 \
  python3 python3-pip curl wget jq tar gzip unzip ca-certificates openssl iproute2 \
  iputils-ping iptables libpcap-dev strongswan wireguard-tools socat nano

python3 -c "import rich, yaml, psutil" 2>/dev/null || \
  pip3 install --break-system-packages -q rich pyyaml psutil 2>/dev/null || \
  pip3 install -q rich pyyaml psutil

mkdir -p "$KEROV_DIR" "$KEROV_ETC"/{brokennode,backhaul,paqet,dagger,gretap,udp,tls,meta} /etc/brokennode /etc/DaggerConnect /opt/paqet-plus /root/backhaul-core
ok "System packages & directories ready."

# 1) BrokenNode (offline bundled)
if [ -f "$CORES_DIR/brokennode-linux-$ARCH" ]; then
  install -m 0755 "$CORES_DIR/brokennode-linux-$ARCH" /usr/local/bin/brokennode
  ok "BrokenNode core installed (offline)."
elif [ -x /usr/local/bin/brokennode ]; then
  ok "BrokenNode core already installed."
else
  warn "Bundled brokennode-linux-$ARCH not found."
fi

# 2) DaggerConnect offline v4.3.1 (offline bundled)
if [ -f "$CORES_DIR/DaggerConnect" ]; then
  GLIBC_VER=$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')
  if python3 -c 'import sys; v=tuple(map(int,sys.argv[1].split("."))); sys.exit(0 if v>=(2,34) else 1)' "${GLIBC_VER:-2.35}"; then
    install -m 0755 "$CORES_DIR/DaggerConnect" /usr/local/bin/DaggerLauncher
  elif [ -f "$CORES_DIR/runtime.tar.gz" ]; then
    RT="/usr/local/lib/DaggerConnect-offline-v4.3.1"
    mkdir -p "$RT/lib"
    tar -xzf "$CORES_DIR/runtime.tar.gz" -C "$RT/lib"
    install -m 0755 "$CORES_DIR/DaggerConnect" "$RT/DaggerConnect"
    printf '#!/bin/sh\nexec "%s/lib/ld-linux-x86-64.so.2" --library-path "%s/lib" "%s/DaggerConnect" "$@"\n' "$RT" "$RT" "$RT" > /usr/local/bin/DaggerLauncher
    chmod 0755 /usr/local/bin/DaggerLauncher
  else
    install -m 0755 "$CORES_DIR/DaggerConnect" /usr/local/bin/DaggerLauncher
  fi
  ok "DaggerConnect core installed (offline)."
elif [ -x /usr/local/bin/DaggerLauncher ]; then
  ok "DaggerConnect core already installed."
else
  warn "Bundled DaggerConnect not found."
fi

# 3) Backhaul Premium (offline bundled)
if [ -f "$CORES_DIR/backhaul_premium" ]; then
  install -m 0755 "$CORES_DIR/backhaul_premium" /usr/local/bin/backhaul_premium
  ln -sf /usr/local/bin/backhaul_premium /root/backhaul-core/backhaul_premium
  ok "Backhaul Premium core installed (offline)."
elif [ -x /usr/local/bin/backhaul_premium ]; then
  ok "Backhaul Premium core already installed."
else
  warn "Bundled backhaul_premium not found."
fi

# 4) paqet-plus (offline-first -> fallback to GitHub)
if [ -f "$CORES_DIR/paqet-plus" ]; then
  install -m 0755 "$CORES_DIR/paqet-plus" /opt/paqet-plus/paqet-plus
  ok "paqet-plus core installed (offline)."
elif [ ! -x /opt/paqet-plus/paqet-plus ]; then
  info "Downloading latest paqet-plus from GitHub..."
  TAG=$(curl -fsSL --connect-timeout 10 "https://api.github.com/repos/LivingG0D/paqet-plus/releases?per_page=1" | jq -r '.[0].tag_name' 2>/dev/null || true)
  if [ -z "$TAG" ] || [ "$TAG" = "null" ]; then
    TAG=$(curl -fsS --connect-timeout 10 -o /dev/null -w '%{redirect_url}' "https://github.com/LivingG0D/paqet-plus/releases/latest" 2>/dev/null | sed -n 's#.*/releases/tag/##p' || true)
  fi
  if [ -n "$TAG" ]; then
    TMP=$(mktemp -d)
    ASSET="paqet-plus-linux-${ARCH}-${TAG}.tar.gz"
    if curl -fsSL --connect-timeout 15 -o "$TMP/$ASSET" "https://github.com/LivingG0D/paqet-plus/releases/download/${TAG}/${ASSET}" 2>/dev/null; then
      tar -xzf "$TMP/$ASSET" -C "$TMP" 2>/dev/null || true
      BIN=$(find "$TMP" -maxdepth 2 -type f -name 'paqet*' | head -1)
      [ -n "$BIN" ] && install -m 0755 "$BIN" /opt/paqet-plus/paqet-plus && ok "paqet-plus ($TAG) installed."
    else
      warn "Could not download paqet-plus (GitHub blocked?)."
    fi
    rm -rf "$TMP"
  else
    warn "Could not reach GitHub for paqet-plus."
  fi
else
  ok "paqet-plus already installed."
fi

# 5) udp2raw (offline-first -> fallback to GitHub)
if [ -f "$CORES_DIR/udp2raw" ]; then
  install -m 0755 "$CORES_DIR/udp2raw" /usr/local/bin/udp2raw
  ok "udp2raw core installed (offline)."
elif [ ! -x /usr/local/bin/udp2raw ]; then
  info "Downloading udp2raw (FakeTCP engine) from GitHub..."
  TMP=$(mktemp -d)
  [ "$ARCH" = "amd64" ] && U2R_BIN="udp2raw_amd64" || U2R_BIN="udp2raw_arm"
  if curl -fsSL --connect-timeout 15 -o "$TMP/u2r.tar.gz" "https://github.com/wangyu-/udp2raw/releases/latest/download/udp2raw_binaries.tar.gz" 2>/dev/null; then
    tar -xzf "$TMP/u2r.tar.gz" -C "$TMP" 2>/dev/null || true
    [ -f "$TMP/$U2R_BIN" ] && install -m 0755 "$TMP/$U2R_BIN" /usr/local/bin/udp2raw && ok "udp2raw installed."
  else
    warn "Could not download udp2raw (GitHub blocked?)."
  fi
  rm -rf "$TMP"
else
  ok "udp2raw already installed."
fi

# 6) Kernel BBR & forwarding tuning
modprobe tcp_bbr 2>/dev/null || true
cat > /etc/sysctl.d/99-kerov.conf <<'EOF'
net.ipv4.ip_forward = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 33554432
net.core.wmem_default = 33554432
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_mtu_probing = 1
EOF
sysctl --system >/dev/null 2>&1 || true

# 7) Install Kerov CLI
install_cli
echo ""
if [ -t 0 ]; then exec /usr/local/bin/kerov; fi
