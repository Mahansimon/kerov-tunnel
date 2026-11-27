#!/usr/bin/env bash
# ==============================================================================
#  Kerov Tunnel v2.3.14 — All-in-One Installer (10 Engines • Offline-First • Ubuntu 22+)
# ==============================================================================
set -euo pipefail

C_C='\033[1;37m'; C_M='\033[1;31m'; C_G='\033[1;37m'; C_Y='\033[1;33m'; C_R='\033[0;31m'; C_N='\033[0m'
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

cli_only=false
ctunnel_core_only=false
offline=false
icmp_core=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --cli-only) cli_only=true ;;
    --offline) offline=true ;;
    --ctunnel-core-only) ctunnel_core_only=true ; offline=true ;;
    --icmp-core)
      [ "$#" -ge 2 ] || err "--icmp-core requires a path to the authorized Linux amd64 binary."
      icmp_core="$2"
      shift
      ;;
    *) err "Usage: sudo bash kerov-install.sh [--cli-only | --offline | --ctunnel-core-only] [--icmp-core /path/to/ICMPTunnel-linux-amd64]" ;;
  esac
  shift
done
if [ -n "$icmp_core" ] && [ ! -f "$icmp_core" ]; then
  err "ICMP core file not found: $icmp_core"
fi

install_brokennode_core() {
  local source="$CORES_DIR/brokennode-linux-amd64" target=/usr/local/bin/brokennode staging
  case "$(uname -m)" in
    x86_64|amd64)
      if [ ! -f "$source" ]; then
        [ -x "$target" ] || warn "Bundled BrokenNode amd64 core not found."
        return 0
      fi
      staging="$(mktemp /usr/local/bin/.brokennode.XXXXXX)"
      if ! install -m 0755 "$source" "$staging" || ! mv -f "$staging" "$target"; then
        rm -f -- "$staging"
        err "Could not install BrokenNode."
      fi
      ok "BrokenNode core installed from the bundle (amd64)."
      ;;
    *) warn "Bundled BrokenNode core requires Linux amd64." ;;
  esac
}

install_paqet_core() {
  local arch source target=/opt/paqet-plus/paqet-plus staging
  case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) warn "No bundled paqet-plus core for this architecture."; return 0 ;;
  esac
  source="paqet-plus-linux-$arch"
  if [ ! -f "$CORES_DIR/$source" ]; then
    [ -x "$target" ] && return 0
    err "Bundled paqet-plus core missing: cores/$source"
  fi
  (cd "$CORES_DIR" && awk -v binary="$source" '$2 == binary {print}' paqet-plus-SHA256SUMS | sha256sum -c --status) ||
    err "Bundled paqet-plus checksum mismatch: $source"
  install -d -m 0755 /opt/paqet-plus
  staging="$(mktemp /opt/paqet-plus/.paqet-plus.XXXXXX)"
  if ! install -m 0755 "$CORES_DIR/$source" "$staging" || ! mv -f "$staging" "$target"; then
    rm -f -- "$staging"
    err "Could not install paqet-plus."
  fi
  ok "paqet-plus core installed from the bundle ($arch)."
}

install_added_cores() {
  case "$(uname -m)" in
    x86_64|amd64) ;;
    *)
      [ -z "$icmp_core" ] || err "The selected ICMP core requires Linux amd64."
      warn "LeechTunnel, QS-Tunnel and ICMPTunnel builds require amd64."
      return 0
      ;;
  esac
  local core_dir=/usr/local/lib/kerov/cores source target staging
  install -d -m 0755 "$core_dir"
  while read -r source target; do
    if [ -f "$CORES_DIR/$source" ]; then
      staging="$(mktemp "$core_dir/.$target.XXXXXX")"
      if ! install -m 0755 "$CORES_DIR/$source" "$staging" || ! mv -f "$staging" "$core_dir/$target"; then
        rm -f -- "$staging"
        err "Could not install $target."
      fi
      ok "$target core installed from the bundle."
    elif [ ! -x "$core_dir/$target" ]; then
      warn "Bundled $source not found."
    fi
  done <<'EOF'
leech-linux-amd64 leech
qs-client-linux-amd64 qs-client
qs-server-linux-amd64 qs-server
EOF
  install_icmp_core "$core_dir"
}

install_icmp_core() {
  local core_dir="$1" source="$icmp_core" staging header machine
  local target="$1/ICMPTunnel"
  local release_url="https://github.com/Qteam-official/ICMPTunnel/releases/download/v1.1.0/ICMPTunnel-linux-amd64"
  local release_sha256="4cb34a6d0faf9292d1dc21b01fbeb1e1b176d2d4c728422934b7a1944d772c77"

  if [ -z "$source" ]; then
    if [ -x "$target" ]; then
      ok "ICMP Tunnel core already installed."
      return
    fi
    if [ -x /usr/local/bin/ICMPTunnel ]; then
      source=/usr/local/bin/ICMPTunnel
    elif [ "$offline" = true ]; then
      warn "ICMP Tunnel core unavailable locally. Pass --icmp-core to install it offline."
      return
    elif ! command -v curl >/dev/null 2>&1; then
      warn "ICMP Tunnel download needs curl. For offline installation, pass --icmp-core."
      return
    fi
  fi

  staging="$(mktemp "$core_dir/.ICMPTunnel.XXXXXX")"
  if [ -n "$source" ]; then
    if ! install -m 0600 -- "$source" "$staging"; then
      rm -f -- "$staging"
      err "Could not read the ICMP core: $source"
    fi
  else
    info "Downloading ICMPTunnel v1.1.0 from Q-TEAM..."
    if ! curl -q -fsSL --proto '=https' --proto-redir '=https' \
      --connect-timeout 10 --max-time 30 -o "$staging" "$release_url"; then
      rm -f -- "$staging"
      warn "Could not reach the official ICMP release. For offline installation, pass --icmp-core."
      return
    fi
    if ! printf '%s  %s\n' "$release_sha256" "$staging" | sha256sum --check --status; then
      rm -f -- "$staging"
      warn "ICMP release checksum mismatch. For offline installation, pass --icmp-core."
      return
    fi
  fi

  header="$(od -An -tx1 -N6 -- "$staging" | tr -d '[:space:]')"
  machine="$(od -An -tx1 -j18 -N2 -- "$staging" | tr -d '[:space:]')"
  if [ "$header" != 7f454c460201 ] || [ "$machine" != 3e00 ]; then
    rm -f -- "$staging"
    err "ICMP core must be a Linux amd64 ELF executable."
  fi
  if ! chmod 0755 -- "$staging" || ! mv -f -- "$staging" "$target"; then
    rm -f -- "$staging"
    err "Could not install the ICMP core."
  fi
  ok "ICMP Tunnel core installed."
}

install_ctunnel_core() (
  local arch work_dir asset line stage source target mode changed=false
  local release="https://github.com/CIAUB/C-Tunnel/releases/download/v2.1.0"
  case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    armv7l|armv7|armv8l|armhf) arch=armv7 ;;
    *) err "C-Tunnel has no Linux binary for $(uname -m)." ;;
  esac
  local -a assets=("ctunnel-linux-$arch" "ctunnel-engine-linux-$arch" "ctunnel-kernel.sh"
    "ctunnel@.service" "ctunnel-engine@.service" "ctunnel-agent.service")
  work_dir="$(mktemp -d)"
  trap 'rm -rf -- "$work_dir"' EXIT
  info "Verifying official C-Tunnel v2.1.0 assets..."
  for asset in SHA256SUMS "${assets[@]}"; do
    if [ -f "$CORES_DIR/ctunnel/$asset" ]; then
      cp -- "$CORES_DIR/ctunnel/$asset" "$work_dir/$asset"
    elif [ "$offline" = true ]; then
      err "Missing bundled C-Tunnel asset: $asset. Extract the complete ZIP."
    elif ! command -v curl >/dev/null 2>&1 || ! curl -q -fsSL --proto '=https' --proto-redir '=https' \
      --connect-timeout 8 --max-time 45 -o "$work_dir/$asset" "$release/$asset"; then
      err "C-Tunnel asset unavailable: $asset. Extract the complete ZIP or rerun when GitHub is reachable."
    fi
    if [ "$asset" = SHA256SUMS ]; then
      if ! printf '%s  %s\n' a419de427a28ca4af4c59416e8af772744a6e9c98cff1d0c9119d9b1b05817b3 "$work_dir/$asset" | sha256sum -c --status; then
        err "C-Tunnel release manifest checksum mismatch."
      fi
    else
      line="$(awk -v name="$asset" '$2 == name {print $1}' "$work_dir/SHA256SUMS")"
      if ! printf '%s  %s\n' "$line" "$work_dir/$asset" | sha256sum -c --status; then
        err "C-Tunnel asset checksum mismatch: $asset"
      fi
    fi
  done
  install -d -m 0755 /usr/local/lib/ctunnel
  install -d -m 0700 /etc/ctunnel /etc/ctunnel/tunnels
  while read -r source target mode; do
    source="${source//ARCH/$arch}"
    if cmp -s -- "$work_dir/$source" "$target" && [ "$(stat -c %a -- "$target")" = "${mode#0}" ]; then
      continue
    fi
    stage="$(mktemp "$(dirname "$target")/.kerov-ctunnel.XXXXXX")"
    if ! install -m "$mode" "$work_dir/$source" "$stage" || ! mv -f -- "$stage" "$target"; then
      rm -f -- "$stage"
      err "Could not install C-Tunnel asset: $source"
    fi
    changed=true
  done <<'EOF'
ctunnel-linux-ARCH /usr/local/bin/ctunnel 0755
ctunnel-engine-linux-ARCH /usr/local/bin/ctunnel-engine 0755
ctunnel-kernel.sh /usr/local/lib/ctunnel/ctunnel-kernel 0755
ctunnel@.service /etc/systemd/system/ctunnel@.service 0644
ctunnel-engine@.service /etc/systemd/system/ctunnel-engine@.service 0644
ctunnel-agent.service /etc/systemd/system/ctunnel-agent.service 0644
EOF
  if [ "$changed" = true ]; then
    systemctl daemon-reload || warn "Reload systemd on this host before creating C-Tunnel tunnels."
    ok "C-Tunnel v2.1.0 core installed."
  else
    ok "C-Tunnel v2.1.0 core already installed."
  fi
)

install_dagger_and_backhaul() {
  local glibc_version runtime
  case "$(uname -m)" in
    x86_64|amd64) ;;
    *) warn "Bundled DaggerConnect and Backhaul cores require Linux amd64."; return 0 ;;
  esac
  if [ -f "$CORES_DIR/DaggerConnect" ]; then
    glibc_version=$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')
    if python3 -c 'import sys; v=tuple(map(int,sys.argv[1].split("."))); sys.exit(0 if v>=(2,34) else 1)' "${glibc_version:-2.35}"; then
      install -m 0755 "$CORES_DIR/DaggerConnect" /usr/local/bin/DaggerLauncher
    elif [ -f "$CORES_DIR/runtime.tar.gz" ]; then
      runtime="/usr/local/lib/DaggerConnect-offline-v4.3.1"
      mkdir -p "$runtime/lib"
      tar -xzf "$CORES_DIR/runtime.tar.gz" -C "$runtime/lib"
      install -m 0755 "$CORES_DIR/DaggerConnect" "$runtime/DaggerConnect"
      printf '#!/bin/sh\nexec "%s/lib/ld-linux-x86-64.so.2" --library-path "%s/lib" "%s/DaggerConnect" "$@"\n' "$runtime" "$runtime" "$runtime" > /usr/local/bin/DaggerLauncher
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

  if [ -f "$CORES_DIR/backhaul_premium" ]; then
    install -m 0755 "$CORES_DIR/backhaul_premium" /usr/local/bin/backhaul_premium
    install -d -m 0755 /root/backhaul-core
    ln -sf /usr/local/bin/backhaul_premium /root/backhaul-core/backhaul_premium
    ok "Backhaul Premium core installed (offline)."
  elif [ -x /usr/local/bin/backhaul_premium ]; then
    ok "Backhaul Premium core already installed."
  else
    warn "Bundled backhaul_premium not found."
  fi
}

install_local_udp2raw() {
  local target=/usr/local/bin/udp2raw staging
  if [ -f "$CORES_DIR/udp2raw" ]; then
    staging="$(mktemp /usr/local/bin/.udp2raw.XXXXXX)"
    if ! install -m 0755 "$CORES_DIR/udp2raw" "$staging" || ! mv -f "$staging" "$target"; then
      rm -f -- "$staging"
      err "Could not install udp2raw."
    fi
    ok "udp2raw core installed from the bundle."
  elif [ -x "$target" ]; then
    ok "udp2raw core already installed."
  else
    return 1
  fi
}

install_cli() {
  install -d "$KEROV_DIR"
  install -m 0755 "$SRC_DIR/kerov.py" "$KEROV_DIR/kerov.py"
  ln -sf "$KEROV_DIR/kerov.py" /usr/local/bin/kerov
  ok "Kerov Tunnel v2.3.14 installed! Launch anytime with: sudo kerov"
}

if [ "$ctunnel_core_only" = true ]; then
  command -v systemctl >/dev/null 2>&1 || err "Required command not found: systemctl"
  install_ctunnel_core
  exit 0
fi

if [ "$cli_only" = true ] || [ "$offline" = true ]; then
  for dependency in python3 ip systemctl; do
    command -v "$dependency" >/dev/null 2>&1 || err "Required command not found: $dependency"
  done
  PYTHONPATH="$KEROV_DIR" python3 -c 'import rich, yaml, psutil' 2>/dev/null ||
    err "Install the Kerov Python dependencies (rich, PyYAML and psutil) before using --cli-only. See README.md."
  install_ctunnel_core
  install_brokennode_core
  install_dagger_and_backhaul
  install_paqet_core
  install_local_udp2raw || warn "For Kerov-UDP, install udp2raw or include it in cores/udp2raw before running --offline."
  install_added_cores
  install_cli
  exit 0
fi
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
      All-in-One Installer v2.3.14
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

# 5) udp2raw (offline-first -> fallback to GitHub)
if install_local_udp2raw; then
  :
else
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

# 7) Install additional engines and the Kerov CLI
install_brokennode_core
install_dagger_and_backhaul
install_paqet_core
install_added_cores
install_ctunnel_core
install_cli
echo ""
if [ -t 0 ]; then exec /usr/local/bin/kerov; fi
