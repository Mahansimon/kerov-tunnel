#!/usr/bin/env bash
# ==============================================================================
#  Kerov Tunnel — 100% Offline Bundle Builder (Run on Foreign Server)
#  Downloads paqet-plus + udp2raw into cores/ and builds kerov-tunnel-full-offline.zip
# ==============================================================================
set -euo pipefail

C_C='\033[0;36m'; C_G='\033[0;32m'; C_Y='\033[1;33m'; C_R='\033[0;31m'; C_N='\033[0m'
ok()   { echo -e "${C_G}  [✔]${C_N} $*"; }
info() { echo -e "${C_C}  [•]${C_N} $*"; }
err()  { echo -e "${C_R}  [✗]${C_N} $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || err "Run as root: sudo bash make-offline-bundle.sh"

SRC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
CORES_DIR="$SRC_DIR/cores"
mkdir -p "$CORES_DIR"

command -v zip >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq zip curl jq tar gzip >/dev/null 2>&1; }

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64"; U2R_BIN="udp2raw_amd64" ;;
  aarch64|arm64) ARCH="arm64"; U2R_BIN="udp2raw_arm" ;;
  *) err "Unsupported arch: $(uname -m)" ;;
esac

info "Fetching latest paqet-plus ($ARCH)..."
TAG=$(curl -fsSL --connect-timeout 15 "https://api.github.com/repos/LivingG0D/paqet-plus/releases?per_page=1" | jq -r '.[0].tag_name' 2>/dev/null || true)
if [ -z "$TAG" ] || [ "$TAG" = "null" ]; then
  TAG=$(curl -fsS --connect-timeout 15 -o /dev/null -w '%{redirect_url}' "https://github.com/LivingG0D/paqet-plus/releases/latest" | sed -n 's#.*/releases/tag/##p')
fi
[ -n "$TAG" ] || err "Could not resolve paqet-plus release tag."
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
ASSET="paqet-plus-linux-${ARCH}-${TAG}.tar.gz"
curl -fL --connect-timeout 20 -o "$TMP/$ASSET" "https://github.com/LivingG0D/paqet-plus/releases/download/${TAG}/${ASSET}"
tar -xzf "$TMP/$ASSET" -C "$TMP"
PQ_BIN=$(find "$TMP" -maxdepth 2 -type f -name 'paqet*' | head -1)
[ -n "$PQ_BIN" ] || err "paqet-plus binary not found in archive."
install -m 0755 "$PQ_BIN" "$CORES_DIR/paqet-plus"
ok "Bundled paqet-plus ($TAG) -> cores/paqet-plus"

info "Fetching latest udp2raw ($ARCH)..."
curl -fL --connect-timeout 20 -o "$TMP/u2r.tar.gz" "https://github.com/wangyu-/udp2raw/releases/latest/download/udp2raw_binaries.tar.gz"
tar -xzf "$TMP/u2r.tar.gz" -C "$TMP"
[ -f "$TMP/$U2R_BIN" ] || err "$U2R_BIN not found in archive."
install -m 0755 "$TMP/$U2R_BIN" "$CORES_DIR/udp2raw"
ok "Bundled udp2raw -> cores/udp2raw"

OUT_ZIP="$(dirname "$SRC_DIR")/kerov-tunnel-full-offline.zip"
rm -f "$OUT_ZIP"
(cd "$(dirname "$SRC_DIR")" && zip -qr "$OUT_ZIP" "$(basename "$SRC_DIR")")
ok "100% Offline bundle created: $OUT_ZIP"

PUB_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)
echo ""
echo -e "${C_Y}  Now transfer $OUT_ZIP to your Iran server, or run this one-time HTTP server here:${C_N}"
echo -e "  ${C_C}  (cd $(dirname "$SRC_DIR") && python3 -m http.server 8899)${C_N}"
echo -e "${C_Y}  And on your IRAN server run:${C_N}"
echo -e "  ${C_G}  wget http://${PUB_IP}:8899/kerov-tunnel-full-offline.zip && unzip kerov-tunnel-full-offline.zip && cd kerov-tunnel && sudo bash kerov-install.sh${C_N}"
echo ""
