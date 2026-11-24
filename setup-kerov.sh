#!/usr/bin/env bash
set -euo pipefail

REPO='Mahansimon/kerov-tunnel'
BRANCH='main'
MODE="install"

for arg in "$@"; do
  case "$arg" in
    --offline|--bundle|offline|bundle) MODE="bundle" ;;
  esac
done

main() {
  workdir="$(mktemp -d)"
  trap 'rm -rf -- "$workdir"' EXIT
  out_dir="$(pwd -P)"

  curl -fsSL --retry 3 --connect-timeout 15 \
    "https://github.com/$REPO/archive/refs/heads/$BRANCH.tar.gz" \
    -o "$workdir/kerov.tar.gz"

  mkdir "$workdir/project"
  tar -xzf "$workdir/kerov.tar.gz" -C "$workdir/project" --strip-components=1

  if [[ ! -f "$workdir/project/kerov-install.sh" ||
        ! -f "$workdir/project/kerov.py" ||
        ! -d "$workdir/project/cores" ]]; then
    printf 'The GitHub archive is missing Kerov project files.\n' >&2
    exit 1
  fi

  if [[ "$MODE" == "bundle" ]]; then
    KEROV_OUT_DIR="$out_dir" bash "$workdir/project/make-offline-bundle.sh"
  else
    bash "$workdir/project/kerov-install.sh" </dev/tty
  fi
}

main
