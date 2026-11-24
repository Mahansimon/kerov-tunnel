#!/usr/bin/env bash
set -euo pipefail

REPO='Mahansimon/kerov-tunnel'
BRANCH='main'

main() {
  if [[ "$REPO" == Mahansimon/* ]]; then
    printf 'Set REPO to your GitHub owner and repository in setup-kerov.sh.\n' >&2
    exit 1
  fi

  workdir=""
  workdir="$(mktemp -d)"
  trap 'rm -rf -- "$workdir"' EXIT

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

  # Bash reads this launcher from the pipe. Kerov reads input from the terminal.
  bash "$workdir/project/kerov-install.sh" </dev/tty
}

main
