#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

docker compose -f challenge/compose/local.yml down --remove-orphans
find runtime/out -mindepth 1 -not -name .gitkeep -delete
echo "LAB_RESET=completed"

