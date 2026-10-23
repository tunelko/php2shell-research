#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

aslr="$(cat /proc/sys/kernel/randomize_va_space)"
echo "HOST_ASLR=randomize_va_space:${aslr}"
if [[ "$aslr" != "2" ]]; then
  echo "WARNING: ASLR is not fully enabled; expected randomize_va_space=2." >&2
fi

for spec in "vulnerable:8426" "patched:8427"; do
  role="${spec%%:*}"
  port="${spec##*:}"
  echo "--- ${role} @ 127.0.0.1:${port} ---"
  body=""
  for attempt in $(seq 1 30); do
    if body="$(curl --fail --silent --show-error "http://127.0.0.1:${port}/version.php" 2>/dev/null)"; then
      break
    fi
    sleep 1
  done
  if [[ -z "$body" ]]; then
    echo "FAIL: ${role} did not become ready" >&2
    exit 1
  fi
  printf '%s\n' "$body"
  base="$(docker compose -f challenge/compose/local.yml exec -T "$role" sh -c 'pid=$(ps -eo pid=,user=,comm= | awk '\''$2=="root" && $3=="apache2" {print $1; exit}'\''); grep -m1 "/libphp.so" "/proc/${pid}/maps" | cut -d"-" -f1' || true)"
  if [[ -n "$base" ]]; then
    echo "LIBPHP_BASE=${base}"
  else
    echo "LIBPHP_BASE=<not found in parent process maps>"
  fi
done

before="$(docker compose -f challenge/compose/local.yml exec -T vulnerable sh -c 'pid=$(ps -eo pid=,user=,comm= | awk '\''$2=="root" && $3=="apache2" {print $1; exit}'\''); grep -m1 "/libphp.so" "/proc/${pid}/maps" | cut -d"-" -f1' || true)"
if [[ -n "$before" ]]; then
  docker compose -f challenge/compose/local.yml restart vulnerable >/dev/null
  sleep 1
  after="$(docker compose -f challenge/compose/local.yml exec -T vulnerable sh -c 'pid=$(ps -eo pid=,user=,comm= | awk '\''$2=="root" && $3=="apache2" {print $1; exit}'\''); grep -m1 "/libphp.so" "/proc/${pid}/maps" | cut -d"-" -f1' || true)"
  if [[ "$before" != "$after" ]]; then
    echo "ASLR_CHECK=base changed after restart (${before} -> ${after})"
  else
    echo "ASLR_CHECK=base did not change; this can happen occasionally, but verify the kernel setting."
  fi
fi

echo "LAB_CHECK=completed"

