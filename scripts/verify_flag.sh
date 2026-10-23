#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -f out/flag.txt ]]; then
  echo "FAIL: out/flag.txt does not exist." >&2
  exit 1
fi

expected="$(docker exec php2shell-vulnerable cat /flag)"
actual="$(tr -d '\r\n' < out/flag.txt)"
if [[ "$actual" == "$expected" ]]; then
  echo "CHALLENGE_SOLVED=yes"
  echo "The proof file matches the flag without displaying it."
else
  echo "CHALLENGE_SOLVED=no (proof does not match /flag)" >&2
  exit 1
fi

