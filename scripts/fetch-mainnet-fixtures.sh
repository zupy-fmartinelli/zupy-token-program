#!/usr/bin/env bash
# Fetch READ-ONLY mainnet fixtures for tests/test_mainnet_fork.rs (story 3.21).
#
# Dumps the real Light Protocol + Token-2022 programs and the accounts the
# client-spend CPI touches, so the fork test runs our program against the
# SAME binaries that run on mainnet. Nothing is signed or sent.
#
#   scripts/fetch-mainnet-fixtures.sh [RPC_URL]
#   cargo build-sbf --no-default-features --features mainnet
#   SBF_OUT_DIR=target/deploy cargo test --test test_mainnet_fork -- --ignored --test-threads=1
#
# Output: tests/fixtures/mainnet/{programs/<id>.so, accounts/<pk>.bin + <pk>.meta}
# (gitignored — ~4.5 MB, re-fetch to refresh). Writes SHA256SUMS for the record.
set -euo pipefail

RPC="${1:-https://api.mainnet-beta.solana.com}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/tests/fixtures/mainnet"
mkdir -p "$OUT/programs" "$OUT/accounts"

PROGRAMS=(
  cTokenmWW8bLPjZEBAUgYy3zKxQZW6VKi7bqNFEVv3m   # Light compressed token (cToken)
  SySTEM1eSU2p4BGQfQpimFEWWSC1XDFeun3Nqzz3rT7   # Light system program
  compr6CUsB5m2jS4Y3831ztGSTnDpnKJTKS95d64XVq   # Account compression
  noopb9bkMVfRPU8AsbpTUg8AQkHtKwMYZiFUjNRtMmV   # SPL noop
  TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb   # Token-2022
)
ACCOUNTS=(
  ZUPYxKLjfRyRmoF6j8Su8D3aTDkB4k4uqXLqHn8wcao   # ZUPY mint (Token-2022)
  6UNF7ECPmEmKrvgpH6abi6XcGmSASvJU9vaDjGgzMVYP   # token_state PDA
  GXtd2izAiMJPwMEjfgTRH3d7k9mjn4Jq3JrWFv9gySYy   # cToken cpi_authority PDA
  35hkDgaAKwMCaxRz2ocSZ6NaUrtKkyNqU6c4RV3tYJRh   # registered_program_pda (Light system)
  bmt1LryLZUMmF7ZtqESaw7wifBXLfXHQYoE4GAmrahU   # V2 batched state tree
  oq1na8gojfdUhsfCpyjNt6h4JaDWtHf1yQj4koBWfto   # V2 output queue of bmt1
  E7JkVUvoGjv1MAJAPgJ7Vh8NnGC5kAHYd1Sndzyb2fYM   # cToken SPL interface pool for ZUPY
)

for p in "${PROGRAMS[@]}"; do
  solana program dump -u "$RPC" "$p" "$OUT/programs/$p.so" >/dev/null
  sleep 1
done

for a in "${ACCOUNTS[@]}"; do
  solana account -u "$RPC" "$a" --output json-compact --output-file "$OUT/accounts/$a.json" >/dev/null
  python3 - "$OUT/accounts/$a.json" "$OUT/accounts/$a" <<'PY'
import base64, json, sys
src, dst = sys.argv[1], sys.argv[2]
acc = json.load(open(src))["account"]
open(dst + ".bin", "wb").write(base64.b64decode(acc["data"][0]))
open(dst + ".meta", "w").write(f'{acc["owner"]} {acc["lamports"]} {str(acc["executable"]).lower()}\n')
PY
  rm -f "$OUT/accounts/$a.json"
  sleep 1
done

( cd "$OUT" && sha256sum programs/*.so accounts/*.bin > SHA256SUMS )
echo "fixtures in $OUT"
cat "$OUT/SHA256SUMS"
