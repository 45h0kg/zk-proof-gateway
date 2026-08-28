#!/usr/bin/env bash
# Full reproduction pipeline for the ZK Proof Gateway prototype.
# Runs every experiment in the paper and writes a timestamped log plus
# fresh artifacts into results/.
#
# Usage:  bash experiments/run_all.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG="$ROOT/results/execution_log.txt"
mkdir -p "$ROOT/results"

stage() { echo; echo "--- $1 ---"; date -u '+start: %H:%M:%S.%3N UTC'; }

{
echo "==============================================================="
echo " ZK PROOF GATEWAY - FULL REPRODUCTION RUN"
echo " $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "==============================================================="
echo "--- ENVIRONMENT ---"
uname -a
grep 'model name' /proc/cpuinfo | head -1 || true
echo "vCPUs: $(nproc)"
grep MemTotal /proc/meminfo || true
python3 --version

stage "STAGE 0: GOVERNANCE WORKFLOW (keygen, sign predicate, verify)"
cd "$ROOT/python"
rm -rf /tmp/zkgw_keys /tmp/zkgw_registry
python3 governance_cli.py keygen --out /tmp/zkgw_keys/governance
python3 governance_cli.py define --id pretrade_notional_cap --version 1 \
  --type range_leq --cap 1000000000 --nbits 32 --unit USD_cents \
  --owner risk-governance-team --key /tmp/zkgw_keys/governance.secret \
  --out /tmp/zkgw_registry
python3 governance_cli.py list --dir /tmp/zkgw_registry --pub /tmp/zkgw_keys/governance.pub
echo "stage 0 exit: $?"

stage "STAGE 1: ADVERSARIAL SOUNDNESS SUITE (11 checks)"
python3 tests_soundness.py
echo "stage 1 exit: $?"

stage "STAGE 2: END-TO-END TRADING DEMO"
python3 demo_trading.py
echo "stage 2 exit: $?"

stage "STAGE 3: PYTHON ENGINE + E2E BENCHMARKS"
python3 bench.py
echo "stage 3 exit: $?"

stage "STAGE 4: RUST BULLETPROOFS BUILD + BENCH"
cd "$ROOT/rust/zkrp"
if [ ! -x target/release/zkrp ]; then cargo build --release 2>&1 | tail -3; fi
./target/release/zkrp bench | tee "$ROOT/results/bulletproofs_bench.json"
echo "stage 4 exit: $?"

stage "STAGE 5: RUST ADVERSARIAL CHECKS (range_leq: cap 1000000000, 32 bits)"
OUT=$(./target/release/zkrp prove 32 1000000000 735000000 ctxA)
PROOF=$(echo "$OUT" | grep -o '"proof_hex": "[^"]*"' | cut -d'"' -f4)
COMMIT=$(echo "$OUT" | grep -o '"commit_v_hex": "[^"]*"' | cut -d'"' -f4)
echo -n "valid proof:        "; ./target/release/zkrp verify 32 1000000000 "$PROOF" "$COMMIT" ctxA
TAMP="ff${PROOF:2}"
echo -n "tampered proof:     "; ./target/release/zkrp verify 32 1000000000 "$TAMP" "$COMMIT" ctxA
echo -n "wrong context:      "; ./target/release/zkrp verify 32 1000000000 "$PROOF" "$COMMIT" ctxB
echo -n "cap lowered at verify: "; ./target/release/zkrp verify 32 100000000 "$PROOF" "$COMMIT" ctxA
echo -n "honest prover refuses over-cap value (\$12.5M > \$1B cap): "
./target/release/zkrp prove 32 1000000000 1250000000 ctxC
echo "(nonzero exit above is expected -- the prover must refuse)"

stage "STAGE 6: AGENTIC PROTOCOL E2E (zk-attach/v0 over JSON-RPC, Python E1 engine)"
cd "$ROOT/python"
python3 verify_e2e.py
echo "stage 6 exit: $?"

stage "STAGE 7: AGENTIC PROTOCOL E2E (Go gateway + Go prover, Rust Bulletproofs E2 engine)"
cd "$ROOT/go"
go build -o /tmp/zkgw-gateway-service ./gatewayservice
go build -o /tmp/zkgw-prover-service ./proverservice
ZKGW_SOURCE_VALUE=735000000 /tmp/zkgw-prover-service --port 8793 \
  --zkrp-bin "$ROOT/rust/zkrp/target/release/zkrp" > /tmp/zkgw-prover-service.log 2>&1 &
PROVER_PID=$!
sleep 1
cd "$ROOT/python"
ZKGW_PROVER_URL=http://127.0.0.1:8793 \
ZKGW_GATEWAY_CMD="/tmp/zkgw-gateway-service --zkrp-bin $ROOT/rust/zkrp/target/release/zkrp" \
  python3 verify_e2e.py
STAGE7_EXIT=$?
kill "$PROVER_PID" 2>/dev/null
echo "stage 7 exit: $STAGE7_EXIT"

echo
echo "=== RUN COMPLETE: $(date -u '+%Y-%m-%d %H:%M:%S UTC') ==="
} 2>&1 | tee "$LOG"

echo
echo "log written to: $LOG"
