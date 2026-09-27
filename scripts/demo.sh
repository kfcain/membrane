#!/usr/bin/env bash
# End-to-end demo. It needs opa on PATH. It uses a fresh var/ directory.
# The demo mixes live gateway evidence with fixture cluster evidence, so the
# check run uses --allow-nonlive. The output is a demonstration, not an assessment.
set -euo pipefail
cd "$(dirname "$0")/.."
PORT="${MEMBRANE_DEMO_PORT:-8750}"
export MEMBRANE_GATEWAY_URL="http://127.0.0.1:${PORT}"
export MEMBRANE_EVIDENCE_DIR="${PWD}/var/evidence"
export MEMBRANE_STATE_DIR="${PWD}/var/state"
rm -rf var && mkdir -p var

echo "== 1. Validate manifests and run the CI policy gate"
membrane validate
conftest test --no-color --policy policy/ci --namespace membrane.ci registry/agents/*.yaml | tail -1

echo "== 2. Generate enforcement config and check for drift"
membrane gen --check

echo "== 3. Start the reference gateway"
membrane gateway serve --port "$PORT" > var/gateway.log 2>&1 &
GW=$!
trap 'kill $GW 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do curl -sf "$MEMBRANE_GATEWAY_URL/healthz" >/dev/null && break; sleep 0.1; done

echo "== 4. Send agent traffic through the gateway"
python scripts/demo_traffic.py

echo "== 5. Run the canary negative tests"
membrane canary run

echo "== 6. Run a kill drill on ticket-triager"
membrane drill kill ticket-triager --sla 300

echo "== 7. Run the checks (demo mode: live gateway evidence plus fixture cluster evidence)"
membrane checks run --allow-nonlive --evidence var/evidence --evidence fixtures/evidence --out out/assessment
echo
echo "Report: out/assessment/report.md"
echo "OSCAL:  out/assessment/assessment-results.oscal.json"
