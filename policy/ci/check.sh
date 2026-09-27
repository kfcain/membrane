#!/usr/bin/env bash
# Prove the CI gate. Every registry manifest must PASS.
# Every file in testdata/bad must FAIL with the message on its "# expect:" line.
# Run from the repo root: policy/ci/check.sh
set -euo pipefail

cd "$(dirname "$0")/../.."
CONFTEST="${CONFTEST_BIN:-conftest}"
POLICY=policy/ci
NS=membrane.ci
rc=0

echo "== registry (expect PASS)"
if "$CONFTEST" test --no-color --policy "$POLICY" --namespace "$NS" registry/agents/*.yaml; then
  echo "PASS registry"
else
  echo "FAIL registry: a registry manifest did not pass the CI gate"
  rc=1
fi

echo "== testdata/bad (expect FAIL)"
for f in "$POLICY"/testdata/bad/*.yaml; do
  expect="$(sed -n 's/^# expect: //p' "$f" | head -n 1)"
  if [ -z "$expect" ]; then
    echo "FAIL $f: no '# expect:' line"
    rc=1
    continue
  fi
  set +e
  out="$("$CONFTEST" test --no-color --policy "$POLICY" --namespace "$NS" "$f" 2>&1)"
  status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    echo "FAIL $f: conftest passed a bad manifest"
    rc=1
  elif ! grep -qF -- "$expect" <<<"$out"; then
    echo "FAIL $f: denied, but not with: $expect"
    echo "$out"
    rc=1
  else
    echo "PASS $f denied: $expect"
  fi
done

exit "$rc"
