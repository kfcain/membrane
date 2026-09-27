#!/usr/bin/env bash
# Run the Kyverno test suite and fail on any expectation mismatch.
#
# Kyverno CLI 1.14.1 counts a row that wants "fail" and gets "pass" as a PASS.
# The row still shows "Want fail, got pass" in its reason column. This script
# treats any "Want ..., got ..." row, and any "Excluded" row, as a failure.
# Run from the repo root: policy/admission/kyverno/check.sh
set -euo pipefail

cd "$(dirname "$0")/../../.."
KYVERNO="${KYVERNO_BIN:-kyverno}"

set +e
out="$("$KYVERNO" test --remove-color --require-tests policy/admission/kyverno 2>&1)"
status=$?
set -e

echo "$out"

if [ "$status" -ne 0 ]; then
  echo "FAIL: kyverno test returned $status"
  exit 1
fi
if grep -qE 'Want [a-z]+, got [a-z]+' <<<"$out"; then
  echo "FAIL: at least one result does not match its expectation (see 'Want ..., got ...' rows)"
  exit 1
fi
if grep -q 'Excluded' <<<"$out"; then
  echo "FAIL: at least one expected result names a resource that the rule does not match"
  exit 1
fi
if ! grep -qE 'Test Summary: [0-9]+ tests passed and 0 tests failed' <<<"$out"; then
  echo "FAIL: no clean test summary"
  exit 1
fi
echo "PASS: every Kyverno result matches its expectation"
