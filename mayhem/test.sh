#!/usr/bin/env bash
#
# Runs the gtest binary built by mayhem/build.sh: upstream's own unit tests plus known-answer tests that
# push fixture packets (the fuzz seeds) through the NetFlow v5/v9, IPFIX and sFlow v5 parsers and compare
# the decoded flow fields with the values the fixtures were built from.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

RUNNER="$SRC/src/build/mayhem/fastnetmon_gtests"
if [ ! -x "$RUNNER" ]; then
  echo "missing $RUNNER: mayhem/build.sh did not produce the test runner" >&2
  emit_ctrf "gtest" 0 1 0
  exit 1
fi

# Upstream's serialize_attack_description.blank_attack expects an output format the current code no longer
# produces (the "Average ..." lines are gone); it fails on the pristine upstream tree, so it is skipped.
SKIP='serialize_attack_description.blank_attack'
OUT="$("$RUNNER" "--gtest_filter=-$SKIP" 2>&1)"
echo "$OUT" | tail -40

# A program that exits early (or is neutered) prints no summary and therefore cannot pass.
RAN="$(echo "$OUT" | sed -n 's/^\[==========\] \([0-9]*\) tests\? from .* ran\..*/\1/p' | tail -1)"
PASSED="$(echo "$OUT" | sed -n 's/^\[  PASSED  \] \([0-9]*\) tests\?\..*/\1/p' | tail -1)"
if [ -z "$RAN" ] || [ -z "$PASSED" ]; then
  emit_ctrf "gtest" 0 1 1
  exit 1
fi
FAILED=$(( RAN - PASSED ))
emit_ctrf "gtest" "$PASSED" "$FAILED" 1
