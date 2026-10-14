#!/bin/sh
# Run the test suite with coverage and fail if total statement coverage is below the minimum.
# Usage: scripts/coverage-gate.sh [profile]   (env COVERAGE_MIN, default 90.0)
set -eu
min="${COVERAGE_MIN:-90.0}"
profile="${1:-coverage.out}"
go test -coverprofile="$profile" ./...
go tool cover -func="$profile" | tail -1
total=$(go tool cover -func="$profile" | awk '$1 == "total:" { sub(/%$/, "", $NF); print $NF }')
if [ -z "$total" ]; then
  echo "coverage gate: could not read total from $profile" >&2
  exit 1
fi
awk -v t="$total" -v min="$min" 'BEGIN {
  if (t + 0 < min + 0) { printf "coverage gate: FAIL total %.1f%% < %.1f%%\n", t, min; exit 1 }
  printf "coverage gate: OK total %.1f%% >= %.1f%%\n", t, min
}'
