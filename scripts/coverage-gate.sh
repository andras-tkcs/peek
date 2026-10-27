#!/bin/sh
# Run the test suite with coverage and fail if total or per-package statement coverage is below the minimums.
# Usage: scripts/coverage-gate.sh [profile]
# Env: COVERAGE_MIN (total, default 95.0), COVERAGE_PACKAGE_MIN (per package, default 93.0),
#      COVERAGE_PACKAGES (space-separated, default "internal/server internal/db internal/objectstore")
set -eu
min="${COVERAGE_MIN:-95.0}"
pkg_min="${COVERAGE_PACKAGE_MIN:-93.0}"
packages="${COVERAGE_PACKAGES:-internal/server internal/db internal/objectstore}"
profile="${1:-coverage.out}"
go test -coverprofile="$profile" ./...
go tool cover -func="$profile" | tail -1
total=$(go tool cover -func="$profile" | awk '$1 == "total:" { sub(/%$/, "", $NF); print $NF }')
if [ -z "$total" ]; then
  echo "coverage gate: could not read total from $profile" >&2
  exit 1
fi
failed=0
awk -v t="$total" -v min="$min" 'BEGIN {
  if (t + 0 < min + 0) { printf "coverage gate: FAIL total %.1f%% < %.1f%%\n", t, min; exit 1 }
  printf "coverage gate: OK total %.1f%% >= %.1f%%\n", t, min
}' || failed=1
module=$(go list -m)
for p in $packages; do
  awk -v pkg="$module/$p" -v name="$p" -v min="$pkg_min" -v profile="$profile" '
    NR > 1 { split($1, a, ":"); f = a[1]; sub(/\/[^\/]*$/, "", f); if (f == pkg) { n += $2; if ($3 > 0) c += $2 } }
    END {
      if (n == 0) { printf "coverage gate: FAIL %s has no statements in %s\n", name, profile; exit 1 }
      pct = 100 * c / n
      if (pct < min + 0) { printf "coverage gate: FAIL %s %.1f%% < %.1f%%\n", name, pct, min; exit 1 }
      printf "coverage gate: OK %s %.1f%% >= %.1f%%\n", name, pct, min
    }' "$profile" || failed=1
done
exit "$failed"
