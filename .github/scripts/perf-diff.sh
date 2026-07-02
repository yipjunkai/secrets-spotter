#!/usr/bin/env bash
#
# Compare two criterion baselines and fail if any benchmark regressed beyond a
# threshold. Reads target/criterion/<bench>/<baseline>/estimates.json and
# compares the mean point estimate of <new> against <base>.
#
# Usage: perf-diff.sh <base-baseline> <new-baseline> <threshold-fraction>
#   e.g. perf-diff.sh base head 0.10   # fail if <new> is >10% slower than <base>
#
# Bootstrap-tolerant, but fail-closed: if no <base> baselines exist AND the
# caller set PERF_BOOTSTRAP=1 (the base ref genuinely predates the bench), print
# a notice and exit 0 — comparisons begin next PR. Missing baselines WITHOUT
# that signal mean the base bench failed to produce output, so exit 1 rather
# than passing an uncompared run (the old unconditional exit 0 failed open).
set -euo pipefail

BASE_NAME=${1:?usage: perf-diff.sh <base> <new> <threshold>}
NEW_NAME=${2:?usage: perf-diff.sh <base> <new> <threshold>}
THRESHOLD=${3:?usage: perf-diff.sh <base> <new> <threshold>}

ROOT="target/criterion"
if [ ! -d "$ROOT" ]; then
  echo "::error::$ROOT not found; nothing to compare"
  exit 1
fi

ceiling_pct=$(jq -rn --argjson t "$THRESHOLD" '$t * 100')
compared=0
skipped=0
failures=0

# Iterate every benchmark that produced a <new> baseline.
while IFS= read -r new_est; do
  bench_dir=$(dirname "$(dirname "$new_est")")
  rel=${bench_dir#"$ROOT/"}
  base_est="$bench_dir/$BASE_NAME/estimates.json"

  if [ ! -f "$base_est" ]; then
    echo "::notice::skip ${rel} (no '${BASE_NAME}' baseline)"
    skipped=$((skipped + 1))
    continue
  fi

  base_mean=$(jq -r '.mean.point_estimate' "$base_est")
  new_mean=$(jq -r '.mean.point_estimate' "$new_est")

  # Percent change and pass/fail, computed in jq to stay float-safe.
  result=$(jq -rn --argjson b "$base_mean" --argjson n "$new_mean" --argjson t "$THRESHOLD" \
    'if $b > 0 then (($n - $b) / $b) as $c | "\($c * 100) \($c > $t)" else "0 false" end')
  pct=${result% *}
  regressed=${result#* }
  compared=$((compared + 1))

  printf '  %-44s %12.1f -> %12.1f ns  (%+.2f%%)\n' "$rel" "$base_mean" "$new_mean" "$pct"
  if [ "$regressed" = "true" ]; then
    echo "::error::${rel} regressed by $(printf '%+.2f' "$pct")% (ceiling ${ceiling_pct}%)"
    failures=$((failures + 1))
  fi
done < <(find "$ROOT" -path "*/${NEW_NAME}/estimates.json" | sort)

echo ""
echo "compared ${compared} benchmark(s), skipped ${skipped}."

if [ "$compared" -eq 0 ]; then
  # No base baselines to compare against. Legitimate ONLY on the first PR that
  # introduces the bench (base ref lacks benches/scan.rs), which the base-bench
  # step signals via PERF_BOOTSTRAP=1. Any other cause — the base-ref bench
  # crashed/flaked under continue-on-error and wrote no baselines — must NOT
  # pass silently, or the gate fails open and greens an uncompared change.
  if [ "${PERF_BOOTSTRAP:-}" = "1" ]; then
    echo "::notice::no comparable baselines (base ref predates the bench harness); bootstrap run, nothing to gate."
    exit 0
  fi
  echo "::error::no comparable baselines, but this is not a bootstrap run — the base-ref benchmark produced no baselines (it likely failed or was skipped). Refusing to green the perf gate on an uncompared change; re-run the job."
  exit 1
fi
if [ "$failures" -gt 0 ]; then
  echo "::error::${failures} benchmark(s) exceeded the ${ceiling_pct}% regression ceiling."
  exit 1
fi
echo "all ${compared} benchmark(s) within the ${ceiling_pct}% regression ceiling."
