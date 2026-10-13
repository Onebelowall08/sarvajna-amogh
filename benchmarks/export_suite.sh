#!/usr/bin/env bash
# Export one suite so every reported figure can be re-derived without the
# cluster. Read-only.
#   ./benchmarks/export_suite.sh S20261006-134605
set -euo pipefail
SUITE="${1:?usage: export_suite.sh <suite_id>}"
OUT="benchmarks/archive/${SUITE}"
mkdir -p "${OUT}"
chq() {
  kubectl exec -n sarvajna-infra deploy/clickhouse -- clickhouse-client \
    --user default --password amogh_secure_pwd --query "$1"
}
for t in detections ground_truth revocations; do
  chq "SHOW CREATE TABLE sarvajna.${t} FORMAT TSVRaw" > "${OUT}/${t}.schema.sql"
  chq "SELECT * FROM sarvajna.${t} WHERE run_id LIKE '${SUITE}\\_\\_%' FORMAT CSVWithNames" \
    | gzip -n > "${OUT}/${t}.csv.gz"
  echo "${t}: $(chq "SELECT count() FROM sarvajna.${t} WHERE run_id LIKE '${SUITE}\\_\\_%'") rows"
done

# The ledger is the authority for which cells are analysed, so an archive
# without it cannot be analysed at all. Its name carries a single underscore
# and is therefore missed by the per-cell glob below.
cp "benchmarks/diag/${SUITE}_ledger.json"    "${OUT}/" 2>/dev/null || \
  echo "WARNING: no ledger for ${SUITE}; the archive cannot be re-analysed" >&2
cp "benchmarks/diag/environment_${SUITE}.json" "${OUT}/" 2>/dev/null || true
cp benchmarks/diag/environment.json          "${OUT}/" 2>/dev/null || true

# This suite's workload data only. An unfiltered copy puts another suite's
# measurements into this archive, where nothing distinguishes them.
cp benchmarks/logs/${SUITE}__*_stats.csv         "${OUT}/" 2>/dev/null || true
cp benchmarks/logs/${SUITE}__*_stats_history.csv "${OUT}/" 2>/dev/null || true
cp benchmarks/logs/${SUITE}__*_locust.log        "${OUT}/" 2>/dev/null || true
cp benchmarks/diag/${SUITE}__*.json              "${OUT}/" 2>/dev/null || true
# Written with the run identifier as a suffix rather than a prefix, so it is
# not matched above. T7 cannot be regenerated without it.
cp benchmarks/diag/quarantine_${SUITE}__*.json   "${OUT}/" 2>/dev/null || true
cp benchmarks/diag/memory_*.json                 "${OUT}/" 2>/dev/null || true
cp benchmarks/diag/verification_*.json           "${OUT}/" 2>/dev/null || true
cp benchmarks/diag/preflight.json                "${OUT}/" 2>/dev/null || true
cp benchmarks/figures_final/_*.csv               "${OUT}/" 2>/dev/null || true
cp benchmarks/figures_final/_*.json              "${OUT}/" 2>/dev/null || true
cp benchmarks/tables/*.md                        "${OUT}/" 2>/dev/null || true
grep -h "${SUITE}" benchmarks/diag/manifest.jsonl > "${OUT}/manifest.jsonl" || true
( cd "${OUT}" && find . -type f ! -name SHA256SUMS -exec shasum -a 256 {} + > SHA256SUMS )
echo "Archive written to ${OUT}"
