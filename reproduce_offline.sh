#!/usr/bin/env bash
# ==============================================================================
# One-Step Offline Reproduction for Suite S20261006-134605
# Spins up a throwaway ClickHouse container, imports the archive,
# and executes the exact analysis pipeline. Requires only Docker & Python.
# ==============================================================================
set -euo pipefail

SUITE="S20261006-134605"
CH_CONTAINER="sarvajna-clickhouse-reproduce"

echo "================================================================="
echo "  Sarvajna-Amogh: Offline Analysis Reproduction (${SUITE})"
echo "================================================================="

# 1. Start ClickHouse in Docker if port 9000 is not already responding
if ! nc -z 127.0.0.1 9000 2>/dev/null; then
  echo "[1/4] Starting isolated ClickHouse container..."
  docker rm -f "${CH_CONTAINER}" >/dev/null 2>&1 || true
  docker run -d --name "${CH_CONTAINER}" \
    -p 9000:9000 -p 8123:8123 \
    -e CLICKHOUSE_PASSWORD="amogh_secure_pwd" \
    -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT="1" \
    clickhouse/clickhouse-server:26.8.2.7 >/dev/null

  echo "Waiting for ClickHouse to be healthy..."
  for i in $(seq 1 30); do
    if docker exec "${CH_CONTAINER}" clickhouse-client --password amogh_secure_pwd --query "SELECT 1" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
else
  echo "[1/4] Existing ClickHouse instance detected on port 9000."
fi

# 2. Ingest Archive
echo "[2/4] Loading archived data into ClickHouse..."
./benchmarks/restore_archive.sh "${SUITE}"

# 3. Run Analysis
echo "[3/4] Running offline analysis..."
python3 benchmarks/analyze.py --suite "${SUITE}"

# 4. Generate Tables
echo "[4/4] Generating markdown tables..."
python3 benchmarks/make_tables.py --suite "${SUITE}"

echo "================================================================="
echo " Reproduction Complete!"
echo " Results generated in: benchmarks/tables/results_${SUITE}.md"
echo " Figures generated in:  benchmarks/figures_final/"
echo "================================================================="
