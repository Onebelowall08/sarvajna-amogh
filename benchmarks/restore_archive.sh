#!/usr/bin/env bash
# Restores an archived suite from benchmarks/archive/<SUITE_ID> into ClickHouse.
# Safe to run whether tables exist, are empty, or need to be created.
set -euo pipefail

SUITE="${1:-S20261006-134605}"
ARCHIVE_DIR="benchmarks/archive/${SUITE}"
CH_HOST="${CH_HOST:-127.0.0.1}"
CH_PORT="${CH_PORT:-9000}"
CH_USER="${CH_USER:-default}"
CH_PW="${CH_PW:-amogh_secure_pwd}"

if [ ! -d "${ARCHIVE_DIR}" ]; then
  echo "Error: Archive directory '${ARCHIVE_DIR}' not found." >&2
  exit 1
fi

echo "==> Restoring suite ${SUITE} into ClickHouse (${CH_HOST}:${CH_PORT})..."

ch_client() {
  clickhouse-client --host "${CH_HOST}" --port "${CH_PORT}" \
    --user "${CH_USER}" --password "${CH_PW}" "$@" 2>/dev/null || \
  docker run --rm -i --network host clickhouse/clickhouse-server:26.8.2.7 \
    clickhouse-client --host "${CH_HOST}" --port "${CH_PORT}" \
    --user "${CH_USER}" --password "${CH_PW}" "$@"
}

# 1. Ensure database exists
ch_client --query "CREATE DATABASE IF NOT EXISTS sarvajna;"

# 2. Re-create schemas (safe if tables already exist)
echo "--> Ensuring tables exist..."
for t in detections ground_truth revocations; do
  if [ -f "${ARCHIVE_DIR}/${t}.schema.sql" ]; then
    sed 's/CREATE TABLE/CREATE TABLE IF NOT EXISTS/' "${ARCHIVE_DIR}/${t}.schema.sql" | ch_client --multiquery 2>/dev/null || true
  fi
done

# 3. Stream gzipped CSVs directly into ClickHouse
for t in detections ground_truth revocations; do
  csv_gz="${ARCHIVE_DIR}/${t}.csv.gz"
  if [ -f "${csv_gz}" ]; then
    echo "--> Ingesting ${t} from ${csv_gz}..."
    gzip -dc "${csv_gz}" | ch_client --query "INSERT INTO sarvajna.${t} FORMAT CSVWithNames"
    count=$(ch_client --query "SELECT count() FROM sarvajna.${t} WHERE run_id LIKE '${SUITE}__%'")
    echo "    Ingested: ${count} rows"
  fi
done

# 4. Copy ledger and diagnostics back to benchmarks/diag if not present
mkdir -p benchmarks/diag
cp "${ARCHIVE_DIR}/${SUITE}_ledger.json" "benchmarks/diag/" 2>/dev/null || true
cp "${ARCHIVE_DIR}/"*__*.json "benchmarks/diag/" 2>/dev/null || true

echo "==> Archive ${SUITE} successfully restored into ClickHouse!"
