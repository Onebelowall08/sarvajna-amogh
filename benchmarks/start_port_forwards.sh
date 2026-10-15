#!/usr/bin/env bash
# Runs all 3 required Kubernetes port-forwards in background watchdog loops.
set -euo pipefail

echo "Starting background port-forwards (Ctrl+C to terminate)..."

trap 'kill $(jobs -p) 2>/dev/null || true' EXIT

( while true; do kubectl port-forward -n default svc/target-app 3501:3000 >/dev/null 2>&1 || true; sleep 2; done ) &
( while true; do kubectl port-forward -n sarvajna-infra svc/clickhouse 9000:9000 >/dev/null 2>&1 || true; sleep 2; done ) &
( while true; do kubectl port-forward -n sarvajna-infra svc/nats 4222:4222 >/dev/null 2>&1 || true; sleep 2; done ) &

echo "Port-forwards active:"
echo "  - target-app: http://localhost:3501"
echo "  - clickhouse: localhost:9000"
echo "  - nats:       localhost:4222"
wait
