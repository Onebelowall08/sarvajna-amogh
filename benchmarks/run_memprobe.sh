#!/usr/bin/env bash
set -euo pipefail

PG_POD=$(kubectl get pods -n sarvajna-infra -l app=postgres -o jsonpath='{.items[0].status.podIP}')
PG_SVC=$(kubectl get svc  -n sarvajna-infra postgres -o jsonpath='{.spec.clusterIP}')
CH_POD=$(kubectl get pods -n sarvajna-infra -l app=clickhouse -o jsonpath='{.items[0].status.podIP}')
NATS_POD=$(kubectl get pods -n sarvajna-infra -l app=nats -o jsonpath='{.items[0].status.podIP}')

echo "[1/4] Ensuring deployment environments are ready..."
kubectl set env -n sarvajna-infra deployment/sarvajna-cep \
  BENCHMARK_RUN_ID=MEMPROBE JOIN_MODE=deterministic \
  CORRELATION_WINDOW_MS=10000 PENDING_EXECVE_HORIZON_MS=10000 \
  IGNORE_DADDRS="${PG_POD},${PG_SVC}" >/dev/null
kubectl set env -n sarvajna-infra deployment/soar-worker \
  BENCHMARK_RUN_ID=MEMPROBE ENFORCE_REVOCATION=false TIER2_ENABLED=false >/dev/null
kubectl rollout status -n sarvajna-infra deployment/sarvajna-cep --timeout=120s >/dev/null
kubectl rollout status -n sarvajna-infra deployment/soar-worker  --timeout=120s >/dev/null

echo "[2/4] Starting Locust workload in background (40s)..."
( BENCHMARK_RUN_ID=MEMPROBE RUN_ADVERSARIAL=false CONFIDENTIAL_FILE_COUNT=512 \
  SSRF_TARGET_IP=$CH_POD SSRF_OPEN_PORT=8123 PREVIEW_ALLOWED_IP=$NATS_POD \
  PREVIEW_ALLOWED_PORT=4222 \
  locust -f benchmarks/locust/locustfile.py --headless --users 10 \
    --spawn-rate 10 --run-time 40s --host http://localhost:3501 \
    --exit-code-on-error 0 --stop-timeout 10 </dev/null >/dev/null 2>&1 ) &
LOCUST_PID=$!

echo "[3/4] Waiting 25s for sustained peak load..."
sleep 25

echo "[4/4] Taking non-reclaimable working set snapshot..."
./benchmarks/measure_memory.sh under_load

echo "Waiting for Locust to conclude..."
wait $LOCUST_PID 2>/dev/null || true

echo "Cleaning up throwaway MEMPROBE rows..."
for t in detections revocations; do
  kubectl exec -n sarvajna-infra deploy/clickhouse -- clickhouse-client \
    --user default --password amogh_secure_pwd \
    --query "ALTER TABLE sarvajna.${t} DELETE WHERE run_id='MEMPROBE'" >/dev/null 2>&1 || true
done
echo "Completed successfully!"
