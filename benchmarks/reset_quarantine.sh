#!/usr/bin/env bash
# Remove the quarantine label and wait for the datapath to converge.
set -uo pipefail

APP_IP=$(kubectl get pods -n default -l app=target-app \
         -o jsonpath='{.items[0].status.podIP}' 2>/dev/null || true)
CIL=$(kubectl get pods -n kube-system -l k8s-app=cilium \
      -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

before=$(kubectl get pods -n default -l app=target-app \
  -o jsonpath='{range .items[*]}{.metadata.labels.quarantine}{"\n"}{end}' 2>/dev/null \
  | grep -c 'true' || true)

kubectl label pod -n default -l app=target-app quarantine- --overwrite >/dev/null 2>&1 || true

if [ "${before:-0}" -eq 0 ]; then
  echo "[BENCHMARK] No quarantine label present; nothing to lift."
  exit 0
fi

if [ -z "$APP_IP" ] || [ -z "$CIL" ]; then
  echo "[BENCHMARK] Quarantine label removed on ${before} pod(s); convergence NOT"
  echo "            verified: could not resolve the pod or agent address."
  exit 1
fi

missing=0
for i in $(seq 1 60); do
  # -wF: fixed string, and the match may not be flanked by a digit. A plain
  # grep for 10.42.0.11 also matches 10.42.0.115, and here a wrong match on an
  # endpoint that is not enforced would report convergence immediately. The
  # next cell would then begin collecting against a still-isolated pod, which
  # is the failure this script exists to prevent.
  line=$(kubectl exec -n kube-system "$CIL" -c cilium-agent -- \
         cilium-dbg endpoint list 2>/dev/null | grep -wF "$APP_IP" | head -1)
  if [ -z "$line" ]; then
    missing=$((missing+1))
  else
    missing=0
    if ! echo "$line" | grep -q "Enabled"; then
      echo "[BENCHMARK] Quarantine lifted on ${before} pod(s); datapath converged after $((i*2))s."
      exit 0
    fi
  fi
  if [ "$missing" -ge 10 ]; then
    echo "[BENCHMARK] ERROR: the agent has not reported an endpoint for ${APP_IP} in"
    echo "            20s. Enforcement state is unknown, which is not the same as"
    echo "            lifted. Refusing to report convergence."
    exit 1
  fi
  sleep 2
done

echo "[BENCHMARK] WARNING: endpoint still reports policy enforcement 120s after the"
echo "            label was removed. A cell started now would collect against an"
echo "            isolated pod."
exit 1
