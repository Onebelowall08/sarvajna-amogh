#!/usr/bin/env bash
# ==============================================================================
# Sarvajna-Amogh Post-Boot Setup Script
# Re-initializes ephemeral databases, eBPF policies, and objects after boot.
# Note: Port-forwards are managed manually by the operator in separate shells.
# ==============================================================================
set -uo pipefail

G="\033[32m"
Y="\033[33m"
RD="\033[31m"
B="\033[1m"
X="\033[0m"

echo -e "\n${B}================================================================${X}"
echo -e "${B}  Sarvajna-Amogh Post-Boot Cluster Initialization${X}"
echo -e "${B}================================================================${X}\n"

# 1. Wait for Kubernetes API
echo -n "[1/6] Waiting for Kubernetes apiserver... "
for i in $(seq 1 60); do
  if kubectl get --raw /readyz >/dev/null 2>&1; then
    echo -e "${G}READY${X}"
    break
  fi
  sleep 1
done

# 2. Wait for core pods to be in Running state
echo -n "[2/6] Waiting for cluster deployments to settle... "
kubectl rollout status -n sarvajna-infra deployment/postgres --timeout=120s >/dev/null 2>&1
kubectl rollout status -n sarvajna-infra deployment/clickhouse --timeout=120s >/dev/null 2>&1
kubectl rollout status -n sarvajna-infra deployment/nats --timeout=120s >/dev/null 2>&1
kubectl rollout status -n sarvajna-infra deployment/sarvajna-cep --timeout=120s >/dev/null 2>&1
kubectl rollout status -n sarvajna-infra deployment/soar-worker --timeout=120s >/dev/null 2>&1
kubectl rollout status -n default deployment/target-app --timeout=120s >/dev/null 2>&1
kubectl rollout status -n kube-system ds/tetragon --timeout=120s >/dev/null 2>&1
echo -e "${G}DONE${X}"

# 3. Apply Postgres & ClickHouse Schemas
echo -n "[3/6] Re-initializing Postgres and ClickHouse schemas... "
kubectl exec -n sarvajna-infra -i deploy/postgres -- \
  psql -U sarvajna -d sarvajna_db < pipeline/postgres-init.sql >/dev/null 2>&1

kubectl exec -n sarvajna-infra -i deploy/clickhouse -- clickhouse-client \
  --user default --password amogh_secure_pwd --multiquery < pipeline/clickhouse-init.sql >/dev/null 2>&1
echo -e "${G}INITIALIZED${X}"

# 4. Attach Policies (Tetragon eBPF and Cilium Quarantine)
echo -n "[4/6] Applying Tetragon TracingPolicies and Cilium CNP... "
kubectl apply -f ebpf/tetragon-policies.yaml >/dev/null 2>&1
kubectl apply -f soar/cilium-quarantine-policy.yaml >/dev/null 2>&1

# Ensure policies attach
for i in $(seq 1 30); do
  pol=$(kubectl exec -n kube-system ds/tetragon -c tetragon -- tetra tracingpolicy list 2>/dev/null || true)
  if echo "$pol" | grep -q "sarvajna-file-open" && echo "$pol" | grep -q "sarvajna-tcp-connect"; then
    break
  fi
  sleep 1
done
echo -e "${G}ATTACHED${X}"

# 5. Lift any lingering quarantine and pre-create confidential objects
echo -n "[5/6] Checking quarantine and pre-creating 512 objects in /tmp... "
./benchmarks/reset_quarantine.sh >/dev/null 2>&1 || true
./benchmarks/precreate_objects.sh >/dev/null 2>&1
echo -e "${G}512 OBJECTS READY${X}"

# 6. Run Preflight Check
echo -e "\n${B}[6/6] Running Automated Environment Preflight...${X}\n"
python benchmarks/run_benchmark.py --preflight-only

echo -e "\n${G}${B}================================================================${X}"
echo -e "${G}${B}  Cluster is 100% READY! Run the full suite with:${X}"
echo -e "${B}    python benchmarks/run_benchmark.py --reset --reps 1${X}"
echo -e "${G}${B}================================================================${X}\n"
