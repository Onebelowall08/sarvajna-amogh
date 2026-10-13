#!/usr/bin/env bash
# Stand up the environment from nothing.
#
# WHAT IS RECORDED AND WHAT IS RECONSTRUCTED
# ------------------------------------------
# The chart versions below are taken from the environment manifest captured
# with suite S20261006-134605 and are exact: Cilium 1.20.1, Tetragon 1.7.1.
# The install flags are reconstructed from the observed cluster state rather
# than transcribed, because the original install predates the manifest.
#
# The acceptance test is therefore the verifier, not this script. Run
#     python benchmarks/verify_environment.py
# afterwards. It performs roughly eighty checks across twelve layers, the
# exact count varying with how many conditional checks apply, and is the
# specification of a usable environment; anything it passes will collect,
# however it was installed.
set -euo pipefail

CLUSTER="${CLUSTER:-sarvajna-cluster}"
CILIUM_VERSION="${CILIUM_VERSION:-1.20.1}"
TETRAGON_VERSION="${TETRAGON_VERSION:-1.7.1}"

step() { echo -e "\n\033[1m[$1]\033[0m $2"; }

step 1/9 "Cluster"
if ! k3d cluster list | grep -q "^${CLUSTER}"; then
  # flannel and the built-in network policy controller are disabled because
  # Cilium provides both. traefik and servicelb are disabled because nothing
  # here uses ingress, and both would otherwise compete for the node's ports.
  k3d cluster create --config cluster/k3d-config.yaml
else
  echo "cluster ${CLUSTER} exists"
fi
kubectl config use-context "k3d-${CLUSTER}"

step 2/9 "Cilium ${CILIUM_VERSION}"
# kube-proxy is left in place, so no kubeProxyReplacement and no
# k8sServiceHost are needed. Policy enforcement must end up in "default" mode,
# where an endpoint is unrestricted until a policy selects it; the verifier
# checks this at layer 7, because "never" would disable the quarantine tier
# silently while every other check still passed.
helm repo add cilium https://helm.cilium.io/ >/dev/null 2>&1 || true
helm repo update >/dev/null
helm upgrade -i cilium cilium/cilium --version "${CILIUM_VERSION}" \
  --namespace kube-system \
  --set operator.replicas=1
kubectl -n kube-system rollout status ds/cilium --timeout=300s

step 3/9 "Tetragon ${TETRAGON_VERSION}"
# The values file turns on process-environment capture, which is what carries
# the request identifier into the kernel event, and points the container
# runtime socket at k3s's containerd rather than the default path. Both are
# verified at layer 6.
helm upgrade -i tetragon cilium/tetragon --version "${TETRAGON_VERSION}" \
  --namespace kube-system -f ebpf/tetragon-values.yaml
kubectl -n kube-system rollout status ds/tetragon --timeout=300s

step 4/9 "Backing services"
kubectl apply -f pipeline/backing-services.yaml
for d in postgres clickhouse nats; do
  kubectl -n sarvajna-infra rollout status "deploy/${d}" --timeout=300s
done

step 5/9 "Schemas"
kubectl exec -n sarvajna-infra -i deploy/postgres -- \
  psql -U sarvajna -d sarvajna_db < pipeline/postgres-init.sql
kubectl exec -n sarvajna-infra -i deploy/clickhouse -- clickhouse-client \
  --user default --password amogh_secure_pwd --multiquery \
  < pipeline/clickhouse-init.sql

step 6/9 "Images"
docker build -t sarvajna-python-base:v2 pipeline/python-base/
docker build -t target-app:v2 app/
k3d image import sarvajna-python-base:v2 target-app:v2 -c "${CLUSTER}"

step 7/9 "Pipeline and application"
kubectl apply -f pipeline/vector/vector-deployment.yaml
kubectl apply -f stream/cep-engine.yaml
kubectl apply -f soar/worker/remediation-worker.yaml
kubectl apply -f app/deployment.yaml
kubectl apply -f ebpf/tetragon-policies.yaml
kubectl apply -f soar/cilium-quarantine-policy.yaml
kubectl -n sarvajna-infra rollout status ds/vector --timeout=300s
for d in sarvajna-cep soar-worker; do
  kubectl -n sarvajna-infra rollout status "deploy/${d}" --timeout=300s
done
kubectl -n default rollout status deploy/target-app --timeout=300s

step 8/9 "Objects"
./benchmarks/precreate_objects.sh

step 9/9 "Port-forwards"
# In restart loops, deliberately. The harness replaces the application pod
# during preflight, and a forward bound to the old pod dies with it. These must
# stay running for the whole campaign, in their own shells or under a process
# manager.
cat <<'EOF'

  Leave these running, one per shell:

    while true; do kubectl port-forward -n default svc/target-app 3501:3000 >/dev/null 2>&1; sleep 2; done
    while true; do kubectl port-forward -n sarvajna-infra svc/clickhouse 9000:9000 >/dev/null 2>&1; sleep 2; done
    while true; do kubectl port-forward -n sarvajna-infra svc/nats 4222:4222 >/dev/null 2>&1; sleep 2; done

  Then verify, which is the acceptance test:

    python benchmarks/verify_environment.py

EOF
