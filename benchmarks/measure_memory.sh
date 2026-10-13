#!/usr/bin/env bash
# Non-reclaimable working set per component, with its reclaimable cache
# alongside, written to the diagnostics directory so the figure has a source.
#
# The harness records memory.peak, which is a high-water mark since the
# container started and counts page cache. It rises monotonically whatever the
# load: measured 5,128 MiB climbing to 6,492 MiB across eleven cells on a host
# that never showed that memory as used. The anon figure below is the part that
# cannot be reclaimed, and it is the only one that should be quoted as a cost.
#
# Read-only. Safe to run at any time.
set -uo pipefail
OUT="benchmarks/diag/memory_$(date -u +%Y%m%d_%H%M%S).json"
mkdir -p benchmarks/diag

read_one() {
  local ns="$1" sel="$2" extra="${3:-}"
  local pod
  pod=$(kubectl get pods -n "$ns" -l "$sel" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  [ -z "$pod" ] && return 1
  kubectl exec -n "$ns" "$pod" $extra -- sh -c \
    'grep -E "^(anon|file|slab) " /sys/fs/cgroup/memory.stat;
     echo "peak $(cat /sys/fs/cgroup/memory.peak 2>/dev/null || echo 0)";
     echo "current $(cat /sys/fs/cgroup/memory.current 2>/dev/null || echo 0)"' 2>/dev/null
}

echo "{" > "$OUT"
echo "  \"measured_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"," >> "$OUT"
echo "  \"state\": \"${1:-idle}\"," >> "$OUT"
echo "  \"components\": {" >> "$OUT"

first=1
while IFS='|' read -r name ns sel extra; do
  [ -z "$name" ] && continue
  out=$(read_one "$ns" "$sel" "$extra") || { echo "  $name: unreachable" >&2; continue; }
  [ -z "$out" ] && continue
  [ "$first" -eq 0 ] && echo "," >> "$OUT"
  first=0
  printf '    "%s": {' "$name" >> "$OUT"
  sep=""
  while read -r k v; do
    [ -z "$k" ] && continue
    printf '%s"%s_mib": %s' "$sep" "$k" "$(awk -v b="$v" 'BEGIN{printf "%.1f", b/1048576}')" >> "$OUT"
    sep=", "
  done <<< "$out"
  printf '}' >> "$OUT"
  anon=$(echo "$out" | awk '/^anon /{printf "%.1f", $2/1048576}')
  echo "  $name  anon=${anon} MiB" >&2
done <<'EOF'
tetragon|kube-system|app.kubernetes.io/name=tetragon|-c tetragon
target-app|default|app=target-app|
vector|sarvajna-infra|app=vector|
sarvajna-cep|sarvajna-infra|app=sarvajna-cep|
soar-worker|sarvajna-infra|app=soar-worker|
clickhouse|sarvajna-infra|app=clickhouse|
nats|sarvajna-infra|app=nats|
EOF

echo "" >> "$OUT"
echo "  }" >> "$OUT"
echo "}" >> "$OUT"
echo "written to $OUT" >&2
