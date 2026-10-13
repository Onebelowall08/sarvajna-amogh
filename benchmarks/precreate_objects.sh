#!/usr/bin/env bash
# Create every restricted object before collection.
#
# The reports route writes a file that does not yet exist, then reads it, so a
# first access produces two file-open events where a subsequent access produces
# one. Across 512 objects that is several hundred unmatched kernel events
# concentrated in whichever cell happens to run first, which is an artefact of
# collection order rather than a property of any configuration under test.
#
# Idempotent: safe to run before every suite.
set -euo pipefail
N="${CONFIDENTIAL_FILE_COUNT:-512}"
POD=$(kubectl get pods -n default -l app=target-app \
      -o jsonpath='{.items[0].metadata.name}')
echo "Pre-creating ${N} objects in ${POD}:/tmp ..."
kubectl exec -n default "${POD}" -- sh -c "
  for i in \$(seq 0 \$(( ${N} - 1 ))); do
    f=/tmp/confidential_\${i}.pdf
    [ -f \"\$f\" ] || printf 'payload for confidential_%s.pdf' \"\$i\" > \"\$f\"
  done
  for f in default.txt quarterly_summary.txt confidential_payroll.pdf merger_notes.pdf; do
    [ -f /tmp/\$f ] || printf 'payload for %s' \"\$f\" > /tmp/\$f
  done
  ls /tmp/confidential_[0-9]*.pdf | wc -l"
