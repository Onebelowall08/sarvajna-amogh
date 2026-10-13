#!/usr/bin/env python3
"""
Sarvajna-Amogh: experiment collection.

OBSERVABILITY IS NOT EVALUATION
-------------------------------
No metric is computed here. Earlier versions computed precision and recall
inside the cell loop, so the reported numbers depended on when the loop happened
to look. All metric computation lives in analyze.py, which runs offline against
stored rows and can therefore be corrected without recollecting anything.

The per-cell console output includes a DIAGNOSTIC block of raw counts, never
metrics, so a broken cell is visible immediately rather than hours later. It is
labelled as diagnostic and must not be quoted: analyze.py produces the
reportable numbers.

SELF-VERIFYING AND RESUMABLE
----------------------------
Every cell checks itself the moment it finishes, against gates derived from its
own snapshot and a few queries over its own rows. A cell that passes is recorded
in a ledger and never collected again. A cell that fails stops the suite
immediately, so no further time is spent collecting against a pipeline already
known to be wrong.

    python benchmarks/run_benchmark.py --reset --reps 1
    ... cell 14 fails, suite stops, prints why ...
    ... fix the cause ...
    python benchmarks/run_benchmark.py --resume S20261006-120000

The resumed run skips the thirteen cells that passed, deletes the failed cell's
rows synchronously and verifies they are gone, then collects from that cell
onward. Nothing already proved correct is recollected, and nothing is counted
twice: each cell appears exactly once in the ledger and exactly once in the
data, so the pooled figures in analyze.py converge whether the suite ran in one
pass or five.

Cell ordering within each group is shuffled, but seeded from the suite
identifier and stored in the ledger, so a resumed run reproduces the original
ordering rather than inventing a new experiment.

WHY THE APPLICATION IS CONFIGURED ONCE
--------------------------------------
Changing an environment variable on the application deployment replaces the pod,
and the pod's filesystem holds the objects the workload reads. A cell that began
by discarding them would read 404 on every request and still look like it ran.
The application is therefore configured, restarted and repopulated exactly once,
in preflight. Per-cell variation happens at the correlator and the response
worker, neither of which owns any state the workload depends on.

Usage:
    python benchmarks/run_benchmark.py --preflight-only
    python benchmarks/run_benchmark.py --dry-run --reset
    python benchmarks/run_benchmark.py --reset --reps 1
    python benchmarks/run_benchmark.py --resume <SUITE_ID>
    python benchmarks/run_benchmark.py --resume <SUITE_ID> --only WINDOW_2000ms
    python benchmarks/run_benchmark.py --resume <SUITE_ID> --status
"""

import argparse
import asyncio
import json
import os
import random
import socket
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

import nats
import pandas as pd
from clickhouse_driver import Client
import checks as K

CH = dict(host="127.0.0.1", port=9000, user="default", password="amogh_secure_pwd")
NATS_URL = "nats://127.0.0.1:4222"
K3D_NODE = os.getenv("K3D_NODE", "k3d-sarvajna-cluster-server-0")
APP_URL = "http://localhost:3501"

INFRA_NS = "sarvajna-infra"
APP_NS = "default"
TET_NS = "kube-system"

CONFIDENTIAL_FILE_COUNT = int(os.getenv("CONFIDENTIAL_FILE_COUNT", "512"))

# One constant for every cell. In earlier suites the drain was computed from the
# enrichment ceiling, so cells with longer retry budgets were also collected for
# longer and any latency difference was partly an artefact of the protocol.
SETTLE_S = int(os.getenv("SETTLE_S", "75"))
DRAIN_MIN_S = int(os.getenv("DRAIN_MIN_S", "75"))
DRAIN_MAX_S = int(os.getenv("DRAIN_MAX_S", "180"))

# Tetragon derives event time from a cached boot wall-clock plus monotonic time.
# After a host suspend that baseline is stale; measured drift on this testbed
# reached 30 hours, which the response worker's 300 s guard rejects, nulling
# every true kernel timestamp and emptying the latency decomposition.
CLOCK_TOLERANCE_S = 60

# Enrichment setting for every cell outside the enrichment sweep.
BASE_ENRICH = (0, 1)

SUITE_ID = f"S{datetime.now():%Y%m%d-%H%M%S}"
DIAG = "benchmarks/diag"
LOGS = "benchmarks/logs"


def sh(cmd, check=True, timeout=400):
    return subprocess.run(
        cmd, shell=True, check=check, capture_output=True, text=True, timeout=timeout
    )


def log(tag, msg):
    print(f"[{datetime.now():%H:%M:%S}] [{tag}] {msg}", flush=True)


class CellFailed(Exception):
    """A cell did not satisfy its own gates. Carries enough to resume."""

    def __init__(self, key, run_id, failures):
        self.key, self.run_id, self.failures = key, run_id, failures
        super().__init__(f"{key} failed {len(failures)} gate(s)")


# =====================================================================
#  CELL DEFINITIONS
# =====================================================================
@dataclass
class Cell:
    """One configuration of the system, collected in isolation.

    pending_ms defaults to the correlation window, which is the coupling the
    window sweep measures. One cell sets it independently to establish that the
    coupling, rather than the window itself, governs the loss.
    """

    name: str
    join_mode: str
    window_ms: int = 10000
    pending_ms: int = 0  # 0 means follow window_ms
    adversarial: bool = False
    enforce: bool = False  # response worker writes revocations
    tier2: bool = False  # pod quarantine enabled
    enrich: tuple = BASE_ENRICH
    users: int = 10
    duration: str = "30s"
    quarantine: bool = False  # collected by run_quarantine_cell

    def horizon(self) -> int:
        return self.pending_ms or self.window_ms


def cell_from_dict(d):
    d = dict(d)
    d["enrich"] = tuple(d.get("enrich", BASE_ENRICH))
    return Cell(**d)


def ladder_cells():
    return [
        Cell("B1_TemporalOnly", "temporal"),
        Cell("B2_SpatialResource", "spatial"),
        Cell("B3_DeterministicBridge", "deterministic"),
        Cell("B4_AdversarialRobustness", "deterministic", adversarial=True),
    ]


def window_cells():
    cells = [
        Cell(f"WINDOW_{w}ms", "deterministic", window_ms=w)
        for w in (2000, 5000, 10000, 20000, 30000)
    ]
    # Same window, buffer horizon held open. If recall at 2000 ms recovers here,
    # the loss at that width is the buffer sharing the window's horizon rather
    # than the attack failing to complete within it.
    cells.append(
        Cell(
            "WINDOW_2000ms_DECOUPLED", "deterministic", window_ms=2000, pending_ms=60000
        )
    )
    return cells


def enrichment_cells():
    return [
        Cell(f"ENRICH_r{r}_d{d}", "deterministic", enrich=(r, d))
        for r, d in ((0, 1), (3, 1), (8, 1), (15, 1), (15, 2))
    ]


def enforcement_cells():
    # Revocations reach the store the application reads, so an action taken
    # against a principal has an observable consequence for that principal's
    # later requests.
    return [
        Cell("ENFORCE_TemporalBaseline", "temporal", enforce=True),
        Cell("ENFORCE_Baseline", "deterministic", enforce=True),
        Cell("ENFORCE_Forgery", "deterministic", enforce=True, adversarial=True),
    ]


def quarantine_cell():
    # Short and small. Pod quarantine severs the pod's egress, so a long cell
    # would measure the consequences of the response rather than the response.
    return Cell(
        "QUARANTINE_Enforced",
        "deterministic",
        tier2=True,
        users=4,
        duration="10s",
        quarantine=True,
    )


def build_plan(reps):
    """The ordered cell plan for a suite.

    Order within each group is shuffled so that a systematic effect of
    collection order cannot be mistaken for an effect of the configuration, but
    the shuffle is seeded from the suite identifier. A resumed run therefore
    reproduces the ordering of the original rather than running a different
    experiment under the same name.

    The quarantine cell is last in each repetition because it severs the pod's
    egress, and the recovery is the one part of the protocol that cannot be
    made invisible to what follows.
    """
    rng = random.Random(SUITE_ID)
    plan = [(Cell("WARMUP", "deterministic", duration="15s"), 0)]
    for rep in range(1, reps + 1):
        for group in (
            ladder_cells(),
            window_cells(),
            enforcement_cells(),
            enrichment_cells(),
        ):
            g = list(group)
            rng.shuffle(g)
            plan.extend((c, rep) for c in g)
        plan.append((quarantine_cell(), rep))
    return plan


def cell_key(cell, rep):
    return f"{cell.name}__r{rep}"


# =====================================================================
#  LEDGER
# =====================================================================
def ledger_path(suite=None):
    return f"{DIAG}/{suite or SUITE_ID}_ledger.json"


def load_ledger(suite):
    p = ledger_path(suite)
    if not os.path.exists(p):
        raise RuntimeError(
            f"No ledger at {p}. --resume needs the suite identifier printed when "
            f"the original run started."
        )
    with open(p) as f:
        return json.load(f)


def save_ledger(led):
    """Written atomically. A ledger truncated by an interrupted write would make
    every completed cell look uncollected."""
    os.makedirs(DIAG, exist_ok=True)
    p = ledger_path(led["suite"])
    tmp = p + ".tmp"
    with open(tmp, "w") as f:
        json.dump(led, f, indent=2, default=str)
    os.replace(tmp, p)


def new_ledger(reps, plan):
    return {
        "suite": SUITE_ID,
        "created": datetime.now(timezone.utc).isoformat(),
        "reps": reps,
        "settle_s": SETTLE_S,
        "drain_min_s": DRAIN_MIN_S,
        "base_enrich": list(BASE_ENRICH),
        "confidential_file_count": CONFIDENTIAL_FILE_COUNT,
        "plan": [{"key": cell_key(c, r), "rep": r, "cell": asdict(c)} for c, r in plan],
        "results": {},
    }


def plan_from_ledger(led):
    return [(cell_from_dict(e["cell"]), e["rep"]) for e in led["plan"]]


def print_status(led):
    res = led.get("results", {})
    done = [k for k, v in res.items() if v.get("passed")]
    failed = [k for k, v in res.items() if not v.get("passed")]
    todo = [e["key"] for e in led["plan"] if e["key"] not in res]
    print(
        f"\n{'=' * 74}\n  SUITE {led['suite']}   created {led['created']}\n{'=' * 74}"
    )
    for e in led["plan"]:
        k = e["key"]
        v = res.get(k)
        if not v:
            mark, extra = "pending", ""
        elif v.get("passed"):
            mark, extra = "PASSED ", f"  {v['run_id']}"
        else:
            mark, extra = "FAILED ", f"  {', '.join(v.get('failures', []))[:90]}"
        print(f"  [{mark}] {k}{extra}")
    print(f"\n  {len(done)} passed, {len(failed)} failed, {len(todo)} not started")
    print("=" * 74)


# =====================================================================
#  ROW PURGE  (before any retry)
# =====================================================================
def purge_cell_rows(run_id):
    """Remove every row a failed attempt wrote, and verify removal.

    Mutations are asynchronous by default, so a retry started immediately after
    issuing the delete would collect alongside rows still being removed and the
    cell would be counted twice in every pooled figure. mutations_sync = 2 waits
    for completion, and the counts are re-read rather than assumed.
    """
    ch = Client(**CH)
    tables = ("detections", "ground_truth", "revocations")
    log("PURGE", f"removing rows from the previous attempt: {run_id}")
    for t in tables:
        ch.execute(
            f"ALTER TABLE sarvajna.{t} DELETE WHERE run_id = %(r)s",
            {"r": run_id},
            settings={"mutations_sync": 2},
        )
    left = {
        t: ch.execute(
            f"SELECT count() FROM sarvajna.{t} WHERE run_id = %(r)s", {"r": run_id}
        )[0][0]
        for t in tables
    }
    if any(left.values()):
        raise RuntimeError(
            f"Rows from {run_id} survived deletion: {left}. Retrying now would "
            f"double-count this cell in every pooled figure."
        )
    csv = f"benchmarks/ground_truth_{run_id}.csv"
    if os.path.exists(csv):
        os.remove(csv)
    log("PURGE", f"removed; {left}")


def purge_orphan_runs(led):
    """Rows from an attempt the ledger never recorded.

    The run identifier is generated inside the collection routine and the
    verdict is written after it returns, so an interrupt or crash in between
    leaves rows no ledger entry points at. A later attempt at the same cell
    would then be pooled alongside them and counted twice.
    """
    ch = Client(**CH)
    known = {v["run_id"] for v in led.get("results", {}).values() if v.get("run_id")}
    pat = {"s": f"{led['suite']}\\_\\_%"}
    seen = set()
    for t in ("detections", "ground_truth", "revocations"):
        seen |= {
            r[0]
            for r in ch.execute(
                f"SELECT DISTINCT run_id FROM sarvajna.{t} WHERE run_id LIKE %(s)s", pat
            )
        }
    orphans = sorted(seen - known)
    for rid in orphans:
        log("PURGE", f"orphan from an unrecorded attempt: {rid}")
        purge_cell_rows(rid)
    if not orphans:
        log("RESUME", "no orphaned rows from interrupted attempts")
    return orphans


# =====================================================================
#  PREFLIGHT
# =====================================================================
def _tetragon_event_epoch():
    out = sh(
        f"kubectl exec -n {TET_NS} ds/tetragon -c tetragon -- "
        "tetra getevents -o json --timeout 5s 2>/dev/null "
        "| jq -r 'select(.time) | .time' | head -1",
        check=False,
    ).stdout.strip()
    if not out:
        return None
    return datetime.fromisoformat(out.replace("Z", "+00:00")).timestamp()


def check_tetragon_clock(abort=True):
    """Compared against the NODE clock, not this host. Every pipeline timestamp
    except the workload generator's own originates on the node, so comparing
    against the laptop is misleading when the cluster runs inside a VM."""
    try:
        node_epoch = float(sh(f"docker exec {K3D_NODE} date -u +%s").stdout.strip())
    except Exception as e:
        log("CLOCK", f"WARNING: cannot read node clock ({e})")
        return None
    tet_epoch = _tetragon_event_epoch()
    if tet_epoch is None:
        msg = "No Tetragon events returned; cannot verify the clock."
        if abort:
            raise RuntimeError(msg)
        log("CLOCK", f"WARNING: {msg}")
        return None

    drift = tet_epoch - node_epoch
    log("CLOCK", f"Tetragon vs node: {drift:+.1f}s (tolerance {CLOCK_TOLERANCE_S}s)")
    if abs(drift) > CLOCK_TOLERANCE_S:
        msg = (
            f"Tetragon clock is {drift:+,.0f}s ({drift / 3600:+.1f}h) from the "
            f"node. The response worker rejects anything beyond 300s, so every "
            f"true kernel timestamp would be null and the latency decomposition "
            f"empty. Restart the Tetragon DaemonSet and do not suspend the host "
            f"during collection."
        )
        if abort:
            raise RuntimeError(msg)
        log("CLOCK", f"WARNING: {msg}")
    return drift


def wait_for_policies(timeout=120):
    for attempt in range(timeout // 2):
        out = sh(
            f"kubectl exec -n {TET_NS} ds/tetragon -c tetragon -- "
            "tetra tracingpolicy list 2>/dev/null",
            check=False,
        ).stdout
        if "sarvajna-file-open" in out and "sarvajna-tcp-connect" in out:
            log("SETUP", f"TracingPolicies attached after {attempt * 2}s.")
            time.sleep(5)
            return
        time.sleep(2)
    raise RuntimeError(
        "TracingPolicies did not attach; aborting rather than "
        "collecting a cell with no kernel coverage."
    )


def restart_tetragon():
    log("SETUP", "Restarting Tetragon to reset its clock baseline...")
    sh(
        f"kubectl rollout restart -n {TET_NS} ds/tetragon && "
        f"kubectl rollout status  -n {TET_NS} ds/tetragon --timeout=200s"
    )
    wait_for_policies()
    check_tetragon_clock(abort=True)


def set_tetragon_enrichment(retries, delay):
    sh(
        f"helm upgrade -i tetragon cilium/tetragon -n {TET_NS} "
        f"-f ebpf/tetragon-values.yaml "
        f"--set-string tetragon.extraArgs.event-cache-retries={retries} "
        f"--set-string tetragon.extraArgs.event-cache-retry-delay={delay} && "
        f"kubectl rollout status ds/tetragon -n {TET_NS} --timeout=200s"
    )
    wait_for_policies()
    check_tetragon_clock(abort=False)  # warn, do not abort mid-sweep


def app_health():
    out = sh(
        f"kubectl exec -n {APP_NS} deploy/target-app -- "
        f"wget -qO- http://127.0.0.1:3000/api/health",
        check=False,
    ).stdout.strip()
    try:
        return json.loads(out)
    except Exception:
        return {"ok": False, "raw": out}


def count_objects():
    # Numbered objects only; see the same glob in checks.l8_application.
    out = sh(
        f"kubectl exec -n {APP_NS} deploy/target-app -- sh -c "
        f"'ls /tmp/confidential_[0-9]*.pdf 2>/dev/null | wc -l'",
        check=False,
    ).stdout.strip()
    try:
        return int(out)
    except Exception:
        return -1


def configure_app_once(ep):
    """Set the application's environment, restart it, then create the objects.

    This order matters and is the whole reason the application is configured
    here rather than per cell. Setting an environment variable replaces the pod,
    and the objects live in the pod's filesystem, so creating them before the
    restart would discard them.
    """
    log("APP", "Configuring application (once for the whole suite)...")
    sh(
        f"kubectl set env -n {APP_NS} deployment/target-app "
        f"ENFORCE_REVOCATION=true "
        f"CONFIDENTIAL_FILE_COUNT={CONFIDENTIAL_FILE_COUNT} "
        f"PREVIEW_ALLOWED_ENDPOINTS={ep['nats_pod']}:4222"
    )
    sh(
        f"kubectl rollout restart -n {APP_NS} deployment/target-app && "
        f"kubectl rollout status  -n {APP_NS} deployment/target-app --timeout=200s"
    )

    canary = check_bridge_canary(abort=True)

    log("APP", f"Creating {CONFIDENTIAL_FILE_COUNT} objects...")
    sh("./benchmarks/precreate_objects.sh", timeout=300)
    n = count_objects()
    if n < CONFIDENTIAL_FILE_COUNT:
        raise RuntimeError(
            f"Only {n} objects present, expected {CONFIDENTIAL_FILE_COUNT}. Every "
            f"object read would return 404 and the cell would record almost "
            f"nothing while appearing to run."
        )

    h = app_health()
    problems = []
    if not h.get("ok"):
        problems.append(f"health endpoint not ok: {h}")
    rev = h.get("revocation", {})
    if not rev.get("enforce"):
        problems.append("application is not enforcing revocation")
    if rev.get("last_error"):
        problems.append(
            f"application cannot reach the revocation store: {rev['last_error']}"
        )
    if not h.get("preview_allowed_endpoints"):
        problems.append(
            "outbound allowlist is empty; every fetch would be classed as a "
            "probe and network precision would be unmeasurable"
        )
    if problems:
        raise RuntimeError(
            "Application preflight failed:\n  - " + "\n  - ".join(problems)
        )

    log("APP", f"Ready. objects={n} allowlist={h.get('preview_allowed_endpoints')}")
    return {"health": h, "objects": n, "canary": canary}


def check_bridge_canary(abort=True):
    """The canary only runs at startup, so on a long-lived pod the line has
    usually rotated out of the container log. This is called immediately after
    a restart for that reason."""
    for _ in range(20):
        out = sh(
            f"kubectl logs -n {APP_NS} deploy/target-app --tail=300 2>/dev/null "
            "| grep bridge_canary | tail -1",
            check=False,
        ).stdout.strip()
        if out:
            try:
                c = json.loads(out)
            except Exception:
                c = {"raw": out}
            if c.get("passed") is True:
                log(
                    "CANARY",
                    f"PASS expected={c.get('expected')} observed={c.get('observed')}",
                )
                return c
            msg = (
                "Bridge canary FAILED: the request identifier is not reaching "
                f"child processes, so the deterministic join cannot work. {out}"
            )
            if abort:
                raise RuntimeError(msg)
            log("CANARY", f"WARNING: {msg}")
            return c
        time.sleep(3)
    msg = "Bridge canary never appeared in the application log after restart."
    if abort:
        raise RuntimeError(msg)
    log("CANARY", f"WARNING: {msg}")
    return None


def environment_manifest():
    """Versions and hardware, captured once per suite."""

    def one(cmd):
        return sh(cmd, check=False).stdout.strip()

    m = {"captured_at": datetime.now(timezone.utc).isoformat(), "suite": SUITE_ID}
    m["kubectl"] = one(
        "kubectl version --client -o json | jq -r .clientVersion.gitVersion"
    )
    m["k8s_server"] = one(
        "kubectl version -o json 2>/dev/null | jq -r .serverVersion.gitVersion"
    )
    m["node_kernel"] = one(f"docker exec {K3D_NODE} uname -r")
    m["node_os"] = one(
        f'docker exec {K3D_NODE} sh -c \'cat /etc/os-release | head -2 | tr "\\n" " "\''
    )
    m["host_kernel"] = one("uname -r")
    m["host_cpu"] = one(
        "lscpu 2>/dev/null | grep -E 'Model name|^CPU\\(s\\):|Thread|Core' | tr '\\n' ';'"
    )
    m["host_mem_kb"] = one("grep MemTotal /proc/meminfo | awk '{print $2}'")
    m["docker"] = one("docker version --format '{{.Server.Version}}'")
    m["helm_releases"] = one(
        "helm list -A -o json 2>/dev/null | jq -c "
        "'[.[] | {name, namespace, chart, app_version}]'"
    )

    imgs = {}
    for ns, sel in (
        (INFRA_NS, "app=clickhouse"),
        (INFRA_NS, "app=nats"),
        (INFRA_NS, "app=postgres"),
        (INFRA_NS, "app=vector"),
        (INFRA_NS, "app=sarvajna-cep"),
        (INFRA_NS, "app=soar-worker"),
        (APP_NS, "app=target-app"),
        (TET_NS, "app.kubernetes.io/name=tetragon"),
        (TET_NS, "k8s-app=cilium"),
    ):
        v = one(
            f"kubectl get pods -n {ns} -l {sel} "
            f"-o jsonpath='{{.items[0].spec.containers[*].image}}'"
        )
        if v:
            imgs[sel.split("=")[-1]] = v
    m["images"] = imgs

    m["python"] = one("python3 --version")
    m["locust"] = one("locust --version 2>&1 | head -1")
    m["pip_freeze"] = one(
        "pip freeze 2>/dev/null | grep -iE "
        "'clickhouse|nats|pandas|numpy|matplotlib|locust'"
    ).replace("\n", " ")

    os.makedirs(DIAG, exist_ok=True)
    with open(f"{DIAG}/environment_{SUITE_ID}.json", "w") as f:
        json.dump(m, f, indent=2)
    with open(f"{DIAG}/environment.json", "w") as f:
        json.dump(m, f, indent=2)
    log(
        "ENV",
        f"manifest written: node kernel {m['node_kernel']}, "
        f"{len(imgs)} component images",
    )
    return m


def preflight(abort=True, with_quarantine=True):
    """Static checks, then the one-time application configuration, then the
    destructive enforcement check. The same implementation verify_environment.py
    runs, so the two cannot drift."""
    log("PREFLIGHT", "=" * 58)
    c = K.Checker()
    ep = K.run_static(c, CONFIDENTIAL_FILE_COUNT)
    K.configure_streams(c)
    manifest = environment_manifest()
    if c.failures() and abort:
        K.summarise(c, f"{DIAG}/preflight.json")
        raise RuntimeError("Preflight failed. Fix the above, then rerun.")

    app = configure_app_once(ep)
    # Refresh endpoints: target-app was recreated with a potentially new address
    ep = K.resolve_endpoints()
    restart_tetragon()
    set_tetragon_enrichment(*BASE_ENRICH)

    log("SETUP", "Warming port-forward after application restart...")
    for _ in range(20):
        code = sh(
            f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 3 {APP_URL}/api/health",
            check=False,
        ).stdout.strip()
        if code == "200":
            log("SETUP", "Port-forward re-established and healthy on localhost:3501.")
            break
        time.sleep(1)
    else:
        log("SETUP", "WARNING: port-forward on localhost:3501 not responding.")

    if with_quarantine:
        K.check_quarantine_enforcement(c, ep, log=lambda m: log("QUARANTINE", m))
    K.l11_revocation_effect(c, ep, log=lambda m: log("REVOCATION", m))

    verdict, fails, _ = K.summarise(c, f"{DIAG}/preflight.json")
    if fails and abort:
        raise RuntimeError("Preflight failed after configuration.")
    log("PREFLIGHT", "=" * 58)
    return {
        "checks": [asdict(r) for r in c.results],
        "app": app,
        "endpoints": ep,
        "verdict": verdict,
        "manifest": manifest,
    }


# =====================================================================
#  INFRA
# =====================================================================
async def _purge():
    try:
        nc = await nats.connect(NATS_URL)
        js = nc.jetstream()
        for s in ("TELEMETRY", "ALERTS"):
            try:
                await js.purge_stream(s)
            except Exception:
                pass
        await nc.close()
    except Exception as e:
        log("PURGE", f"WARNING: {e}")


def purge_streams():
    asyncio.run(_purge())


def truncate_revocations():
    """Per cell. A revocation issued in one cell would otherwise still be in
    force during the next, so an enforcement cell would begin with principals
    already blocked by a previous configuration."""
    sh(
        f"kubectl exec -n {INFRA_NS} deploy/postgres -- psql -U sarvajna "
        f"-d sarvajna_db -c 'TRUNCATE revocations;'",
        check=False,
    )


def init_db(reset):
    ch = Client(**CH)
    ch.execute("CREATE DATABASE IF NOT EXISTS sarvajna")
    if reset:
        for t in ("detections", "ground_truth", "revocations", "raw_telemetry"):
            try:
                ch.execute(f"TRUNCATE TABLE IF EXISTS sarvajna.{t}")
                log("RESET", f"Truncated sarvajna.{t}")
            except Exception as e:
                log("RESET", f"Could not truncate {t}: {e}")
    log("INIT", f"Suite = {SUITE_ID}")


def wait_for_drain(run_id, stable_polls=4, interval=3):
    ch = Client(**CH)
    last, stable, waited, trace = -1, 0, 0, []
    while waited < DRAIN_MAX_S:
        n = ch.execute(
            "SELECT count() FROM sarvajna.detections "
            "WHERE run_id = %(r)s AND correlated = 1",
            {"r": run_id},
        )[0][0]
        trace.append({"t": waited, "correlated": n})
        if n == last and waited >= DRAIN_MIN_S:
            stable += 1
            if stable >= stable_polls:
                log("DRAIN", f"Quiescent at {waited}s with {n} correlated rows.")
                return waited, trace
        else:
            stable = 0
            if waited % 15 == 0:
                log("DRAIN", f"{waited}s: {n} correlated rows...")
        last = n
        time.sleep(interval)
        waited += interval
    log("DRAIN", f"Ceiling reached at {waited}s with {last} rows.")
    return waited, trace


# =====================================================================
#  DIAGNOSTICS  (raw state, never metrics)
# =====================================================================
def snapshot(run_id, cell: Cell, rep, ep, drain_s, drain_trace, extra=None):
    ch = Client(**CH)
    snap = {
        "run_id": run_id,
        "cell": cell.name,
        "rep": rep,
        "config": asdict(cell),
        "endpoints": ep,
        "drain_s": drain_s,
        "drain_trace": drain_trace,
        "captured_at": datetime.now(timezone.utc).isoformat(),
    }
    if extra:
        snap.update(extra)

    def safe(fn):
        try:
            return fn()
        except Exception as e:
            return {"error": str(e)}

    snap["matched_on"] = safe(
        lambda: dict(
            ch.execute(
                "SELECT matched_on, count() FROM sarvajna.detections "
                "WHERE run_id = %(r)s GROUP BY matched_on",
                {"r": run_id},
            )
        )
    )
    snap["alert_type"] = safe(
        lambda: dict(
            ch.execute(
                "SELECT alert_type, count() FROM sarvajna.detections "
                "WHERE run_id = %(r)s AND correlated = 1 GROUP BY alert_type",
                {"r": run_id},
            )
        )
    )
    snap["detections"] = safe(
        lambda: dict(
            zip(
                (
                    "total",
                    "correlated",
                    "with_attack_id",
                    "with_kernel_true",
                    "with_app_emit",
                ),
                ch.execute(
                    "SELECT count(), countIf(correlated = 1), "
                    "countIf(attack_id IS NOT NULL AND attack_id != ''), "
                    "countIf(t_kernel_true IS NOT NULL), "
                    "countIf(t_app_emit IS NOT NULL) "
                    "FROM sarvajna.detections WHERE run_id = %(r)s",
                    {"r": run_id},
                )[0],
            )
        )
    )
    snap["ground_truth"] = safe(
        lambda: dict(
            ch.execute(
                "SELECT attack_type, count() FROM sarvajna.ground_truth "
                "WHERE run_id = %(r)s GROUP BY attack_type",
                {"r": run_id},
            )
        )
    )
    # A request refused because its principal was revoked reached the
    # application and was answered by it. Counting only HTTP 200 as delivered
    # would score every successful enforcement action as a delivery failure:
    # measured 1217 of 5333 in the forgery enforcement cell, which is precisely
    # the collateral damage that cell exists to quantify.
    snap["delivery"] = safe(
        lambda: dict(
            zip(
                ("issued", "delivered", "blocked", "undelivered"),
                ch.execute(
                    "SELECT count(), "
                    "       countIf(http_status = 200 OR blocked = 1), "
                    "       countIf(blocked = 1), "
                    "       countIf(http_status != 200 AND blocked = 0) "
                    "FROM sarvajna.ground_truth WHERE run_id = %(r)s",
                    {"r": run_id},
                )[0],
            )
        )
    )
    snap["blocked_requests"] = safe(
        lambda: ch.execute(
            "SELECT countIf(blocked = 1) FROM sarvajna.ground_truth "
            "WHERE run_id = %(r)s",
            {"r": run_id},
        )[0][0]
    )
    snap["revocations"] = safe(
        lambda: ch.execute(
            "SELECT count(), uniqExact(principal_user) FROM sarvajna.revocations "
            "WHERE run_id = %(r)s",
            {"r": run_id},
        )[0]
    )
    snap["actions"] = safe(
        lambda: dict(
            ch.execute(
                "SELECT action_type, count() FROM sarvajna.detections "
                "WHERE run_id = %(r)s GROUP BY action_type",
                {"r": run_id},
            )
        )
    )

    # Execution true positives and false positives, the two structural gates.
    snap["rce_tp"] = safe(
        lambda: dict(
            zip(
                ("tp", "attempts"),
                ch.execute(
                    "WITH det AS (SELECT attack_id, max(correlated) AS c "
                    "  FROM sarvajna.detections WHERE run_id = %(r)s "
                    "  AND attack_id != '' AND attack_id IS NOT NULL "
                    "  GROUP BY attack_id) "
                    "SELECT countIf(g.label = 1 AND det.c = 1), count() "
                    "FROM sarvajna.ground_truth g "
                    "LEFT JOIN det ON g.attack_id = det.attack_id "
                    "WHERE g.run_id = %(r)s "
                    "  AND g.attack_type = 'RCE_COMMAND_INJECTION' "
                    "SETTINGS join_use_nulls = 1",
                    {"r": run_id},
                )[0],
            )
        )
    )
    # Split by whether the benign request was a forgery target.
    #
    # Under forgery the attacker declares a victim's identifier, so the
    # correlator pairs the attacker's execution with the victim's own benign
    # record and the detection carries that record's identifier. It is
    # correlated against a benign row, but it is not a false positive: it is
    # the misattribution the adversarial condition exists to measure. Counting
    # it as precision loss would report the project's central finding as a
    # defect in the correlator.
    snap["false_positives"] = safe(
        lambda: dict(
            zip(
                ("fp", "forgery_recon"),
                ch.execute(
                    "WITH det AS (SELECT attack_id, max(correlated) AS c "
                    "  FROM sarvajna.detections WHERE run_id = %(r)s "
                    "  AND attack_id != '' AND attack_id IS NOT NULL "
                    "  GROUP BY attack_id) "
                    "SELECT countIf(g.label = 0 AND det.c = 1 "
                    "               AND g.attack_type != 'forgery_recon'), "
                    "       countIf(g.label = 0 AND det.c = 1 "
                    "               AND g.attack_type = 'forgery_recon') "
                    "FROM sarvajna.ground_truth g "
                    "LEFT JOIN det ON g.attack_id = det.attack_id "
                    "WHERE g.run_id = %(r)s SETTINGS join_use_nulls = 1",
                    {"r": run_id},
                )[0],
            )
        )
    )
    snap["reassigned"] = safe(
        lambda: ch.execute(
            "SELECT count() FROM sarvajna.detections d "
            "INNER JOIN sarvajna.ground_truth g ON d.attack_id = g.attack_id "
            "WHERE d.run_id = %(r)s AND d.correlated = 1 "
            "  AND d.attack_id != '' AND d.attack_id IS NOT NULL "
            "  AND d.run_id != g.run_id",
            {"r": run_id},
        )[0][0]
    )
    snap["orphaned"] = safe(
        lambda: ch.execute(
            "SELECT countIf(attack_id NOT IN "
            "    (SELECT attack_id FROM sarvajna.ground_truth)), count() "
            "FROM sarvajna.detections WHERE run_id = %(r)s AND correlated = 1 "
            "  AND attack_id != '' AND attack_id IS NOT NULL",
            {"r": run_id},
        )[0]
    )

    def _clean_ts(s):
        if not s:
            return ""
        return str(s).replace("T", " ").replace("+00:00", "").replace("Z", "")

    _a = _clean_ts(extra.get("t_cell_start")) if extra else ""
    _b = _clean_ts(extra.get("t_cell_end")) if extra else ""

    # Bounded on BOTH the event time and the collection time. Bounding on
    # collection alone admits telemetry produced before the cell began and still
    # draining through the collector: the same workload measured 3 ms at p50 in
    # isolation and 2600 ms when the bound was on collection only.
    snap["collection_delay_ms"] = (
        safe(
            lambda: {
                f"{s}/{t}": {"n": n, "p50": p50, "p95": p95, "p99": p99}
                for s, t, n, p50, p95, p99 in ch.execute(
                    "SELECT source, event_type, count(), "
                    "round(quantile(0.50)(dateDiff('millisecond', "
                    "  coalesce(app_time, kernel_time), ingest_time))), "
                    "round(quantile(0.95)(dateDiff('millisecond', "
                    "  coalesce(app_time, kernel_time), ingest_time))), "
                    "round(quantile(0.99)(dateDiff('millisecond', "
                    "  coalesce(app_time, kernel_time), ingest_time))) "
                    "FROM sarvajna.raw_telemetry "
                    "WHERE ingest_time BETWEEN parseDateTime64BestEffortOrNull(%(a)s, 6) "
                    "                      AND parseDateTime64BestEffortOrNull(%(b)s, 6) "
                    "  AND coalesce(app_time, kernel_time) BETWEEN "
                    "      parseDateTime64BestEffortOrNull(%(a)s, 6) "
                    "  AND parseDateTime64BestEffortOrNull(%(b)s, 6) "
                    "GROUP BY source, event_type",
                    {"a": _a, "b": _b},
                )
            }
        )
        if _a
        else {}
    )

    # Rows collected during the cell whose event predates it. Excluded from the
    # figures above, counted here so the exclusion is a measurement rather than
    # a silent filter.
    snap["stale_telemetry"] = (
        safe(
            lambda: dict(
                zip(
                    ("collected_in_window", "event_before_window"),
                    ch.execute(
                        "SELECT count(), countIf(coalesce(app_time, kernel_time) < "
                        "  parseDateTime64BestEffortOrNull(%(a)s, 6)) "
                        "FROM sarvajna.raw_telemetry "
                        "WHERE ingest_time BETWEEN parseDateTime64BestEffortOrNull(%(a)s, 6) "
                        "                      AND parseDateTime64BestEffortOrNull(%(b)s, 6)",
                        {"a": _a, "b": _b},
                    )[0],
                )
            )
        )
        if _a
        else {}
    )

    snap["stage_latency_ms"] = safe(
        lambda: {
            a: dict(
                zip(
                    (
                        "n",
                        "export_p50",
                        "export_p95",
                        "transport_p50",
                        "transport_p95",
                        "correlate_p50",
                        "correlate_p95",
                        "act_p50",
                        "act_p95",
                        "pipeline_p50",
                        "pipeline_p95",
                        "pipeline_p99",
                        "e2e_p50",
                        "e2e_p95",
                    ),
                    row,
                )
            )
            for a, *row in ch.execute(
                "SELECT alert_type, count(), "
                "round(quantile(0.50)(dateDiff('millisecond', t_kernel_true, t_collector))), "
                "round(quantile(0.95)(dateDiff('millisecond', t_kernel_true, t_collector))), "
                "round(quantile(0.50)(dateDiff('millisecond', t_collector, t_kernel))), "
                "round(quantile(0.95)(dateDiff('millisecond', t_collector, t_kernel))), "
                "round(quantile(0.50)(dateDiff('millisecond', t_kernel, t_correlate))), "
                "round(quantile(0.95)(dateDiff('millisecond', t_kernel, t_correlate))), "
                "round(quantile(0.50)(dateDiff('millisecond', t_correlate, t_action))), "
                "round(quantile(0.95)(dateDiff('millisecond', t_correlate, t_action))), "
                "round(quantile(0.50)(mttr_pipeline_ms)), "
                "round(quantile(0.95)(mttr_pipeline_ms)), "
                "round(quantile(0.99)(mttr_pipeline_ms)), "
                "round(quantile(0.50)(mttr_app_ms)), round(quantile(0.95)(mttr_app_ms)) "
                "FROM sarvajna.detections WHERE run_id = %(r)s AND correlated = 1 "
                "AND t_kernel_true IS NOT NULL "
                "AND t_app_emit BETWEEN parseDateTime64BestEffortOrNull(%(a)s, 6) "
                "                   AND parseDateTime64BestEffortOrNull(%(b)s, 6) "
                "GROUP BY alert_type",
                {"r": run_id, "a": _a, "b": _b},
            )
        }
        if _a
        else {}
    )

    # Cross-request pairing: a kernel event matched to an application record
    # from a different request. Zero by construction for the declared
    # identifier; a property of the join key for the others.
    snap["cross_request_pairing"] = safe(
        lambda: {
            m: {"n": n, "crossed": x, "pct": round(100 * x / n, 2) if n else 0}
            for m, n, x in ch.execute(
                "SELECT matched_on, count(), "
                "countIf(abs(dateDiff('millisecond', t_app_emit, t_kernel_true)) > 100) "
                "FROM sarvajna.detections WHERE run_id = %(r)s AND correlated = 1 "
                "AND t_kernel_true IS NOT NULL AND t_app_emit IS NOT NULL "
                "AND t_app_emit BETWEEN parseDateTime64BestEffortOrNull(%(a)s, 6) "
                "                   AND parseDateTime64BestEffortOrNull(%(b)s, 6) "
                "GROUP BY matched_on",
                {"r": run_id, "a": _a, "b": _b},
            )
        }
        if _a
        else {}
    )

    # The correlator prints its counters on a five-second timer, so the most
    # recent line can predate the last event it processed. Polling until two
    # consecutive prints agree establishes that it is quiescent and the counters
    # are final, which makes the reconciliation exact rather than approximate.
    import re as _re

    def _cep_counters():
        line = sh(
            f"kubectl logs -n {INFRA_NS} deploy/sarvajna-cep --tail=400 "
            "2>/dev/null | grep '\\[CEP\\]' | tail -1",
            check=False,
        ).stdout.strip()
        st = {k: int(v) for k, v in _re.findall(r"'([a-z_]+)': (\d+)", line)}
        for key in ("processed", "pending", "held"):
            m = _re.search(rf"{key}=(\d+)", line)
            if m:
                st[key] = int(m.group(1))
        # pending describes the queue rather than work completed, and can change
        # without any event being processed.
        return line, st, {k: v for k, v in st.items() if k != "pending"}

    cep_line, stats, sig = _cep_counters()
    stable = False
    for _ in range(5):
        time.sleep(6)
        line2, stats2, sig2 = _cep_counters()
        if sig2 == sig and sig:
            stable = True
            break
        cep_line, stats, sig = line2, stats2, sig2
    snap["cep_tail"] = [cep_line]
    snap["cep_stats"] = stats

    outcomes = sum(v for k, v in stats.items() if k.startswith(("match_", "nomatch_")))
    overhead = sum(
        v for k, v in stats.items() if k.startswith(("dropped_", "ignored_"))
    )
    # Application records the correlator accepted, counted from the telemetry it
    # consumed rather than from the request log. One request can produce several
    # events and some produce none the correlator acts on.
    app_rows = (
        safe(
            lambda: ch.execute(
                "SELECT count() FROM sarvajna.raw_telemetry "
                "WHERE source = 'application' AND pod_name LIKE 'target-app%%' "
                "AND ingest_time BETWEEN parseDateTime64BestEffortOrNull(%(a)s, 6) "
                "AND parseDateTime64BestEffortOrNull(%(b)s, 6)",
                {"a": _a, "b": _b},
            )[0][0]
        )
        if _a
        else 0
    )
    gt_rows = app_rows if isinstance(app_rows, int) else 0
    snap["cep_reconciliation"] = {
        "processed": stats.get("processed", 0),
        "outcomes": outcomes,
        "dropped_or_ignored": overhead,
        "app_records": gt_rows,
        "residual": stats.get("processed", 0) - (outcomes + overhead + gt_rows),
        "counters_stable": stable,
        "held_at_end": stats.get("held", -1),
    }

    snap["app_health"] = safe(app_health)
    snap["clock_drift_s"] = check_tetragon_clock(abort=False)

    os.makedirs(DIAG, exist_ok=True)
    with open(f"{DIAG}/{run_id}.json", "w") as f:
        json.dump(snap, f, indent=2, default=str)
    with open(f"{DIAG}/manifest.jsonl", "a") as f:
        f.write(
            json.dumps(
                {k: v for k, v in snap.items() if k != "drain_trace"}, default=str
            )
            + "\n"
        )

    d = snap["detections"] if isinstance(snap["detections"], dict) else {}
    print("\n  ---- DIAGNOSTIC SNAPSHOT (raw counts, NOT results) ----")
    print(
        f"  detections: total={d.get('total')} correlated={d.get('correlated')} "
        f"with_attack_id={d.get('with_attack_id')} "
        f"kernel_true={d.get('with_kernel_true')} app_emit={d.get('with_app_emit')}"
    )
    if isinstance(snap["matched_on"], dict) and snap["matched_on"]:
        print(
            "  matched_on: "
            + "  ".join(
                f"{k}={v}"
                for k, v in sorted(snap["matched_on"].items(), key=lambda kv: -kv[1])
            )
        )
    if isinstance(snap["actions"], dict) and snap["actions"]:
        print(
            "  actions:    " + "  ".join(f"{k}={v}" for k, v in snap["actions"].items())
        )
    print(
        f"  revocations={snap.get('revocations')}  "
        f"blocked_requests={snap.get('blocked_requests')}  "
        f"delivery={snap.get('delivery')}"
    )
    rec = snap.get("cep_reconciliation", {})
    print(
        f"  cep: processed={rec.get('processed')} outcomes={rec.get('outcomes')} "
        f"dropped/ignored={rec.get('dropped_or_ignored')} "
        f"app={rec.get('app_records')} residual={rec.get('residual')} "
        f"held={rec.get('held_at_end')} stable={rec.get('counters_stable')}"
    )
    st = snap.get("stale_telemetry") or {}
    if isinstance(st, dict) and st.get("collected_in_window"):
        stale = st.get("event_before_window", 0)
        pct = 100 * stale / st["collected_in_window"]
        print(
            f"  telemetry: {st['collected_in_window']} collected in window, "
            f"{stale} ({pct:.1f}%) predate it"
        )
    lat = snap.get("stage_latency_ms") or {}
    if isinstance(lat, dict) and lat:
        print(
            "  latency:    "
            + "  ".join(
                f"{a.split('_')[0]} pipeline_p50={v.get('pipeline_p50')}ms "
                f"p95={v.get('pipeline_p95')}ms"
                for a, v in sorted(lat.items())
            )
        )
    print("  -------------------------------------------------------\n")
    return snap


# =====================================================================
#  PER-CELL VERIFICATION
# =====================================================================
def verify_cell(cell: Cell, snap):
    """Gates this cell must satisfy to be considered collected.

    Universal gates apply to every cell and test the apparatus: data was
    produced, the reason codes partition the events, nothing was left held, the
    counters settled, the workload was delivered, no telemetry leaked in from a
    previous cell, the correlator kept up, and no detection belongs to another
    cell or to no cell.

    Type-specific gates apply by configuration and test the experiment: a mode
    that structurally cannot bind a process execution must report none, the mode
    that can must report some, the proximity baseline must produce false
    positives now that benign traffic reaches every route, and the configurations
    that discriminate must produce none.

    Returns (passed, failures, notes).
    """
    f, notes = [], []

    def num(x, default=0):
        return x if isinstance(x, (int, float)) else default

    d = snap.get("detections") if isinstance(snap.get("detections"), dict) else {}
    rec = snap.get("cep_reconciliation") or {}
    gt = snap.get("ground_truth") if isinstance(snap.get("ground_truth"), dict) else {}
    dl = snap.get("delivery") if isinstance(snap.get("delivery"), dict) else {}
    stale = (
        snap.get("stale_telemetry")
        if isinstance(snap.get("stale_telemetry"), dict)
        else {}
    )

    # ---- universal -------------------------------------------------
    corr = num(d.get("correlated"))
    if corr <= 0:
        f.append(f"no correlated detections (correlated={corr})")

    gt_total = sum(v for v in gt.values() if isinstance(v, int))
    if gt_total <= 0:
        f.append("no ground truth ingested; this cell cannot enter any denominator")

    # The quarantine cell severs the pod's network while kernel telemetry
    # continues, and its own egress probe runs a process loop inside the pod ten
    # times a second. Some kernel events therefore have no application partner
    # by construction. Its contribution is the containment measurement rather
    # than any precision or recall figure, so a small residual is reported
    # rather than treated as a defect.
    tol = max(20, int(0.01 * num(rec.get("processed")))) if cell.quarantine else 0

    resid = num(rec.get("residual"), 0)
    if abs(resid) > tol:
        f.append(
            f"reason codes do not partition the events (residual={resid}); "
            f"processed={rec.get('processed')} outcomes={rec.get('outcomes')} "
            f"dropped={rec.get('dropped_or_ignored')} app={rec.get('app_records')}"
        )
    elif resid:
        notes.append(f"residual {resid} within tolerance {tol}")

    held = num(rec.get("held_at_end"), -1)
    if held < 0 or held > tol:
        f.append(
            f"events still held at cell end (held={held}); their outcomes are missing"
        )
    elif held:
        notes.append(f"held {held} within tolerance {tol}")

    if not rec.get("counters_stable") and not cell.quarantine:
        f.append("correlator counters never settled; the reconciliation is approximate")
    issued, delivered = num(dl.get("issued")), num(dl.get("delivered"))
    rate = (delivered / issued) if issued else 0.0
    if rate < 0.98:
        f.append(
            f"delivery {delivered}/{issued} = {rate:.3f} (reached the application, "
            f"including {num(dl.get('blocked'))} refused by revocation); requests "
            f"that never arrived are indistinguishable from undetected attacks"
        )
    elif num(dl.get("blocked")):
        notes.append(f"refused by revocation {num(dl.get('blocked'))}")

    cw = num(stale.get("collected_in_window"))
    sb = num(stale.get("event_before_window"))
    if cw and 100 * sb / cw >= 5.0:
        f.append(
            f"{sb} of {cw} telemetry records collected during this cell predate it "
            f"({100 * sb / cw:.1f}%); the settle period is too short"
        )

    peak = num(snap.get("cep_backlog_peak"))
    if peak >= 500:
        f.append(
            f"correlator queue reached {peak}; this cell's latency describes the "
            f"queue rather than the pipeline"
        )

    if num(snap.get("reassigned")) != 0:
        f.append(
            f"{snap.get('reassigned')} detection(s) carry an attack issued by another "
            f"cell; the composite join credits them to neither"
        )

    orph = snap.get("orphaned")
    if isinstance(orph, (list, tuple)) and len(orph) == 2 and orph[1]:
        pct = 100 * orph[0] / orph[1]
        if pct >= 1.0:
            f.append(
                f"{orph[0]} of {orph[1]} correlated detections ({pct:.2f}%) have no "
                f"ground-truth row"
            )

    if d.get("total") and not num(d.get("with_kernel_true")):
        f.append(
            "true kernel time null on every row; Tetragon's clock is outside the "
            "response worker's guard and the latency decomposition is empty"
        )

    lat = (
        snap.get("stage_latency_ms")
        if isinstance(snap.get("stage_latency_ms"), dict)
        else {}
    )
    if lat and corr:
        counted = sum(num(v.get("n")) for v in lat.values() if isinstance(v, dict))
        if counted < 0.8 * corr:
            f.append(
                f"latency computed over {counted} of {corr} correlated rows; the "
                f"cell-window filter is excluding rows, most likely a clock offset "
                f"between this host and the application container"
            )

    # ---- structural, by join mode ----------------------------------
    rce = snap.get("rce_tp") if isinstance(snap.get("rce_tp"), dict) else {}
    tp, attempts = num(rce.get("tp")), num(rce.get("attempts"))
    if cell.join_mode in ("temporal", "spatial"):
        if tp != 0:
            f.append(
                f"{cell.join_mode} mode reported {tp} execution true positives of "
                f"{attempts}; it returns mode_cannot_match_execve and must report 0, "
                f"so a deterministic correlator processed these attacks"
            )
    elif cell.join_mode == "deterministic" and attempts > 0:
        if tp <= 0:
            f.append(
                f"the bridge detected no process execution ({tp}/{attempts}); the "
                f"declared identifier is not reaching the correlator"
            )
        else:
            notes.append(f"execution recall {tp}/{attempts}")

    fpd = snap.get("false_positives")
    if isinstance(fpd, dict):
        fp, misattributed = num(fpd.get("fp")), num(fpd.get("forgery_recon"))
    else:
        fp, misattributed = num(fpd), 0

    if cell.join_mode == "temporal":
        if fp <= 0:
            f.append(
                "the proximity baseline produced no false positives; benign traffic "
                "is not reaching the vulnerable routes, so precision is not measured"
            )
        else:
            notes.append(f"false positives {fp}")
    elif fp != 0:
        f.append(
            f"{fp} false positive(s) under {cell.join_mode} mode on authorised "
            f"traffic that was not a forgery target"
        )

    if cell.adversarial:
        # Attributed to the victim whose identifier was copied. Zero would mean
        # the forged identifier never bound, so the condition produced nothing.
        if misattributed <= 0:
            f.append(
                "no forged execution was attributed to its victim; the forgery "
                "condition produced no misattribution to measure"
            )
        else:
            notes.append(f"misattributed to victims {misattributed}")
    elif misattributed:
        f.append(
            f"{misattributed} detection(s) attributed to a forgery target in a "
            f"cell that issues no forgery traffic"
        )

    # ---- by configuration ------------------------------------------
    if cell.adversarial:
        strip, forge = num(gt.get("RCE_EVASION_STRIP")), num(gt.get("RCE_FORGERY"))
        if strip <= 0 or forge <= 0:
            f.append(
                f"adversarial traffic was not issued (strip={strip} forgery={forge}); "
                f"the evasion and forgery conditions produce no data"
            )
        else:
            notes.append(f"adversarial issued strip={strip} forgery={forge}")

    if cell.enforce:
        revs = snap.get("revocations")
        n_rev = revs[0] if isinstance(revs, (list, tuple)) and revs else 0
        if num(n_rev) <= 0:
            f.append(
                "no revocation was written; the user-scoped response tier took no "
                "action, so collateral damage cannot be measured"
            )
        blocked = num(snap.get("blocked_requests"))
        # Attackers draw a fresh identifier per attack and never transact again,
        # so a baseline enforcement cell can legitimately block nothing. Victims
        # transact continuously, so the conditions that revoke them must not.
        if cell.join_mode == "temporal" or cell.adversarial:
            if blocked <= 0:
                f.append(
                    "no request was refused despite revocations being in force; "
                    "collateral damage measures zero where it should not"
                )
            else:
                notes.append(f"blocked requests {blocked}")
        else:
            notes.append(f"blocked requests {blocked} (attackers do not re-transact)")

    if cell.quarantine:
        q = snap.get("quarantine") or {}
        if not q.get("containment_latency_s"):
            f.append(
                "the quarantine cell produced no containment measurement; the action "
                "fired but convergence was never observed"
            )
        else:
            notes.append(f"containment {q['containment_latency_s']}s")

    return (len(f) == 0), f, notes


# =====================================================================
#  CELL
# =====================================================================
def ingest_ground_truth(run_id):
    f = f"benchmarks/ground_truth_{run_id}.csv"
    if not os.path.exists(f):
        log(
            "GT",
            f"!! MISSING {f} — this cell has NO ground truth and will be "
            f"excluded from analysis.",
        )
        return 0
    df = pd.read_csv(f)
    for c in ("victim_user", "victim_trace", "tenant_id"):
        if c not in df.columns:
            df[c] = ""
    for c in ("http_status", "blocked"):
        if c not in df.columns:
            df[c] = 0
    df = df.fillna({
        "victim_user": "",
        "victim_trace": "",
        "tenant_id": "",
        "http_status": 0,
        "blocked": 0,
    })
    rows = []
    for _, r in df.iterrows():
        t = pd.to_datetime(r.get("t_sent"), errors="coerce")
        rows.append((
            str(r["run_id"]),
            str(r["attack_id"]),
            0 if str(r["label"]).lower() == "benign" else 1,
            str(r["attack_type"]),
            str(r["user_id"]),
            str(r["tenant_id"]),
            str(r["payload"]),
            str(r["victim_user"]),
            str(r["victim_trace"]),
            int(r["http_status"]),
            int(r["blocked"]),
            datetime.utcnow() if pd.isna(t) else t.to_pydatetime(),
        ))
    Client(**CH).execute(
        "INSERT INTO sarvajna.ground_truth (run_id, attack_id, label, attack_type, "
        "user_id, tenant_id, payload, victim_user, victim_trace, http_status, "
        "blocked, t_sent) VALUES",
        rows,
    )
    log("GT", f"Ingested {len(rows)} rows.")
    return len(rows)


def _pod_name(ns, selector):
    return sh(
        f"kubectl get pods -n {ns} -l {selector} "
        f"-o jsonpath='{{.items[0].metadata.name}}'",
        check=False,
    ).stdout.strip()


RESOURCE_TARGETS = [
    ("target-app", APP_NS, "app=target-app", ""),
    ("vector", INFRA_NS, "app=vector", ""),
    ("sarvajna-cep", INFRA_NS, "app=sarvajna-cep", ""),
    ("soar-worker", INFRA_NS, "app=soar-worker", ""),
    ("clickhouse", INFRA_NS, "app=clickhouse", ""),
    ("nats", INFRA_NS, "app=nats", ""),
    ("tetragon", TET_NS, "app.kubernetes.io/name=tetragon", "-c tetragon"),
]


def cgroup_snapshot():
    """Cumulative CPU microseconds and current memory, per component.

    Read from the cgroup rather than from the metrics API. metrics-server
    computes a rate between scrapes roughly fifteen seconds apart, so a cell
    shorter than that returns whatever the last scrape happened to catch:
    measured 2, 55 and 1 millicores for the same component under three
    identical workloads. A counter delta over the cell is exact.
    """
    out = {}
    for name, ns, sel, c in RESOURCE_TARGETS:
        pod = _pod_name(ns, sel)
        if not pod:
            continue
        r = (
            sh(
                f"kubectl exec -n {ns} {pod} {c} -- sh -c "
                f"'cat /sys/fs/cgroup/cpu.stat 2>/dev/null | head -1; "
                f"cat /sys/fs/cgroup/memory.current 2>/dev/null; "
                f"cat /sys/fs/cgroup/memory.peak 2>/dev/null'",
                check=False,
                timeout=30,
            )
            .stdout.strip()
            .splitlines()
        )
        rec = {}
        for line in r:
            if line.startswith("usage_usec"):
                rec["cpu_usec"] = int(line.split()[1])
            elif line.isdigit():
                rec.setdefault("mem_now", int(line))
                rec["mem_peak"] = int(line)
        if "cpu_usec" in rec:
            out[name] = rec
    return out


def resource_delta(before, after, wall_s):
    """Average cores and peak memory over the cell."""
    out = {}
    for name, a in after.items():
        b = before.get(name)
        if not b or "cpu_usec" not in b:
            continue
        cpu_s = (a["cpu_usec"] - b["cpu_usec"]) / 1e6
        out[name] = {
            "cpu_seconds": round(cpu_s, 3),
            "mean_millicores": round(1000 * cpu_s / wall_s, 1) if wall_s else None,
            "mem_peak_mib": round(a.get("mem_peak", 0) / 1048576, 1),
        }
    return out


def sample_cep_backlog(stop_event, out):
    """Correlator queue depth, sampled while the cell runs.

    Latency is a property of the pipeline only while the correlator keeps up.
    Once it falls behind, every later event inherits the queue and the reported
    figure describes the backlog instead of the system.
    """
    import re as _re

    while not stop_event.is_set():
        line = sh(
            f"kubectl logs -n {INFRA_NS} deploy/sarvajna-cep --tail=1 "
            "2>/dev/null | grep '\\[CEP\\]'",
            check=False,
        ).stdout
        m = _re.search(r"pending=(\d+).*?held=(\d+)", line)
        if m:
            out.append({"pending": int(m.group(1)), "held": int(m.group(2))})
        stop_event.wait(2)


def run_locust(run_id, cell: Cell, ep):
    env = os.environ.copy()
    env["BENCHMARK_RUN_ID"] = run_id
    env["RUN_ADVERSARIAL"] = "true" if cell.adversarial else "false"
    env["CONFIDENTIAL_FILE_COUNT"] = str(CONFIDENTIAL_FILE_COUNT)
    # Probes target a real pod address: a closed port on a live host is refused
    # immediately, where an address with no listener black-holes the packet and
    # every probe would cost the full client timeout.
    env["SSRF_TARGET_IP"] = ep["clickhouse_pod"]
    env["SSRF_OPEN_PORT"] = "8123"
    env["PREVIEW_ALLOWED_IP"] = ep["nats_pod"]
    env["PREVIEW_ALLOWED_PORT"] = "4222"

    import threading

    os.makedirs(LOGS, exist_ok=True)
    lg = f"{LOGS}/{run_id}_locust.log"
    res_before = cgroup_snapshot()
    backlog, stop = [], threading.Event()
    sampler = threading.Thread(
        target=sample_cep_backlog, args=(stop, backlog), daemon=True
    )
    sampler.start()
    t0 = time.time()
    with open(lg, "w") as fh:
        subprocess.run(
            [
                "locust",
                "-f",
                "benchmarks/locust/locustfile.py",
                "--headless",
                "--users",
                str(cell.users),
                "--spawn-rate",
                "10",
                "--run-time",
                cell.duration,
                "--host",
                APP_URL,
                "--csv",
                f"{LOGS}/{run_id}",
                "--csv-full-history",
                "--exit-code-on-error",
                "0",
                # Tasks in flight when the run-time limit elapses finish writing
                # their ground-truth row. Without this the process can exit
                # between a response returning and the row being written.
                "--stop-timeout",
                "10",
            ],
            env=env,
            stdout=fh,
            stderr=subprocess.STDOUT,
            check=False,
        )
    wall = round(time.time() - t0, 1)
    stop.set()
    sampler.join(timeout=10)
    res = resource_delta(res_before, cgroup_snapshot(), wall)

    agg = sh(f"grep -E '^ *Aggregated' {lg} | tail -1", check=False).stdout.strip()
    if agg:
        log("LOCUST", agg[:150])
    log("LOCUST", f"wall={wall}s -> {lg}")
    if res:
        log(
            "RESOURCE",
            "  ".join(
                f"{k}={v['mean_millicores']}m/{v['mem_peak_mib']}Mi"
                for k, v in sorted(res.items())
            ),
        )
    peak = max((b["pending"] for b in backlog), default=0)
    log("BACKLOG", f"correlator queue peaked at {peak}")
    return {
        "locust_wall_s": wall,
        "resources": res,
        "cep_backlog": backlog,
        "cep_backlog_peak": peak,
    }


def run_cell(cell: Cell, rep, ep):
    run_id = f"{SUITE_ID}__{cell.name}__r{rep}__{uuid.uuid4().hex[:6]}"
    print(
        f"\n{'=' * 74}\n  {cell.name}   rep {rep}   mode={cell.join_mode} "
        f"window={cell.window_ms}ms horizon={cell.horizon()}ms "
        f"enrich={cell.enrich[0]}x{cell.enrich[1]}s "
        f"adv={cell.adversarial} enforce={cell.enforce} tier2={cell.tier2}\n"
        f"  {run_id}\n{'=' * 74}"
    )

    # check=True: a cell collected against a still-isolated pod produces data
    # that looks ordinary and is not.
    sh("./benchmarks/reset_quarantine.sh", check=True, timeout=180)

    # Settle BEFORE purge and reconfigure. Telemetry from the previous cell is
    # still in the enrichment cache and the collector's tail; reconfiguring the
    # correlator while it is in flight re-stamps it with THIS cell's identifier
    # while it still carries the PREVIOUS cell's attack identifiers.
    log("SETTLE", f"{SETTLE_S}s for the previous cell to drain fully...")
    time.sleep(SETTLE_S)
    purge_streams()
    truncate_revocations()
    K.configure_cep(
        run_id,
        cell.join_mode,
        cell.window_ms,
        cell.horizon(),
        f"{ep['postgres_pod']},{ep['postgres_svc']}",
        log=lambda m: log("CEP", m),
    )
    K.configure_soar(run_id, cell.enrich[0], cell.enrich[1], cell.enforce, cell.tier2)

    # Purged a second time, after both consumers are running. The durable
    # subscription keeps its position across a restart, so the incoming
    # correlator resumes from whatever accumulated while no consumer was
    # running, and the cell's own events queue behind that backlog.
    purge_streams()
    time.sleep(3)

    t_cell_start = datetime.now(timezone.utc)
    extra = run_locust(run_id, cell, ep)
    drain_s, trace = wait_for_drain(run_id)
    extra["t_cell_start"] = t_cell_start.isoformat()
    extra["t_cell_end"] = datetime.now(timezone.utc).isoformat()
    ingest_ground_truth(run_id)
    snap = snapshot(run_id, cell, rep, ep, drain_s, trace, extra)
    return run_id, snap


def run_quarantine_cell(cell: Cell, rep, ep):
    """Measures how long after the response action the pod's egress is actually
    severed.

    The network policy applies to the pod network. Traffic arriving through the
    API server's port-forward does not traverse that path, so ingress continues
    while egress stops. The probe therefore runs INSIDE the pod and watches its
    own outbound reachability, which is the direction the policy governs.
    """
    run_id = f"{SUITE_ID}__{cell.name}__r{rep}__{uuid.uuid4().hex[:6]}"
    print(
        f"\n{'=' * 74}\n  {cell.name}   rep {rep}   (pod quarantine enabled)\n"
        f"  {run_id}\n{'=' * 74}"
    )

    sh("./benchmarks/reset_quarantine.sh", check=True, timeout=180)
    log("SETTLE", f"{SETTLE_S}s...")
    time.sleep(SETTLE_S)
    purge_streams()
    truncate_revocations()
    K.configure_cep(
        run_id,
        cell.join_mode,
        cell.window_ms,
        cell.horizon(),
        f"{ep['postgres_pod']},{ep['postgres_svc']}",
        log=lambda m: log("CEP", m),
    )
    K.configure_soar(run_id, cell.enrich[0], cell.enrich[1], cell.enforce, cell.tier2)
    purge_streams()
    time.sleep(3)

    cil = sh(
        f"kubectl get pods -n {TET_NS} -l k8s-app=cilium "
        f"-o jsonpath='{{.items[0].metadata.name}}'"
    ).stdout.strip()

    def endpoint_enforced():
        return (
            "Enabled"
            in sh(
                f"kubectl exec -n {TET_NS} {cil} -c cilium-agent -- "
                # -wF: a prefix match would poll an endpoint belonging to a
                # different pod, which never becomes enforced, so the poll
                # would time out and the cell would record no containment at
                # all. The reported figure comes from the in-pod egress probe
                # rather than from this poll, so the collected measurement was
                # not affected.
                f"cilium-dbg endpoint list 2>/dev/null | grep -wF {ep['target_app_pod']} "
                f"| head -1",
                check=False,
            ).stdout
        )

    pod = sh(
        f"kubectl get pods -n {APP_NS} -l app=target-app "
        f"-o jsonpath='{{.items[0].metadata.name}}'"
    ).stdout.strip()
    probe_log = f"{LOGS}/{run_id}_egress.log"
    probe_cmd = (
        f"kubectl exec -n {APP_NS} {pod} -- sh -c "
        f"'i=0; while [ $i -lt 600 ]; do "
        f"  if wget -q -T 1 -O /dev/null http://{ep['clickhouse_pod']}:8123/ping "
        f'     2>/dev/null; then echo "$(date +%s.%N) ok"; '
        f'  else echo "$(date +%s.%N) fail"; fi; '
        f"  i=$((i+1)); sleep 0.1; done'"
    )
    with open(probe_log, "w") as fh:
        probe = subprocess.Popen(
            probe_cmd, shell=True, stdout=fh, stderr=subprocess.STDOUT
        )
    time.sleep(3)

    t_cell_start = datetime.now(timezone.utc)
    extra = run_locust(run_id, cell, ep)
    extra["t_cell_start"] = t_cell_start.isoformat()
    time.sleep(20)
    probe.terminate()
    try:
        probe.wait(timeout=10)
    except Exception:
        probe.kill()

    first_fail, saw_ok = None, False
    try:
        with open(probe_log) as fh:
            for line in fh:
                parts = line.split()
                if len(parts) != 2:
                    continue
                if parts[1] == "ok":
                    saw_ok = True
                elif parts[1] == "fail" and saw_ok and first_fail is None:
                    first_fail = float(parts[0])
    except Exception as e:
        log("QUARANTINE", f"could not parse probe log: {e}")

    # Containment latency, polled rather than sampled. The datapath converges
    # asynchronously over tens of seconds, so a probe at a fixed offset would
    # land anywhere inside that spread.
    ch = Client(**CH)
    row = ch.execute(
        "SELECT min(t_action) FROM sarvajna.detections "
        "WHERE run_id = %(r)s AND action_type LIKE '%%pod_quarantine%%' "
        "AND action_ok = 1",
        {"r": run_id},
    )
    t_action = row[0][0] if row and row[0][0] else None

    t_enforced = None
    if t_action:
        for _ in range(120):
            if endpoint_enforced():
                t_enforced = time.time()
                break
            time.sleep(0.5)

    result = {
        "first_egress_failure_epoch": first_fail,
        "first_quarantine_action": str(t_action) if t_action else None,
        "egress_was_reachable_before": saw_ok,
    }
    if t_action and t_enforced:
        base = t_action.replace(tzinfo=timezone.utc).timestamp()
        result["containment_latency_s"] = round(t_enforced - base, 3)
        if first_fail:
            result["egress_failure_latency_s"] = round(first_fail - base, 3)
        log(
            "QUARANTINE",
            f"containment converged {result['containment_latency_s']:.1f}s after the action",
        )
    else:
        log("QUARANTINE", f"could not measure containment: {result}")

    with open(f"{DIAG}/quarantine_{run_id}.json", "w") as f:
        json.dump(result, f, indent=2, default=str)
    with open(f"{DIAG}/quarantine.json", "w") as f:
        json.dump(result, f, indent=2, default=str)

    # Lift the isolation BEFORE the drain and the snapshot.
    #
    # Containment is already measured, so holding the pod severed past this
    # point measures nothing and corrupts the reconciliation: the application's
    # revocation poller retries every 500 ms against an unreachable store while
    # the egress probe's own process loop keeps arriving, so the correlator's
    # counters are still moving when the snapshot reads them. Measured with the
    # reset after the snapshot: 2739 outcomes against 2625 detection rows, nine
    # events still held, counters never settling.
    sh("./benchmarks/reset_quarantine.sh", check=True, timeout=180)
    for _ in range(20):
        h = app_health()
        if h.get("ok") and not (h.get("revocation") or {}).get("last_error"):
            break
        time.sleep(3)
    else:
        log(
            "QUARANTINE",
            "!! application did not recover its connection to the revocation "
            "store; the next cell would not enforce",
        )

    drain_s, trace = wait_for_drain(run_id)
    extra["t_cell_end"] = datetime.now(timezone.utc).isoformat()
    ingest_ground_truth(run_id)
    snap = snapshot(
        run_id, cell, rep, ep, drain_s, trace, {**extra, "quarantine": result}
    )
    return run_id, snap


# =====================================================================
#  DRY RUN
# =====================================================================
def dry_run(ep):
    """Four short cells plus the validity gates, using the same per-cell
    verification the suite uses."""
    global SETTLE_S, DRAIN_MIN_S, DRAIN_MAX_S
    SETTLE_S = int(os.getenv("SETTLE_S", "20"))
    DRAIN_MIN_S = int(os.getenv("DRAIN_MIN_S", "30"))
    DRAIN_MAX_S = int(os.getenv("DRAIN_MAX_S", "80"))
    log("DRY", f"timers: settle {SETTLE_S}s drain {DRAIN_MIN_S}s")

    cells = [
        Cell("WARMUP", "deterministic", duration="10s"),
        Cell("B3_DeterministicBridge", "deterministic", duration="10s"),
        Cell("B1_TemporalOnly", "temporal", duration="10s"),
        Cell("B2_SpatialResource", "spatial", duration="10s"),
    ]
    ok = True
    print("\n" + "=" * 74)
    print("  DRY RUN")
    print("=" * 74)
    for c in cells:
        run_id, snap = run_cell(c, 0, ep)
        passed, failures, notes = verify_cell(c, snap)
        ok &= passed
        print(
            f"  [{'PASS' if passed else 'FAIL'}] {c.name}"
            + (f"   {'; '.join(notes)}" if notes else "")
        )
        for x in failures:
            print(f"         - {x}")

    print("=" * 74)
    print(
        f"  VERDICT: {'the full suite is expected to produce valid results' if ok else 'a defect remains; do not run the full suite'}"
    )
    print(f"  dry-run rows are under {SUITE_ID}; --reset clears them.")
    print("=" * 74)
    return ok


# =====================================================================
#  SUITE
# =====================================================================
def main():
    global SUITE_ID

    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--reset",
        action="store_true",
        help="truncate all tables before collecting (new suite only)",
    )
    ap.add_argument("--reps", type=int, default=1)
    ap.add_argument("--preflight-only", action="store_true")
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="four short cells plus the per-cell gates",
    )
    ap.add_argument(
        "--resume",
        default="",
        help="suite id to continue; skips cells that already passed",
    )
    ap.add_argument(
        "--only", default="", help="with --resume, collect just this cell name"
    )
    ap.add_argument(
        "--status", action="store_true", help="with --resume, print the ledger and exit"
    )
    ap.add_argument(
        "--no-abort",
        action="store_true",
        help="warn instead of aborting on preflight failure",
    )
    a = ap.parse_args()

    os.makedirs(DIAG, exist_ok=True)
    os.makedirs(LOGS, exist_ok=True)

    led = None
    if a.resume:
        SUITE_ID = a.resume
        led = load_ledger(SUITE_ID)
        if a.status:
            print_status(led)
            return
        if a.reset:
            print(
                "!! --reset with --resume would destroy the data already "
                "collected for this suite. Refusing.",
                file=sys.stderr,
            )
            sys.exit(1)
        log("RESUME", f"continuing suite {SUITE_ID}")

    try:
        pf = preflight(abort=not a.no_abort)
    except RuntimeError as e:
        print(f"\n!! PREFLIGHT FAILED\n{e}\n", file=sys.stderr)
        sys.exit(1)
    ep = pf["endpoints"]

    if a.preflight_only:
        log("DONE", f"Preflight complete. See {DIAG}/preflight.json")
        return

    if a.dry_run:
        init_db(a.reset)
        sys.exit(0 if dry_run(ep) else 1)

    if led is None:
        init_db(a.reset)
        plan = build_plan(a.reps)
        led = new_ledger(a.reps, plan)
        led["preflight_verdict"] = pf["verdict"]
        save_ledger(led)
    else:
        plan = plan_from_ledger(led)
        purge_orphan_runs(led)

    # Preflight restored the base enrichment, so that is the live setting.
    current_enrich = tuple(BASE_ENRICH)
    results = led.setdefault("results", {})

    print(f"\n{'#' * 74}\n#  SUITE {SUITE_ID}   {len(plan)} cells\n{'#' * 74}")

    try:
        for cell, rep in plan:
            key = cell_key(cell, rep)

            if a.only and cell.name != a.only:
                continue

            prev = results.get(key)
            if prev and prev.get("passed") and not a.only:
                log("SKIP", f"{key} already passed ({prev['run_id']})")
                continue
            if prev:
                # A previous attempt left rows. They must go before this one
                # collects, or the cell is counted twice everywhere it is pooled.
                purge_cell_rows(prev["run_id"])

            if tuple(cell.enrich) != current_enrich:
                log(
                    "SWEEP",
                    f"Tetragon enrichment: retries={cell.enrich[0]} "
                    f"delay={cell.enrich[1]}s",
                )
                set_tetragon_enrichment(*cell.enrich)
                current_enrich = tuple(cell.enrich)

            if cell.quarantine:
                run_id, snap = run_quarantine_cell(cell, rep, ep)
            else:
                run_id, snap = run_cell(cell, rep, ep)

            passed, failures, notes = verify_cell(cell, snap)
            results[key] = {
                "run_id": run_id,
                "passed": passed,
                "failures": failures,
                "notes": notes,
                "at": datetime.now(timezone.utc).isoformat(),
            }
            save_ledger(led)

            if passed:
                log("CELL", f"PASS {key}" + (f"   {'; '.join(notes)}" if notes else ""))
            else:
                raise CellFailed(key, run_id, failures)

    except CellFailed as e:
        print(f"\n{'!' * 74}")
        print(f"!  CELL FAILED: {e.key}")
        print(f"!  run_id: {e.run_id}")
        print(f"{'!' * 74}")
        for x in e.failures:
            print(f"!  - {x}")
        done = sum(1 for v in results.values() if v.get("passed"))
        print(
            f"!\n!  {done} cell(s) collected and verified before this one. Their "
            f"data is kept."
        )
        print(f"!  Diagnostics: {DIAG}/{e.run_id}.json")
        print(f"!\n!  Fix the cause, then continue from this cell:")
        print(f"!      python benchmarks/run_benchmark.py --resume {SUITE_ID}")
        print(
            f"!\n!  The failed cell's rows are deleted and verified gone before it "
            f"is\n!  collected again, so nothing is counted twice."
        )
        print(f"{'!' * 74}\n")
        sys.exit(2)

    except KeyboardInterrupt:
        save_ledger(led)
        done = sum(1 for v in results.values() if v.get("passed"))
        print(f"\n\n  Interrupted. {done} cell(s) collected and verified.")
        print(
            f"  Continue with: python benchmarks/run_benchmark.py --resume {SUITE_ID}\n"
        )
        sys.exit(130)

    # Restore the documented enrichment setting.
    if current_enrich != tuple(BASE_ENRICH):
        try:
            set_tetragon_enrichment(*BASE_ENRICH)
        except Exception as e:
            log("SWEEP", f"!! Could not restore enrichment: {e}")

    led["completed"] = datetime.now(timezone.utc).isoformat()
    save_ledger(led)
    print_status(led)
    print(
        f"\n{'=' * 74}\n  COLLECTION COMPLETE.  Suite = {SUITE_ID}\n"
        f"  Ledger:      {ledger_path(SUITE_ID)}\n"
        f"  Diagnostics: {DIAG}/   Workload logs: {LOGS}/\n"
        f"  Wait ~2 minutes, then:\n"
        f"      python benchmarks/analyze.py --suite {SUITE_ID}\n"
        f"      ./benchmarks/export_suite.sh {SUITE_ID}\n{'=' * 74}"
    )


if __name__ == "__main__":
    main()
