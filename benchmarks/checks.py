#!/usr/bin/env python3
from __future__ import annotations

"""
Shared environment verification.

ONE IMPLEMENTATION, TWO ENTRY POINTS
------------------------------------
benchmarks/verify_environment.py  audits an environment without the harness
benchmarks/run_benchmark.py       calls the same checks before collecting

An earlier version of the verifier carried its own copy of the correlator
reconfiguration routine. That copy did not wait for the outgoing pod to
terminate, so the tool built to detect a defect reproduced it internally and
reported a healthy pipeline as broken. configure_cep and configure_soar
therefore live here, and both entry points call them rather than reimplementing
them.

EVERY CHECK RECORDS WHAT IT OBSERVED
------------------------------------
A check that reports only pass or fail is not evidence. A reader needs to see
the measured drift, the object count, the detected fraction. The archived JSON
is written for someone reproducing this work on their own cluster, who needs to
compare their numbers against these rather than trust a verdict.

NO CHECK ASSERTS A CONSTANT IT HAS NOT MEASURED
-----------------------------------------------
An earlier verifier hard-coded per-attack detection rates of roughly 0.28, 0.52
and 0.48, observed once on a degraded pipeline, and failed healthy environments
against them for the rest of the project. Thresholds here are either structural
(a count that must be zero) or deliberately loose, and the measured value is
always printed next to them.
"""

import json
import os
import shutil
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

INFRA_NS = "sarvajna-infra"
APP_NS = "default"
TET_NS = "kube-system"
CH_PW = "amogh_secure_pwd"
K3D_NODE = os.getenv("K3D_NODE", "k3d-sarvajna-cluster-server-0")
APP_URL = "http://localhost:3501"
DIAG = "benchmarks/diag"

G, Y, RD, B, X = "\033[32m", "\033[33m", "\033[31m", "\033[1m", "\033[0m"


def sh(cmd, check=False, timeout=180):
    try:
        return subprocess.run(
            cmd,
            shell=True,
            check=check,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "timeout")


async def _purge_streams():
    try:
        import nats

        nc = await nats.connect("nats://127.0.0.1:4222", connect_timeout=5)
        js = nc.jetstream()
        for s in ("TELEMETRY", "ALERTS"):
            try:
                await js.purge_stream(s)
            except Exception:
                pass
        await nc.close()
    except Exception:
        pass


def purge_streams():
    import asyncio

    try:
        asyncio.run(_purge_streams())
    except Exception:
        pass


async def _configure_streams():
    import nats
    from nats.js.api import StreamConfig, RetentionPolicy, StorageType

    nc = await nats.connect("nats://127.0.0.1:4222", connect_timeout=5)
    js = nc.jetstream()
    out = {}
    for name, subj in (
        ("TELEMETRY", "telemetry.events"),
        ("ALERTS", "alerts.critical"),
    ):
        cfg = StreamConfig(
            name=name,
            subjects=[subj],
            retention=RetentionPolicy.LIMITS,
            storage=StorageType.FILE,
            # Ten minutes. The streams were created with no limits, so they
            # retained every message the project had produced: preflight found
            # 34,442 and 19,672. Purging that immediately before a cell leaves
            # the file store compacting while the cell runs, and both the
            # correlator and the response worker block on it. Measured cost in
            # the first cell after such a purge: correlation delayed from 2 ms
            # to 5,384 ms, decaying to 10 ms by the third cell.
            max_age=600.0,
            max_msgs=2_000_000,
        )
        try:
            await js.update_stream(cfg)
            out[name] = "updated"
        except Exception:
            try:
                await js.add_stream(cfg)
                out[name] = "created"
            except Exception as e:
                out[name] = f"error: {e}"
    info = {}
    for name in ("TELEMETRY", "ALERTS"):
        try:
            i = await js.stream_info(name)
            info[name] = {"msgs": i.state.messages, "max_age_s": i.config.max_age}
        except Exception as e:
            info[name] = {"error": str(e)[:60]}
    await nc.close()
    return out, info


def configure_streams(c: Checker = None):
    import asyncio

    try:
        out, info = asyncio.run(_configure_streams())
    except Exception as e:
        if c:
            c.add(5, "stream retention bounded", "FAIL", str(e)[:70])
        return {}
    if c:
        bad = [
            n
            for n, v in info.items()
            if not isinstance(v, dict) or not v.get("max_age_s")
        ]
        c.add(
            5,
            "stream retention bounded",
            "PASS" if not bad else "FAIL",
            "  ".join(f"{n}: {v}" for n, v in info.items()),
            ""
            if not bad
            else "unbounded streams accumulate every message ever produced; the "
            "purge before the next cell then runs while that cell collects",
        )
    return info


def chq(sql, fmt="TabSeparated"):
    r = sh(
        f"kubectl exec -n {INFRA_NS} deploy/clickhouse -- clickhouse-client "
        f'--user default --password {CH_PW} --query "{sql} FORMAT {fmt}"'
    )
    return r.stdout.strip() if r.returncode == 0 else None


def pgq(sql):
    r = sh(
        f"kubectl exec -n {INFRA_NS} deploy/postgres -- "
        f'psql -U sarvajna -d sarvajna_db -tAc "{sql}"'
    )
    return r.stdout.strip() if r.returncode == 0 else None


# =====================================================================
#  RESULT COLLECTION
# =====================================================================
@dataclass
class Result:
    layer: int
    name: str
    status: str  # PASS WARN FAIL INFO
    observed: str = ""
    remedy: str = ""


@dataclass
class Checker:
    results: list = field(default_factory=list)
    quiet: bool = False

    def add(self, layer, name, status, observed="", remedy=""):
        r = Result(layer, name, status, str(observed), remedy)
        self.results.append(r)
        if not self.quiet:
            icon = {
                "PASS": f"{G}ok  {X}",
                "WARN": f"{Y}warn{X}",
                "FAIL": f"{RD}FAIL{X}",
                "INFO": "    ",
            }[status]
            print(f"  {icon} {name:<46} {observed}")
            if remedy and status in ("FAIL", "WARN"):
                print(f"       {Y}remedy:{X} {remedy}")
        return r

    def layer(self, n, title):
        if not self.quiet:
            print(f"\n{B}[{n}] {title}{X}")

    def failures(self):
        return [r for r in self.results if r.status == "FAIL"]

    def warnings(self):
        return [r for r in self.results if r.status == "WARN"]

    def value(self, name):
        for r in self.results:
            if r.name == name:
                return r.observed
        return None


# =====================================================================
#  SHARED CONFIGURATION ROUTINES
# =====================================================================
def configure_cep(run_id, join_mode, window_ms, pending_ms, ignore_daddrs, log=print):
    """Reconfigure the correlator and wait for the OUTGOING pod to be gone.

    kubectl rollout status returns when the incoming pod reports Ready. A
    rolling update only then signals the outgoing one, which lingers for up to
    its termination grace period still consuming from the same durable
    subscription. For that window two correlators split the message stream, so
    an application record and the kernel event it explains land in different
    processes and the join can never fire.
    """
    sh(
        f"kubectl set env -n {INFRA_NS} deployment/sarvajna-cep "
        f"JOIN_MODE={join_mode} CORRELATION_WINDOW_MS={window_ms} "
        f"PENDING_EXECVE_HORIZON_MS={pending_ms} "
        f"IGNORE_DADDRS={ignore_daddrs} BENCHMARK_RUN_ID={run_id} && "
        f"kubectl rollout status -n {INFRA_NS} deployment/sarvajna-cep "
        f"--timeout=120s",
        check=True,
        timeout=200,
    )

    for i in range(60):
        pods = [
            l.split()
            for l in sh(
                f"kubectl get pods -n {INFRA_NS} -l app=sarvajna-cep --no-headers"
            )
            .stdout.strip()
            .splitlines()
            if l.strip()
        ]
        if len(pods) == 1 and pods[0][1] == "1/1" and pods[0][2] == "Running":
            if i:
                log(f"[CEP] outgoing correlator gone after {i}s; exactly one running")
            break
        time.sleep(1)
    else:
        log("[CEP] !! WARNING: more than one correlator after 60s")

    got = sh(
        f"kubectl exec -n {INFRA_NS} deploy/sarvajna-cep -- printenv "
        f"BENCHMARK_RUN_ID JOIN_MODE CORRELATION_WINDOW_MS "
        f"PENDING_EXECVE_HORIZON_MS"
    ).stdout.split()
    want = [run_id, join_mode, str(window_ms), str(pending_ms)]
    if got[:4] != want:
        log(f"[CEP] !! WARNING: live env {got[:4]}, expected {want}")
    time.sleep(2)
    return got[:4] == want


def configure_soar(
    run_id, enrich_retries, enrich_delay_s, enforce, tier2, act_on_uncorrelated=False
):
    """The response worker uses a Recreate strategy, so there is never more
    than one. Its environment is stamped onto every detection row, which is how
    the configuration a number was produced under stays recoverable from the
    data alone."""
    sh(
        f"kubectl set env -n {INFRA_NS} deployment/soar-worker "
        f"BENCHMARK_RUN_ID={run_id} "
        f"ENRICH_RETRIES={enrich_retries} ENRICH_DELAY_S={enrich_delay_s} "
        f"ENFORCE_REVOCATION={'true' if enforce else 'false'} "
        f"TIER2_ENABLED={'true' if tier2 else 'false'} "
        f"ACT_ON_UNCORRELATED={'true' if act_on_uncorrelated else 'false'} && "
        f"kubectl rollout status -n {INFRA_NS} deployment/soar-worker "
        f"--timeout=120s",
        check=True,
        timeout=200,
    )
    time.sleep(2)


def resolve_endpoints():
    """Addresses the workload and correlator need. Pod addresses change
    whenever a pod is replaced, and a stale one is not an error anybody
    notices: the exclusion quietly stops matching, or the workload probes an
    address that no longer belongs to anything."""

    def pod_ip(label, ns=INFRA_NS):
        return sh(
            f"kubectl get pods -n {ns} -l {label} "
            f"-o jsonpath='{{.items[0].status.podIP}}'"
        ).stdout.strip()

    def svc_ip(name, ns=INFRA_NS):
        return sh(
            f"kubectl get svc -n {ns} {name} -o jsonpath='{{.spec.clusterIP}}'"
        ).stdout.strip()

    ep = {
        "clickhouse_pod": pod_ip("app=clickhouse"),
        "nats_pod": pod_ip("app=nats"),
        "postgres_pod": pod_ip("app=postgres"),
        "postgres_svc": svc_ip("postgres"),
        "clickhouse_svc": svc_ip("clickhouse"),
        "target_app_pod": pod_ip("app=target-app", APP_NS),
    }
    missing = [k for k, v in ep.items() if not v]
    if missing:
        raise RuntimeError(f"Could not resolve: {missing}")
    return ep


def app_health():
    out = sh(
        f"kubectl exec -n {APP_NS} deploy/target-app -- "
        f"wget -qO- http://127.0.0.1:3000/api/health"
    ).stdout.strip()
    try:
        return json.loads(out)
    except Exception:
        return {"ok": False, "raw": out[:200]}


# =====================================================================
#  LAYER 0  tooling
# =====================================================================
def l0_tooling(c: Checker):
    c.layer(0, "Local tooling")
    for tool, why in [
        ("kubectl", "cluster control"),
        ("docker", "node access"),
        ("helm", "enrichment sweep"),
        ("jq", "event parsing"),
        ("locust", "workload generation"),
    ]:
        p = shutil.which(tool)
        c.add(
            0,
            f"{tool} on PATH",
            "PASS" if p else "FAIL",
            p or "not found",
            "" if p else f"install {tool}; required for {why}",
        )
    for mod in ("clickhouse_driver", "nats", "pandas", "numpy", "matplotlib"):
        try:
            __import__(mod)
            c.add(0, f"python module {mod}", "PASS", "importable")
        except ImportError:
            c.add(
                0,
                f"python module {mod}",
                "FAIL",
                "not importable",
                f"pip install {mod.replace('_', '-')}",
            )


# =====================================================================
#  LAYER 1  cluster and workloads
# =====================================================================
def l1_cluster(c: Checker):
    c.layer(1, "Cluster and workloads")
    r = sh(f"docker inspect -f '{{{{.State.Running}}}}' {K3D_NODE}")
    c.add(
        1, "node container running", "PASS" if "true" in r.stdout else "FAIL", K3D_NODE
    )

    up = sh("kubectl get --raw /readyz")
    c.add(
        1,
        "apiserver readyz",
        "PASS" if "ok" in up.stdout else "FAIL",
        up.stdout.strip()[:40],
    )

    # Resolved by label, not by name prefix. A pod name carries a random
    # suffix, so a prefix that matches on one cluster matches nothing on
    # another: this check previously looked for a pod whose name began
    # "cilium-q", which was the suffix this host happened to generate and
    # would fail everywhere else.
    #
    # The prefix "tetragon" was ambiguous for a second reason. It matches both
    # the DaemonSet pod and the operator, and which one was checked depended on
    # the order kubectl happened to list them, so the same command reported
    # 2/2 on one invocation and 1/1 on another.
    #
    # Every selector below is one the rest of this codebase already uses
    # successfully: the resource sampler keys on the Tetragon label and the
    # enforcement layer keys on the Cilium one.
    expected = [
        (INFRA_NS, "clickhouse", "app=clickhouse"),
        (INFRA_NS, "nats", "app=nats"),
        (INFRA_NS, "postgres", "app=postgres"),
        (INFRA_NS, "sarvajna-cep", "app=sarvajna-cep"),
        (INFRA_NS, "soar-worker", "app=soar-worker"),
        (INFRA_NS, "vector", "app=vector"),
        (APP_NS, "target-app", "app=target-app"),
        (TET_NS, "tetragon", "app.kubernetes.io/name=tetragon"),
        (TET_NS, "cilium-agent", "k8s-app=cilium"),
    ]
    for ns, label, sel in expected:
        out = sh(f"kubectl get pods -n {ns} -l {sel} --no-headers").stdout.strip()
        lines = [l.split() for l in out.splitlines() if l.strip()]
        if not lines:
            c.add(
                1,
                f"{ns}/{label}",
                "FAIL",
                f"no pod matching {sel}",
                f"kubectl get pods -n {ns} --show-labels",
            )
            continue
        l = lines[0]
        ready_now, ready_tot = l[1].split("/")
        restarts = int(l[3]) if l[3].isdigit() else 0
        ok = ready_now == ready_tot and l[2] == "Running"
        det = f"{l[1]} {l[2]} restarts={restarts} age={l[-1]}"
        if not ok:
            c.add(
                1, f"{ns}/{label}", "FAIL", det, f"kubectl describe pod -n {ns} {l[0]}"
            )
        elif restarts > 0:
            c.add(
                1,
                f"{ns}/{label}",
                "WARN",
                det,
                f"kubectl logs -n {ns} {l[0]} --previous",
            )
        else:
            c.add(1, f"{ns}/{label}", "PASS", det)

    n = len(
        sh(f"kubectl get pods -n {INFRA_NS} -l app=sarvajna-cep --no-headers")
        .stdout.strip()
        .splitlines()
    )
    c.add(
        1,
        "exactly one correlator",
        "PASS" if n == 1 else "FAIL",
        f"{n} pod(s)",
        ""
        if n == 1
        else "two consumers on one durable subscription split "
        "the stream; paired joins cannot fire",
    )


# =====================================================================
#  LAYER 2  network paths
# =====================================================================
def l2_network(c: Checker, ep=None):
    c.layer(2, "Network paths")
    for name, port in [("clickhouse", 9000), ("nats", 4222), ("target-app", 3501)]:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=3).close()
            c.add(2, f"localhost:{port} ({name})", "PASS", "reachable")
        except Exception as e:
            svc = {
                "clickhouse": f"-n {INFRA_NS} svc/clickhouse 9000:9000",
                "nats": f"-n {INFRA_NS} svc/nats 4222:4222",
                "target-app": f"-n {APP_NS} svc/target-app 3501:3000",
            }[name]
            c.add(
                2,
                f"localhost:{port} ({name})",
                "FAIL",
                str(e)[:50],
                f"kubectl port-forward {svc} >/dev/null 2>&1 &",
            )

    try:
        ep = ep or resolve_endpoints()
        c.add(
            2,
            "endpoint resolution",
            "PASS",
            " ".join(f"{k}={v}" for k, v in ep.items()),
        )
    except Exception as e:
        c.add(2, "endpoint resolution", "FAIL", str(e)[:80])
        ep = {}
    return ep


# =====================================================================
#  LAYER 3  ClickHouse schema
# =====================================================================
REQUIRED_COLUMNS = {
    "detections": [
        "run_id",
        "config",
        "concurrency",
        "window_ms",
        "enrich_retries",
        "enrich_delay_s",
        "enforce_revocation",
        "attack_id",
        "trace_id",
        "alert_type",
        "correlated",
        "join_mode",
        "matched_on",
        "user_id",
        "tenant_id",
        "pod_name",
        "tier",
        "action_type",
        "action_ok",
        "action_err",
        "t_app_emit",
        "t_kernel",
        "t_kernel_true",
        "t_collector",
        "t_correlate",
        "t_soar_in",
        "t_action",
        "t_enforced",
        "mttr_ms",
        "mttr_e2e_ms",
        "mttr_app_ms",
        "mttr_pipeline_ms",
    ],
    "ground_truth": [
        "run_id",
        "attack_id",
        "label",
        "attack_type",
        "user_id",
        "tenant_id",
        "payload",
        "victim_user",
        "victim_trace",
        "http_status",
        "blocked",
        "t_sent",
    ],
    "revocations": [
        "run_id",
        "attack_id",
        "trace_id",
        "alert_type",
        "principal_user",
        "principal_tenant",
        "enforced",
        "action_ok",
        "action_err",
        "t_action",
    ],
    "raw_telemetry": [
        "ingest_time",
        "event_time",
        "app_time",
        "kernel_time",
        "collector_time",
        "runtime_time",
        "source",
        "event_type",
        "pod_name",
        "trace_id",
        "attack_id",
        "raw_payload",
    ],
}


def l3_storage(c: Checker):
    c.layer(3, "ClickHouse schema and capacity")
    ping = chq("SELECT 1")
    c.add(
        3,
        "clickhouse responding",
        "PASS" if ping == "1" else "FAIL",
        ping or "no reply",
    )
    if ping != "1":
        return

    for tbl, cols in REQUIRED_COLUMNS.items():
        got = chq(
            f"SELECT name FROM system.columns WHERE database='sarvajna' "
            f"AND table='{tbl}'"
        )
        if got is None:
            c.add(
                3,
                f"table {tbl}",
                "FAIL",
                "missing",
                "apply pipeline/clickhouse-init.sql",
            )
            continue
        have = set(got.split())
        miss = [x for x in cols if x not in have]
        c.add(
            3,
            f"table {tbl}",
            "PASS" if not miss else "FAIL",
            f"{len(have)} columns" if not miss else f"missing {miss}",
            ""
            if not miss
            else "apply pipeline/clickhouse-init.sql plus the ALTER statements",
        )

    # Second resolution would make millisecond latency unmeasurable, and the
    # column would still exist and still accept writes.
    for col in ("t_kernel", "t_correlate", "t_action"):
        t = chq(
            f"SELECT type FROM system.columns WHERE database='sarvajna' "
            f"AND table='detections' AND name='{col}'"
        )
        ok = t and "DateTime64" in t
        c.add(
            3,
            f"detections.{col} precision",
            "PASS" if ok else "FAIL",
            t or "?",
            "" if ok else "DateTime has one-second resolution",
        )

    w = chq(
        "SELECT type FROM system.columns WHERE database='sarvajna' "
        "AND table='detections' AND name='window_ms'"
    )
    ok = w in ("UInt32", "UInt64")
    c.add(
        3,
        "detections.window_ms range",
        "PASS" if ok else "WARN",
        w or "?",
        "" if ok else "UInt16 cannot represent a 30000 ms window safely",
    )

    rows = chq(
        "SELECT concat(table,'=',toString(sum(rows))) FROM system.parts "
        "WHERE database='sarvajna' AND active GROUP BY table"
    )
    c.add(3, "existing row counts", "INFO", (rows or "empty").replace("\n", "  "))

    d = sh(f"docker exec {K3D_NODE} df -BG /var/lib | tail -1").stdout.split()
    if len(d) >= 5:
        avail = int(d[3].rstrip("G"))
        c.add(
            3,
            "node disk headroom",
            "PASS" if avail > 10 else "FAIL",
            f"{avail}G free",
            "" if avail > 10 else "free space before collecting",
        )


# =====================================================================
#  LAYER 4  revocation store
# =====================================================================
def l4_revocation_store(c: Checker):
    c.layer(4, "Revocation store")
    t = pgq("SELECT to_regclass('revocations')")
    c.add(
        4,
        "revocations table",
        "PASS" if t == "revocations" else "FAIL",
        t or "absent",
        ""
        if t == "revocations"
        else "kubectl exec -n sarvajna-infra -i deploy/postgres -- "
        "psql -U sarvajna -d sarvajna_db < pipeline/postgres-init.sql",
    )
    if t != "revocations":
        return
    n = pgq("SELECT count(*) FROM revocations")
    c.add(
        4,
        "revocations currently in force",
        "PASS" if n == "0" else "WARN",
        f"{n} row(s)",
        ""
        if n == "0"
        else "a principal revoked by an earlier run would start the next cell "
        "already blocked; the harness truncates this per cell",
    )


# =====================================================================
#  LAYER 5  message transport
# =====================================================================
def l5_messaging(c: Checker):
    c.layer(5, "NATS JetStream")
    try:
        import asyncio, nats

        async def probe():
            nc = await nats.connect("nats://127.0.0.1:4222", connect_timeout=5)
            js = nc.jetstream()
            out = {}
            # Judged on the consumer's pending count, not on stored messages.
            # Retention keeps a message after it has been acknowledged, so the
            # stored count is accumulated history: this check reported 34,442
            # messages as a backlog when nothing was unconsumed.
            for s, consumers in (
                ("TELEMETRY", ("cep-pull-consumer",)),
                ("ALERTS", ("soar-worker-durable",)),
            ):
                try:
                    i = await js.stream_info(s)
                    pending, named = 0, []
                    for cn in consumers:
                        try:
                            ci = await js.consumer_info(s, cn)
                            pending = max(pending, ci.num_pending)
                            named.append(cn)
                        except Exception:
                            pass
                    out[s] = {
                        "msgs": i.state.messages,
                        "pending": pending,
                        "consumers": i.state.consumer_count,
                        "named": named,
                    }
                except Exception as e:
                    out[s] = {"error": str(e)[:60]}
            await nc.close()
            return out

        info = asyncio.run(probe())
        for s, v in info.items():
            if "error" in v:
                c.add(
                    5,
                    f"stream {s}",
                    "WARN",
                    v["error"],
                    "created on first connect by the correlator",
                )
            else:
                backlog = v["pending"]
                detail = (
                    f"{v['msgs']} stored, {backlog} unconsumed, "
                    f"{v['consumers']} consumer(s)"
                )
                if not v["named"]:
                    c.add(
                        5,
                        f"stream {s}",
                        "WARN",
                        detail + ", durable consumer not found",
                        "the correlator or response worker has not yet attached; "
                        "its durable subscription is created on first connect",
                    )
                else:
                    c.add(
                        5,
                        f"stream {s}",
                        "PASS" if backlog < 1000 else "WARN",
                        detail,
                        ""
                        if backlog < 1000
                        else "the consumer is behind, so it would process stale "
                        "events before the next cell's own; the harness purges "
                        "per cell",
                    )
    except Exception as e:
        c.add(
            5,
            "jetstream probe",
            "FAIL",
            str(e)[:60],
            f"kubectl port-forward -n {INFRA_NS} svc/nats 4222:4222 &",
        )


# =====================================================================
#  LAYER 6  kernel telemetry
# =====================================================================
def _tetragon_event_epoch():
    out = sh(
        f"kubectl exec -n {TET_NS} ds/tetragon -c tetragon -- "
        "tetra getevents -o json --timeout 5s 2>/dev/null "
        "| jq -r 'select(.time) | .time' | head -1"
    ).stdout.strip()
    if not out:
        return None
    return datetime.fromisoformat(out.replace("Z", "+00:00")).timestamp()


def l6_ebpf(c: Checker):
    c.layer(6, "Kernel telemetry")
    cfg = sh(
        f"kubectl logs -n {TET_NS} ds/tetragon -c tetragon --tail=400 "
        "2>/dev/null | grep -m1 'config settings'"
    ).stdout.replace(" ", "")

    for flag, why in [
        (
            "enable-process-environment-variables:true",
            "the request identifier cannot reach the correlator without this",
        ),
        (
            "filter-environment-variables:[TRACE_ID]",
            "without the filter every container variable is exported",
        ),
        ("enable-cri:true", "pod resolution falls back to the informer"),
        (
            "cri-endpoint:unix:///run/k3s/containerd/containerd.sock",
            "k3d's containerd is not at the default path",
        ),
        ("enable-cgidmap:true", "cgroup to pod mapping"),
    ]:
        present = flag.replace(" ", "") in cfg
        c.add(
            6,
            f"tetragon {flag.split(':')[0]}",
            "PASS" if present else "FAIL",
            "set" if present else "NOT set",
            "" if present else f"helm upgrade with ebpf/tetragon-values.yaml; {why}",
        )

    import re as _re

    m = _re.search(r"event-cache-retries:(\d+).*?event-cache-retry-delay:(\d+)", cfg)
    if m:
        r_, d_ = int(m.group(1)), int(m.group(2))
        c.add(
            6,
            "enrichment retry ceiling",
            "INFO",
            f"retries={r_} delay={d_}s -> up to {r_ * d_}s added exec-path latency",
        )
    else:
        c.add(6, "enrichment retry ceiling", "WARN", "could not parse config line")

    pol = sh(
        f"kubectl exec -n {TET_NS} ds/tetragon -c tetragon -- "
        "tetra tracingpolicy list 2>/dev/null"
    ).stdout
    for p in ("sarvajna-file-open", "sarvajna-tcp-connect"):
        ok = p in pol
        c.add(
            6,
            f"policy {p}",
            "PASS" if ok else "FAIL",
            "attached" if ok else "MISSING",
            "" if ok else "kubectl apply -f ebpf/tetragon-policies.yaml",
        )

    # Against the NODE clock. Every pipeline timestamp except the workload
    # generator's originates on the node, so comparing against the host is
    # misleading when the cluster runs inside a VM.
    try:
        node = float(sh(f"docker exec {K3D_NODE} date -u +%s").stdout.strip())
        tet = _tetragon_event_epoch()
        if tet is None:
            c.add(
                6,
                "tetragon clock vs node",
                "WARN",
                "no events in 5s",
                "generate traffic, or check the export allow list",
            )
        else:
            drift = tet - node
            ok = abs(drift) < 60
            c.add(
                6,
                "tetragon clock vs node",
                "PASS" if ok else "FAIL",
                f"{drift:+.1f}s (tolerance 60s)",
                ""
                if ok
                else "kubectl rollout restart -n kube-system "
                "ds/tetragon; the response worker nulls true "
                "kernel time beyond 300s",
            )
    except Exception as e:
        c.add(6, "tetragon clock vs node", "WARN", str(e)[:60])


# =====================================================================
#  LAYER 7  enforcement capability
# =====================================================================
def l7_enforcement(c: Checker, ep):
    c.layer(7, "Enforcement capability")
    cnp = sh(
        "kubectl get cnp -n default isolate-compromised-pod --no-headers"
    ).stdout.strip()
    c.add(
        7,
        "quarantine policy present",
        "PASS" if cnp else "FAIL",
        cnp[:60] if cnp else "absent",
        "" if cnp else "kubectl apply -f soar/cilium-quarantine-policy.yaml",
    )

    cil = sh(
        f"kubectl get pods -n {TET_NS} -l k8s-app=cilium "
        f"-o jsonpath='{{.items[0].metadata.name}}'"
    ).stdout.strip()
    c.add(7, "cilium agent", "PASS" if cil else "FAIL", cil or "not found")
    if not cil:
        return

    mode = sh(
        f"kubectl get cm -n {TET_NS} cilium-config "
        f"-o jsonpath='{{.data.enable-policy}}'"
    ).stdout.strip()
    c.add(
        7,
        "policy enforcement mode",
        "PASS" if mode != "never" else "FAIL",
        mode or "unset",
        ""
        if mode != "never"
        else "policy is globally disabled; no endpoint can ever be isolated",
    )

    line = sh(
        f"kubectl exec -n {TET_NS} {cil} -c cilium-agent -- "
        # -wF: fixed string, and the match may not be flanked by a digit.
        # A plain grep for 10.42.0.11 also matches 10.42.0.115, and this check
        # was observed reporting the Postgres endpoint in place of the
        # application's for exactly that reason.
        f"cilium-dbg endpoint list 2>/dev/null | grep -wF "
        f"{ep.get('target_app_pod', 'NONE')} | head -1"
    ).stdout.strip()
    line = " ".join(line.split())
    if not line:
        c.add(
            7,
            "target endpoint known to agent",
            "FAIL",
            "no endpoint found",
            "enforcement state cannot be verified",
        )
    else:
        enforced = "Enabled" in line
        c.add(
            7,
            "target endpoint enforcement",
            "WARN" if enforced else "PASS",
            line[:90],
            "./benchmarks/reset_quarantine.sh" if enforced else "",
        )


def check_quarantine_enforcement(c: Checker, ep, log=print):
    """Destructive and self-restoring. Applies the label, waits for the agent
    to report enforcement, probes, then removes it and waits for convergence.

    Enforcement is polled rather than waited out. Adding a label changes the
    endpoint's security identity and the agent resolves it asynchronously;
    measured convergence ranged from 17 to 26 seconds, and one observation
    exceeded 25 seconds without converging at all. A probe at a fixed offset
    would sometimes sample before enforcement and report a working policy as
    inert, which is precisely the error this check exists to rule out.
    """
    c.layer(7, "Quarantine enforcement (destructive, self-restoring)")
    pod = sh(
        f"kubectl get pods -n {APP_NS} -l app=target-app "
        f"-o jsonpath='{{.items[0].metadata.name}}'"
    ).stdout.strip()
    app_ip = ep["target_app_pod"]
    ch_ip = ep["clickhouse_pod"]
    cil = sh(
        f"kubectl get pods -n {TET_NS} -l k8s-app=cilium "
        f"-o jsonpath='{{.items[0].metadata.name}}'"
    ).stdout.strip()

    def epline():
        return " ".join(
            sh(
                f"kubectl exec -n {TET_NS} {cil} -c cilium-agent -- "
                # -wF: see l7_enforcement. A prefix match here would poll an
                # endpoint belonging to a different pod and report that this
                # one never converged.
                f"cilium-dbg endpoint list 2>/dev/null | grep -wF {app_ip} "
                f"| head -1"
            ).stdout.split()
        )

    def pod_ingress():
        return (
            "OK"
            if "OK"
            in sh(
                f"kubectl run qp-{uuid.uuid4().hex[:6]} --rm -i --restart=Never "
                f"--image=busybox:1.36 --quiet -- sh -c "
                f"'wget -q -T 3 -O /dev/null http://{app_ip}:3000/api/health "
                f"&& echo OK || echo BLOCKED'",
                timeout=90,
            ).stdout
            else "BLOCKED"
        )

    def pf_ingress():
        code = ""
        for _ in range(6):
            code = sh(
                "curl -s -o /dev/null -w '%{http_code}' --max-time 3 "
                f"{APP_URL}/api/health",
                check=False,
            ).stdout.strip()
            if code == "200":
                return "OK"
            time.sleep(0.5)
        return f"BLOCKED({code})"

    def egress():
        return (
            "OK"
            if "OK"
            in sh(
                f"kubectl exec -n {APP_NS} {pod} -- sh -c "
                f"'wget -q -T 3 -O /dev/null http://{ch_ip}:8123/ping "
                f"&& echo OK || echo BLOCKED'",
                timeout=60,
            ).stdout
            else "BLOCKED"
        )

    before = (pod_ingress(), pf_ingress(), egress())
    if before != ("OK", "OK", "OK"):
        c.add(
            7,
            "quarantine precondition",
            "FAIL",
            f"pod={before[0]} pf={before[1]} egress={before[2]}",
            "traffic must flow before quarantine or a later block cannot be "
            "attributed to the response action",
        )
        return

    t0 = time.time()
    sh(f"kubectl label pod -n {APP_NS} {pod} quarantine=true --overwrite")
    for _ in range(120):
        if "Enabled" in epline():
            break
        time.sleep(0.5)
    else:
        c.add(
            7,
            "quarantine converges",
            "FAIL",
            "not enforced within 60s",
            "the response tier writes a label that enforces nothing",
        )
        sh("./benchmarks/reset_quarantine.sh", timeout=200)
        return
    t_enf = time.time() - t0

    after = (pod_ingress(), pf_ingress(), egress())
    still = "Enabled" in epline()

    rst = sh("./benchmarks/reset_quarantine.sh", timeout=200)
    time.sleep(5)
    for _ in range(10):
        recovered = (pod_ingress(), egress())
        if recovered == ("OK", "OK"):
            break
        time.sleep(2)

    severed = after[0] == "BLOCKED" and after[2] == "BLOCKED"
    c.add(7, "containment latency (apply)", "INFO", f"{t_enf:.1f}s")
    c.add(
        7,
        "pod-network traffic severed",
        "PASS" if severed else "FAIL",
        f"ingress={after[0]} egress={after[2]} still_enforced={still}",
    )
    c.add(
        7,
        "port-forward survives containment",
        "INFO" if after[1] == "OK" else "INFO",
        after[1],
        "the workload generator reaches the application through a path the "
        "policy does not govern; a deployment serving ingress over the pod "
        "network would be isolated in both directions",
    )
    c.add(
        7,
        "recovery after reset",
        "PASS" if recovered == ("OK", "OK") else "FAIL",
        f"ingress={recovered[0]} egress={recovered[1]}  "
        f"{rst.stdout.strip().splitlines()[-1] if rst.stdout.strip() else ''}",
        ""
        if recovered == ("OK", "OK")
        else "a cell starting now would collect against an isolated pod",
    )

    os.makedirs(DIAG, exist_ok=True)
    with open(f"{DIAG}/quarantine_enforcement.json", "w") as f:
        json.dump(
            {
                "app_pod": pod,
                "app_ip": app_ip,
                "before": {
                    "pod_ingress": before[0],
                    "pf_ingress": before[1],
                    "egress": before[2],
                },
                "under_enforcement": {
                    "pod_ingress": after[0],
                    "pf_ingress": after[1],
                    "egress": after[2],
                    "still_enforced": still,
                },
                "after_reset": {"pod_ingress": recovered[0], "egress": recovered[1]},
                "containment_latency_s": round(t_enf, 3),
                "measured_at": datetime.now(timezone.utc).isoformat(),
            },
            f,
            indent=2,
        )


# =====================================================================
#  LAYER 8  application
# =====================================================================
def l8_application(c: Checker, expected_objects=512, ep=None):
    c.layer(8, "Application and context bridge")
    h = app_health()
    c.add(
        8,
        "health endpoint",
        "PASS" if h.get("ok") else "FAIL",
        h.get("pod_name", str(h)[:80]),
    )
    if not h.get("ok"):
        return h

    rev = h.get("revocation", {})
    c.add(
        8,
        "revocation enforcement enabled",
        "PASS" if rev.get("enforce") else "FAIL",
        f"enforce={rev.get('enforce')} revoked={rev.get('revoked_count')} "
        f"refreshes={rev.get('refreshes')}",
        ""
        if rev.get("enforce")
        else "the user-scoped tier would record actions that never take effect",
    )
    c.add(
        8,
        "revocation store reachable",
        "PASS" if not rev.get("last_error") else "FAIL",
        f"last refresh {rev.get('last_refresh_ms_ago')}ms ago"
        if not rev.get("last_error")
        else rev["last_error"][:70],
    )

    allow = h.get("preview_allowed_endpoints") or []
    if not allow:
        c.add(
            8,
            "outbound allowlist",
            "FAIL",
            "empty",
            "every outbound fetch would be classed as a probe, so network "
            "precision would be unmeasurable",
        )
    else:
        # Non-empty is not sufficient. The allowlist holds a pod address, and
        # a pod address changes whenever the pod is rescheduled, so an
        # allowlist left over from a previous session names an endpoint that
        # no longer exists. Benign fetches would then be classed as probes
        # exactly as if the list were empty, and the check would still pass.
        #
        # The harness sets this from a freshly resolved address at the start of
        # every campaign, so this is drift between campaigns rather than within
        # one, but a reader verifying an environment before collecting would
        # see READY and collect a cell whose network precision means nothing.
        want = f"{ep['nats_pod']}:4222" if ep and ep.get("nats_pod") else ""
        stale = bool(want) and want not in allow
        c.add(
            8,
            "outbound allowlist",
            "WARN" if stale else "PASS",
            ",".join(allow) + (f"  (NATS is now at {want})" if stale else ""),
            "the permitted endpoint no longer exists; the harness corrects "
            "this at the start of a campaign, but a cell collected against "
            "this configuration would class every benign fetch as a probe"
            if stale
            else "",
        )

    # confidential_[0-9]*.pdf rather than confidential_*.pdf. The looser glob
    # also matches confidential_payroll.pdf, which is a fixture object rather
    # than one of the numbered pool the workload sweeps, so the check reported
    # 513 of 512 and the figure did not mean what the name said.
    n = sh(
        f"kubectl exec -n {APP_NS} deploy/target-app -- sh -c "
        f"'ls /tmp/confidential_[0-9]*.pdf 2>/dev/null | wc -l'"
    ).stdout.strip()
    try:
        n = int(n)
    except Exception:
        n = -1
    c.add(
        8,
        "restricted objects present",
        "PASS" if n >= expected_objects else "FAIL",
        f"{n} of {expected_objects}",
        ""
        if n >= expected_objects
        else "./benchmarks/precreate_objects.sh  (every object read would 404 and "
        "the cell would record almost nothing while appearing to run)",
    )

    out = sh(
        f"kubectl logs -n {APP_NS} deploy/target-app --tail=400 2>/dev/null "
        "| grep bridge_canary | tail -1"
    ).stdout.strip()
    if not out:
        c.add(
            8,
            "bridge canary",
            "WARN",
            "not in current log window",
            "it fires only at startup; kubectl rollout restart -n default "
            "deployment/target-app to re-check",
        )
    else:
        try:
            k = json.loads(out)
            ok = k.get("passed") is True
            c.add(
                8,
                "bridge canary",
                "PASS" if ok else "FAIL",
                f"expected={k.get('expected')} observed={k.get('observed')}",
                ""
                if ok
                else "the request identifier is not reaching child "
                "processes; the deterministic join cannot work",
            )
        except Exception:
            c.add(8, "bridge canary", "WARN", out[:70])
    return h


# =====================================================================
#  LAYER 9  pipeline configuration
# =====================================================================
def l9_pipeline(c: Checker):
    c.layer(9, "Pipeline configuration")
    v = sh(f"kubectl get cm -n {INFRA_NS} vector-config -o yaml 2>/dev/null").stdout
    for key, why in [
        ("tetragon_direct", "direct file source for kernel events"),
        (
            "app_logs",
            "application records read by the same mechanism as kernel "
            "events, measured at 14 ms against 3000 ms at p95 for the "
            "Kubernetes log source",
        ),
        (
            "glob_minimum_cooldown_ms",
            "the container runtime rotates the "
            "application log; at the default cooldown "
            "lines in a new file wait up to a second",
        ),
        ("read_from: end", "prevents replaying old logs on restart"),
        ("kernel_time", "true kernel timestamp for end-to-end latency"),
        ("collector_time", "collector receipt for the decomposition"),
        (
            '.pod_name == "unknown"',
            "host processes share this kernel and would otherwise be collected",
        ),
    ]:
        ok = key in v
        c.add(
            9,
            f"vector: {key}",
            "PASS" if ok else "FAIL",
            "present" if ok else "absent",
            ""
            if ok
            else f"kubectl apply -f pipeline/vector/vector-deployment.yaml; {why}",
        )

    hp = sh(
        f"kubectl get ds -n {INFRA_NS} vector -o jsonpath="
        f"'{{.spec.template.spec.volumes[?(@.name==\"data\")]}}'"
    ).stdout
    c.add(
        9,
        "collector checkpoints survive restart",
        "PASS" if "hostPath" in hp else "FAIL",
        "hostPath" if "hostPath" in hp else "emptyDir",
        ""
        if "hostPath" in hp
        else "an emptyDir discards file checkpoints, so a restart re-reads the "
        "application log from the beginning and floods the correlator with "
        "stale records",
    )

    rot = sh(
        "kubectl exec -n sarvajna-infra ds/vector -- sh -c "
        "'ls /var/log/pods/default_target-app-*/nextjs/ 2>/dev/null | wc -l'",
        check=False,
    ).stdout.strip()
    c.add(
        9,
        "application log rotation state",
        "INFO",
        f"{rot} file(s) in the log directory",
    )

    leaked = chq(
        "SELECT count() FROM sarvajna.raw_telemetry "
        "WHERE source='kernel' AND pod_name='unknown' "
        "AND ingest_time > now() - INTERVAL 30 MINUTE"
    )
    c.add(
        9,
        "no host telemetry collected",
        "PASS" if leaked in ("0", None) else "FAIL",
        f"{leaked} unresolved kernel events in the last 30 min",
        ""
        if leaked in ("0", None)
        else "host activity is being persisted; the ethics statement and the "
        "latency measurements both depend on this being zero",
    )

    for dep, keys in [
        (
            "sarvajna-cep",
            [
                "JOIN_MODE",
                "CORRELATION_WINDOW_MS",
                "PENDING_EXECVE_HORIZON_MS",
                "IGNORE_DADDRS",
            ],
        ),
        (
            "soar-worker",
            [
                "ENRICH_RETRIES",
                "ENFORCE_REVOCATION",
                "TIER2_ENABLED",
                "ACT_ON_UNCORRELATED",
            ],
        ),
    ]:
        env = sh(
            f"kubectl set env -n {INFRA_NS} deployment/{dep} --list 2>/dev/null"
        ).stdout
        for k in keys:
            line = [l for l in env.splitlines() if l.startswith(k + "=")]
            c.add(
                9,
                f"{dep} {k}",
                "PASS" if line else "WARN",
                line[0][:60] if line else "unset (set per cell by the harness)",
            )

    q = sh(
        f"kubectl get pods -n {APP_NS} -l app=target-app "
        "-o jsonpath='{.items[*].metadata.labels.quarantine}'"
    ).stdout.strip()
    c.add(
        9,
        "target not quarantined",
        "PASS" if not q else "FAIL",
        "clean" if not q else f"quarantine={q}",
        "" if not q else "./benchmarks/reset_quarantine.sh",
    )


# =====================================================================
#  LAYER 10  end to end
# =====================================================================
def l10_smoke(c: Checker, ep, n_each=10, log=print):
    """Fires attacks and authorised requests, then checks three things the
    static layers cannot: that attacks are attributed, that authorised traffic
    producing identical kernel evidence is not, and that requests are actually
    delivered.

    The last matters because a request that never reached the application looks
    exactly like one the correlator failed to detect. Measured once at 0.86
    recall, entirely explained by connection failures in the first 1.5 s of a
    run.
    """
    c.layer(10, f"End to end ({n_each} of each request type)")
    vid = f"VERIFY-{datetime.now():%Y%m%d-%H%M%S}"
    configure_cep(
        vid,
        "deterministic",
        10000,
        10000,
        f"{ep['postgres_pod']},{ep['postgres_svc']}",
        log=log,
    )
    configure_soar(vid, 0, 1, enforce=False, tier2=False)
    purge_streams()
    sh(
        f"kubectl exec -n {INFRA_NS} deploy/postgres -- psql -U sarvajna "
        f"-d sarvajna_db -c 'TRUNCATE revocations;'"
    )
    time.sleep(15)

    ch_pod = ep["clickhouse_pod"]
    nats_pod = ep["nats_pod"]
    ids = {k: [] for k in ("rce", "bola", "ssrf", "ok_file", "ok_net")}
    delivered = {k: 0 for k in ids}

    def fire(cmd):
        return sh(cmd, timeout=30).stdout.strip()

    # Warm the connection first: the access path refuses a share of
    # simultaneous connections, and those failures would be indistinguishable
    # from detection failures.
    for _ in range(10):
        if (
            fire(f"curl -s -o /dev/null -w '%{{http_code}}' {APP_URL}/api/health")
            == "200"
        ):
            break
        time.sleep(0.5)

    for i in range(n_each):
        a = {k: f"verify-{k}-{uuid.uuid4().hex[:8]}" for k in ids}
        obj = f"confidential_{300 + i}.pdf"
        port = 30000 + i

        delivered["rce"] += (
            fire(
                f"curl -s -o /dev/null -w '%{{http_code}}' -X POST {APP_URL}/api/ping "
                f"-H 'Content-Type: application/json' -H 'x-attack-id: {a['rce']}' "
                f'-d \'{{"host":"127.0.0.1; whoami","userId":"verify_attacker",'
                f'"tenantId":"adversary_corp","attackId":"{a["rce"]}"}}\''
            )
            == "200"
        )
        delivered["bola"] += (
            fire(
                f"curl -s -o /dev/null -w '%{{http_code}}' "
                f"'{APP_URL}/api/reports?file={obj}' -H 'x-attack-id: {a['bola']}' "
                f"-H 'x-user-id: verify_attacker' -H 'x-tenant-id: adversary_corp'"
            )
            == "200"
        )
        delivered["ok_file"] += (
            fire(
                f"curl -s -o /dev/null -w '%{{http_code}}' "
                f"'{APP_URL}/api/reports?file={obj}' -H 'x-attack-id: {a['ok_file']}' "
                f"-H 'x-user-id: victim_user_1' -H 'x-tenant-id: tenant_victim'"
            )
            == "200"
        )
        delivered["ssrf"] += (
            fire(
                f"curl -s -o /dev/null -w '%{{http_code}}' -X POST {APP_URL}/api/preview "
                f"-H 'Content-Type: application/json' -H 'x-attack-id: {a['ssrf']}' "
                f'-d \'{{"targetUrl":"http://{ch_pod}:{port}/",'
                f'"userId":"verify_attacker","tenantId":"adversary_corp",'
                f'"attackId":"{a["ssrf"]}"}}\''
            )
            == "200"
        )
        delivered["ok_net"] += (
            fire(
                f"curl -s -o /dev/null -w '%{{http_code}}' -X POST {APP_URL}/api/preview "
                f"-H 'Content-Type: application/json' -H 'x-attack-id: {a['ok_net']}' "
                f'-d \'{{"targetUrl":"http://{nats_pod}:4222/",'
                f'"userId":"legit_user_5","tenantId":"tenant_3",'
                f'"attackId":"{a["ok_net"]}"}}\''
            )
            == "200"
        )
        for k in ids:
            ids[k].append(a[k])
        time.sleep(0.2)

    total = n_each * 5
    deliv_total = sum(delivered.values())
    c.add(
        10,
        "requests delivered",
        "PASS" if deliv_total == total else "FAIL",
        f"{deliv_total}/{total}",
        ""
        if deliv_total == total
        else "undelivered requests are indistinguishable from undetected attacks",
    )

    log(f"      waiting up to 60s for correlation ...")
    want = {"rce": "trace_id", "bola": "file_path", "ssrf": "dest_endpoint"}
    hits = {k: {} for k in ids}
    waited = 0
    while waited < 60:
        time.sleep(10)
        waited += 10
        for k, lst in ids.items():
            pending = [i for i in lst if i not in hits[k]]
            if not pending:
                continue
            rows = chq(
                "SELECT attack_id, matched_on, user_id, isNotNull(t_app_emit) "
                "FROM sarvajna.detections WHERE attack_id IN ('"
                + "','".join(pending)
                + "') AND correlated=1"
            )
            for line in (rows or "").splitlines():
                p = line.split("\t")
                if len(p) >= 4:
                    hits[k][p[0]] = p[1:]
        if all(len(hits[k]) >= delivered[k] for k in ("rce", "bola", "ssrf")):
            break

    # Allow the correlation window (10s) + idle grace (2s) to drain held events
    time.sleep(15)

    for k in ("rce", "bola", "ssrf"):
        got, exp = len(hits[k]), delivered[k]
        pred_ok = all(v[0] == want[k] for v in hits[k].values())
        status = "PASS" if (got == exp and pred_ok and exp > 0) else "FAIL"
        sample = next(iter(hits[k].values()), ["-", "-", "-"])
        c.add(
            10,
            f"{k.upper()} attributed",
            status,
            f"{got}/{exp} detected  matched_on={sample[0]}  user={sample[1]}",
            ""
            if status == "PASS"
            else f"expected every delivered attack to correlate on {want[k]}",
        )

    for k, label in (("ok_file", "authorised read"), ("ok_net", "allowed fetch")):
        n = len(hits[k])
        c.add(
            10,
            f"{label} not attributed",
            "PASS" if n == 0 else "FAIL",
            f"{n} of {delivered[k]} correlated",
            ""
            if n == 0
            else "authorised traffic produced the same kernel evidence as an "
            "attack and was attributed; precision is not being measured",
        )

    revs = chq(
        f"SELECT count(), uniqExact(principal_user) FROM "
        f"sarvajna.revocations WHERE run_id='{vid}'"
    )
    c.add(10, "revocations recorded", "INFO", revs or "none")

    # One kernel event, one outcome. The correlator's counters are cumulative
    # since pod start and configure_cep restarted it, so they describe this
    # check alone. An event reported unmatched and later matched would make the
    # outcome total exceed the row count; an event held and never flushed would
    # make it fall short.
    import re as _re

    cep = sh(
        f"kubectl logs -n {INFRA_NS} deploy/sarvajna-cep --tail=40 "
        "2>/dev/null | grep '\\[CEP\\]' | tail -1"
    ).stdout.strip()
    rows = chq(f"SELECT count() FROM sarvajna.detections WHERE run_id='{vid}'")
    outcomes = sum(
        int(v) for k, v in _re.findall(r"'(match_[a-z_]+|nomatch_[a-z_]+)': (\d+)", cep)
    )
    held = _re.search(r"held=(\d+)", cep)
    held = int(held.group(1)) if held else -1
    c.add(
        10,
        "one outcome per kernel event",
        "PASS" if rows and outcomes == int(rows) else "FAIL",
        f"{outcomes} outcomes, {rows} detection rows",
        ""
        if rows and outcomes == int(rows)
        else "reason codes do not partition the events; an event is being "
        "reported twice or held and never flushed",
    )
    c.add(
        10,
        "buffer drained with no traffic",
        "PASS" if held == 0 else "FAIL",
        f"held={held}",
        ""
        if held == 0
        else "events waiting for a partner are never reported once telemetry "
        "stops, which is exactly the end of a collection period",
    )
    ig = _re.search(r"'ignored_infra_connect': (\d+)", cep)
    c.add(
        10,
        "infrastructure connections excluded",
        "INFO",
        ig.group(1) if ig else "0 (connection pool stayed warm)",
    )

    dup = chq(
        f"SELECT alert_type, count(), uniqExact(attack_id) FROM "
        f"sarvajna.detections WHERE run_id='{vid}' AND correlated=1 "
        f"GROUP BY alert_type"
    )
    bad = [
        l
        for l in (dup or "").splitlines()
        if len(l.split("\t")) == 3 and l.split("\t")[1] != l.split("\t")[2]
    ]
    c.add(
        10,
        "no duplicate correlations",
        "PASS" if not bad else "FAIL",
        (dup or "none").replace("\n", "  "),
        ""
        if not bad
        else "an application record matched more than once; counts collapse under "
        "the analysis join so metrics survive, but the partition does not",
    )

    for t in ("detections", "revocations"):
        chq(f"ALTER TABLE sarvajna.{t} DELETE WHERE run_id='{vid}'")
    sh(
        f"kubectl exec -n {INFRA_NS} deploy/postgres -- psql -U sarvajna "
        f"-d sarvajna_db -c 'TRUNCATE revocations;'"
    )


def l11_revocation_effect(c: Checker, ep, log=print):
    """Proves a revocation refuses a later request.

    The smoke test runs without enforcement, so it establishes only that a row
    is written. Whether the row has any effect is a separate property, and it
    is the one the user-scoped response tier depends on."""
    c.layer(11, "Revocation takes effect")
    vid = f"REVOK-{datetime.now():%Y%m%d-%H%M%S}"
    user = f"revoke_probe_{uuid.uuid4().hex[:6]}"
    configure_cep(
        vid,
        "deterministic",
        10000,
        10000,
        f"{ep['postgres_pod']},{ep['postgres_svc']}",
        log=log,
    )
    configure_soar(vid, 0, 1, enforce=True, tier2=False)
    purge_streams()
    sh(
        f"kubectl exec -n {INFRA_NS} deploy/postgres -- psql -U sarvajna "
        f"-d sarvajna_db -c 'TRUNCATE revocations;'"
    )
    time.sleep(15)

    pre = sh(
        f"curl -s -o /dev/null -w '%{{http_code}}' "
        f"'{APP_URL}/api/reports?file=default.txt' "
        f"-H 'x-user-id: {user}' -H 'x-tenant-id: tenant_1'"
    ).stdout.strip()
    c.add(
        11,
        "principal serves before revocation",
        "PASS" if pre == "200" else "FAIL",
        f"HTTP {pre}",
    )

    sh(
        f"curl -s -o /dev/null -X POST {APP_URL}/api/ping "
        f"-H 'Content-Type: application/json' "
        f'-d \'{{"host":"127.0.0.1; whoami","userId":"{user}",'
        f'"tenantId":"adversary_corp","attackId":"{vid}-atk"}}\''
    )

    t0, blocked_at, code = time.time(), None, ""
    while time.time() - t0 < 60:
        code = sh(
            f"curl -s -o /dev/null -w '%{{http_code}}' "
            f"'{APP_URL}/api/reports?file=default.txt' "
            f"-H 'x-user-id: {user}' -H 'x-tenant-id: tenant_1'"
        ).stdout.strip()
        if code == "403":
            blocked_at = time.time() - t0
            break
        time.sleep(0.25)

    c.add(
        11,
        "principal refused after revocation",
        "PASS" if blocked_at is not None else "FAIL",
        f"HTTP {code} after {blocked_at:.2f}s"
        if blocked_at is not None
        else f"still HTTP {code} after 60s",
        ""
        if blocked_at is not None
        else "the user-scoped tier records actions that never take effect",
    )
    if blocked_at is not None:
        c.add(11, "revocation effect latency", "INFO", f"{blocked_at:.2f}s")

    sh(
        f"kubectl exec -n {INFRA_NS} deploy/postgres -- psql -U sarvajna "
        f"-d sarvajna_db -c 'TRUNCATE revocations;'"
    )
    for t in ("detections", "revocations"):
        chq(f"ALTER TABLE sarvajna.{t} DELETE WHERE run_id='{vid}'")


# =====================================================================
#  ORCHESTRATION
# =====================================================================
def run_static(c: Checker, expected_objects=512):
    """Read-only layers. Safe at any time, including between cells."""
    l0_tooling(c)
    l1_cluster(c)
    ep = l2_network(c)
    l3_storage(c)
    l4_revocation_store(c)
    l5_messaging(c)
    l6_ebpf(c)
    if ep:
        l7_enforcement(c, ep)
    l8_application(c, expected_objects, ep)
    l9_pipeline(c)
    return ep


def summarise(c: Checker, path=None):
    fails, warns = c.failures(), c.warnings()
    passes = [r for r in c.results if r.status == "PASS"]
    print(f"\n{B}{'=' * 70}{X}")
    print(
        f"  {G}PASS {len(passes)}{X}   {Y}WARN {len(warns)}{X}   {RD}FAIL {len(fails)}{X}"
    )
    if fails:
        print(f"\n  {RD}BLOCKING:{X}")
        for r in fails:
            print(f"    - [{r.layer}] {r.name}: {r.observed}")
            if r.remedy:
                print(f"        -> {r.remedy}")
    if warns:
        print(f"\n  {Y}NON-BLOCKING:{X}")
        for r in warns:
            print(f"    - [{r.layer}] {r.name}: {r.observed}")
    verdict = "NOT READY" if fails else ("READY (with warnings)" if warns else "READY")
    print(f"\n  {B}VERDICT: {verdict}{X}\n{B}{'=' * 70}{X}")

    if path:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(
                {
                    "at": datetime.now(timezone.utc).isoformat(),
                    "verdict": verdict,
                    "checks": [asdict(r) for r in c.results],
                },
                f,
                indent=2,
            )
        print(f"  report: {path}\n")
    return verdict, fails, warns
