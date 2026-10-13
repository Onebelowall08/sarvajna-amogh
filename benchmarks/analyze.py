#!/usr/bin/env python3
"""
Sarvajna-Amogh: offline analysis.

THE LEDGER IS THE AUTHORITY
---------------------------
A cell is included only if the collection harness recorded it as passed. Failed
attempts leave their diagnostic JSON on disk after their rows are purged, so
globbing benchmarks/diag/ would read three cells that no longer exist in the
database. Every query here filters on run identifiers taken from the ledger.

WHAT IS COUNTED, AND WHAT IS NOT
--------------------------------
A ground-truth row is detected if any detection carrying its attack identifier
is correlated. Rows are joined on the identifier alone within a cell, because
the cell's run identifier already scopes both sides.

Three populations are reported separately rather than folded into precision:

  forgery_recon   A benign request whose identifier the attacker copied. The
                  correlator pairs the attacker's execution with this victim's
                  record, so the row is correlated against a benign label. It
                  is misattribution, which the adversarial condition exists to
                  measure, not a discrimination failure.

  RCE_FORGERY     The attacker's own request. Its execution declares the
                  victim's identifier, so no detection ever carries the
                  attacker's. Recall against this class is zero by
                  construction: the attack is detected, the attacker is not.

  RCE_EVASION_STRIP
                  The execution carries no identifier at all and is reported
                  unattributed. Recall is zero because the system declines to
                  attribute rather than attributing wrongly.

THREE RECALL FIGURES, NOT ONE
-----------------------------
recall              over the three primary attack classes, comparable across
                    the configurations that issue no adversarial traffic
attribution_recall  over every attack the cell issued, so the adversarial
                    configurations include their stripped and forged attempts
detection_recall    counts an alert as raised even where it named the wrong
                    principal; the gap to attribution_recall is what the
                    forgery achieved

A single figure over the primary classes would report the adversarial cell at
1.000 while 784 of its attacks went unattributed, flattering the configuration
built to defeat attribution.

SINGLE REPETITION
-----------------
One collection per cell. Proportions carry a Wilson interval, which describes
sampling uncertainty within the several hundred attempts the cell issued. No
interval describes variation between repetitions, because one collection
cannot estimate it, and no difference between cells is claimed to be
statistically significant.

Usage:
    python benchmarks/analyze.py --suite S20261006-134605
"""

import argparse
import json
import math
import os
import sys

import pandas as pd
from clickhouse_driver import Client

CH = dict(host="127.0.0.1", port=9000, user="default", password="amogh_secure_pwd")
DIAG = "benchmarks/diag"
OUT = "benchmarks/figures_final"

ATTACK_CLASSES = [
    "BOLA_AUTHORIZATION_BYPASS",
    "SSRF_UNAUTHORIZED_PROBE",
    "RCE_COMMAND_INJECTION",
]
ADVERSARIAL_CLASSES = ["RCE_EVASION_STRIP", "RCE_FORGERY"]
# Benign rows the attacker targeted. Correlated by design, excluded from the
# precision denominator and reported as misattribution.
MISATTRIBUTION_CLASS = "forgery_recon"
BENIGN_CLASSES = ["none", "authorized_access", "allowed_fetch"]


def wilson(k, n, z=1.96):
    """Wilson score interval for a proportion.

    Correct at the boundaries, where the normal approximation puts bounds
    outside [0, 1]. Several figures here are exactly 0 or exactly 1: the
    proximity baseline attributes no process execution at all, and the bridge
    attributes every one, so an interval that cannot represent those honestly
    is useless.

    This describes sampling uncertainty in the proportion, which is a property
    of the several hundred attempts in the cell and is reportable whether the
    cell was collected once or ten times. It says nothing about variation
    between repetitions, which one collection cannot estimate.
    """
    if not n:
        return (None, None)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4))


def load_cells(suite):
    """The cells the harness verified, in plan order, warm-up excluded."""
    p = f"{DIAG}/{suite}_ledger.json"
    if not os.path.exists(p):
        sys.exit(
            f"No ledger at {p}. Analysis needs the harness's own record of "
            f"which cells passed."
        )
    with open(p) as f:
        led = json.load(f)

    results = led.get("results", {})
    cells = []
    for entry in led["plan"]:
        key = entry["key"]
        res = results.get(key)
        if not res or not res.get("passed"):
            print(f"  excluded (not verified): {key}")
            continue
        cfg = entry["cell"]
        if cfg["name"] == "WARMUP":
            print(f"  excluded (warm-up): {key}")
            continue
        cells.append({
            "key": key,
            "cell": cfg["name"],
            "rep": entry["rep"],
            "run_id": res["run_id"],
            "mode": cfg["join_mode"],
            "window_ms": cfg["window_ms"],
            "horizon_ms": cfg["pending_ms"] or cfg["window_ms"],
            "enrich_retries": cfg["enrich"][0],
            "enrich_delay_s": cfg["enrich"][1],
            "adversarial": cfg["adversarial"],
            "enforce": cfg["enforce"],
            "tier2": cfg["tier2"],
            "users": cfg["users"],
            "duration": cfg["duration"],
        })
    return led, cells


def confusion(ch, run_id):
    """One row per (attack_type, label) with how many were detected.

    The aggregate over detections collapses a class that produced several
    kernel events from one request, so a request counts once however many
    events it generated.
    """
    rows = ch.execute(
        "WITH det AS ("
        "  SELECT attack_id, max(correlated) AS c, "
        "         anyIf(matched_on, correlated = 1) AS predicate "
        "  FROM sarvajna.detections "
        "  WHERE run_id = %(r)s AND attack_id != '' AND attack_id IS NOT NULL "
        "  GROUP BY attack_id) "
        # label is Enum8('benign' = 0, 'attack' = 1), and the driver returns the
        # name rather than the ordinal, so it arrives in Python as a string.
        # Converting to the underlying integer in SQL keeps the rest of this
        # module working on 0 and 1, and reads the enum's own ordinal rather
        # than comparing against a spelling a later schema change could alter.
        "SELECT g.attack_type, toUInt8(g.label) AS lbl, "
        "       count(), countIf(det.c = 1), "
        "       countIf(g.blocked = 1), "
        "       countIf(g.blocked = 1 AND det.c = 1), "
        "       anyIf(det.predicate, det.c = 1) "
        "FROM sarvajna.ground_truth g "
        "LEFT JOIN det ON g.attack_id = det.attack_id "
        "WHERE g.run_id = %(r)s "
        "GROUP BY g.attack_type, lbl "
        "SETTINGS join_use_nulls = 1",
        {"r": run_id},
    )
    return [
        {
            "attack_type": a,
            "label": int(lbl),
            "n": int(n),
            "detected": int(d),
            "blocked": int(b),
            "blocked_and_detected": int(bd),
            "predicate": pred or "",
        }
        for a, lbl, n, d, b, bd, pred in rows
    ]


def latency(ch, run_id):
    """Per class, with the three owners of the end-to-end figure separated.

    spawn is the application's: the interval between writing its own record and
    the kernel observing the process it started. export is the kernel
    observability layer's. The remainder is this work's.
    """
    rows = ch.execute(
        "SELECT alert_type, count(), "
        # the application's own cost: record written, process not yet observed
        "round(quantile(0.50)(dateDiff('millisecond', t_app_emit, t_kernel_true))), "
        "round(quantile(0.95)(dateDiff('millisecond', t_app_emit, t_kernel_true))), "
        # the observability layer's: kernel observes, collector receives
        "round(quantile(0.50)(dateDiff('millisecond', t_kernel_true, t_collector))), "
        "round(quantile(0.95)(dateDiff('millisecond', t_kernel_true, t_collector))), "
        # this work's, decomposed
        "round(quantile(0.50)(dateDiff('millisecond', t_collector, t_kernel))), "
        "round(quantile(0.95)(dateDiff('millisecond', t_collector, t_kernel))), "
        "round(quantile(0.50)(dateDiff('millisecond', t_kernel, t_correlate))), "
        "round(quantile(0.95)(dateDiff('millisecond', t_kernel, t_correlate))), "
        "round(quantile(0.50)(dateDiff('millisecond', t_correlate, t_action))), "
        "round(quantile(0.95)(dateDiff('millisecond', t_correlate, t_action))), "
        # this work's, end to end
        "round(quantile(0.50)(mttr_pipeline_ms)), "
        "round(quantile(0.95)(mttr_pipeline_ms)), "
        "round(quantile(0.99)(mttr_pipeline_ms)), "
        # everything, as the application experiences it
        "round(quantile(0.50)(mttr_app_ms)), "
        "round(quantile(0.95)(mttr_app_ms)) "
        "FROM sarvajna.detections "
        "WHERE run_id = %(r)s AND correlated = 1 "
        "  AND t_kernel_true IS NOT NULL AND t_app_emit IS NOT NULL "
        "  AND mttr_pipeline_ms IS NOT NULL "
        "GROUP BY alert_type",
        {"r": run_id},
    )
    names = (
        "n",
        "spawn_p50",
        "spawn_p95",
        "export_p50",
        "export_p95",
        "collect_p50",
        "collect_p95",
        "correlate_p50",
        "correlate_p95",
        "act_p50",
        "act_p95",
        "pipeline_p50",
        "pipeline_p95",
        "pipeline_p99",
        "e2e_p50",
        "e2e_p95",
    )
    return [dict(zip(("alert_type",) + names, (a,) + tuple(r))) for a, *r in rows]


def pairing(ch, run_id):
    """Kernel events paired with a record from a different request.

    The proxy is a gap above 100 ms between the application's timestamp and the
    kernel's. It separates cleanly for the resource-identity predicates, where
    a mispairing lands on whatever request last touched the same object. It
    does NOT separate for proximity matching: once collection latency fell to
    3 ms and the workload reached roughly 170 requests per second, an unrelated
    request's record is usually within 100 ms, so the proxy reports near zero
    for a predicate whose misattribution is established instead by its false
    positives and by the collateral damage it causes under enforcement. The
    proxy_valid column records which case each row is.
    """
    rows = ch.execute(
        "SELECT matched_on, count(), "
        "countIf(abs(dateDiff('millisecond', t_app_emit, t_kernel_true)) > 100) "
        "FROM sarvajna.detections "
        "WHERE run_id = %(r)s AND correlated = 1 "
        "  AND t_kernel_true IS NOT NULL AND t_app_emit IS NOT NULL "
        "GROUP BY matched_on",
        {"r": run_id},
    )
    return [
        {
            "predicate": m,
            "n": int(n),
            "crossed": int(x),
            "pct": round(100 * x / n, 2) if n else 0.0,
            "proxy_valid": m not in ("temporal",),
        }
        for m, n, x in rows
    ]


def collection(run_id):
    """Collection delay by event type, taken from the cell's own snapshot.

    Recomputing it here would need the cell's time bounds, and the snapshot
    already holds the figure computed with them: bounded on both the event time
    and the collection time, so telemetry produced before the cell and still
    draining through the collector is excluded.

    Joining the telemetry to ground truth by attack identifier would not work
    in its place. An application record carries that identifier; a kernel event
    does not, because the exporter has no knowledge of the request header that
    set it. The join would return application rows only, and the process-export
    cost that the enrichment sweep exists to measure would vanish.
    """
    p = f"{DIAG}/{run_id}.json"
    if not os.path.exists(p):
        return []
    with open(p) as f:
        snap = json.load(f)
    cd = snap.get("collection_delay_ms") or {}
    if not isinstance(cd, dict):
        return []
    out = []
    for key, v in cd.items():
        if not isinstance(v, dict) or "p50" not in v:
            continue
        src, _, et = key.partition("/")
        out.append({
            "source": src,
            "event_type": et,
            "n": v.get("n"),
            "p50": v.get("p50"),
            "p95": v.get("p95"),
            "p99": v.get("p99"),
        })
    return out


def revocation_effect(ch, run_id):
    """How long after a revocation the principal was actually refused.

    Bounded on both sides rather than reported as a point estimate. The lower
    bound is the last request that principal still had served after the action;
    the upper bound is the first that was refused. Enforcement took effect
    somewhere between them, and the width of that gap is the principal's own
    request interval rather than a property of the pipeline.

    The request that triggered the revocation is excluded. It was answered
    before the action was taken, but the workload generator writes its
    ground-truth row only once the response has returned, so for a small
    fraction of attacks that row carries a timestamp later than the action it
    provoked: measured 12 of 1635 principals in the deterministic enforcement
    cell. Counting it would report a principal that never returned as having
    transacted again and escaped enforcement.

    A principal who genuinely never transacts again is recorded with a refusal
    count of zero rather than dropped. That case is the finding of the
    enforcement cells, not missing data.

    Computed in Python rather than SQL because each comparison is against that
    principal's own action time, and both populations are small: at most a few
    thousand revocations and a few thousand requests in a cell.
    """
    revs = ch.execute(
        "SELECT principal_user, min(t_action), any(attack_id) "
        "FROM sarvajna.revocations WHERE run_id = %(r)s GROUP BY principal_user",
        {"r": run_id},
    )
    if not revs:
        return []
    rows = ch.execute(
        "SELECT user_id, attack_id, t_sent, blocked "
        "FROM sarvajna.ground_truth WHERE run_id = %(r)s",
        {"r": run_id},
    )
    by_user = {}
    for user, aid, t_sent, blocked in rows:
        by_user.setdefault(user, []).append((t_sent, aid, int(blocked)))

    out = []
    for principal, t_action, trigger_aid in revs:
        after = [
            (t, b)
            for t, aid, b in sorted(by_user.get(principal, []))
            if t > t_action and aid != trigger_aid
        ]
        refused = [t for t, b in after if b == 1]
        if not refused:
            out.append({
                "principal": principal,
                "requests_after": len(after),
                "refused": 0,
                "upper_ms": None,
                "lower_ms": None,
            })
            continue
        t_first_refused = min(refused)
        served = [t for t, b in after if b == 0 and t < t_first_refused]
        out.append({
            "principal": principal,
            "requests_after": len(after),
            "refused": len(refused),
            "upper_ms": (t_first_refused - t_action).total_seconds() * 1000.0,
            "lower_ms": (
                (max(served) - t_action).total_seconds() * 1000.0 if served else 0.0
            ),
        })
    return out


def resources(run_id):
    """Per-component CPU and memory for the cell, from its own snapshot.

    Recorded by the harness as a cgroup counter delta across the cell rather
    than sampled from the cluster metrics interface, which computes a rate
    between scrapes roughly fifteen seconds apart and therefore returns
    whatever the last scrape happened to catch for a cell shorter than that:
    measured 2, 55 and 1 millicores for the same component under three
    identical workloads.

    The memory column is the cgroup high-water mark since the container
    started, and it includes reclaimable page cache. It rises monotonically
    whatever the load, so it is a bound rather than a working set and is
    labelled as such wherever it is reported.
    """
    p = f"{DIAG}/{run_id}.json"
    if not os.path.exists(p):
        return []
    with open(p) as f:
        snap = json.load(f)
    res = snap.get("resources") or {}
    if not isinstance(res, dict):
        return []
    out = []
    for comp, v in res.items():
        if not isinstance(v, dict):
            continue
        out.append({
            "component": comp,
            "cpu_seconds": v.get("cpu_seconds"),
            "mean_millicores": v.get("mean_millicores"),
            "mem_peak_mib": v.get("mem_peak_mib"),
        })
    return out


def forgery_audit(ch, run_ids):
    """Where attribution landed when the identifier was forged.

    Joins the victim's own identifier, recorded in ground truth when the
    attacker harvested it, to the principal the correlator named. This is
    direct evidence rather than inference: it shows the alert fired and names
    the party it accused.
    """
    if not run_ids:
        return {}
    rows = ch.execute(
        "SELECT count(), countIf(d.trace_id != ''), "
        "       countIf(d.user_id = g.victim_user), "
        "       countIf(d.user_id = g.user_id) "
        "FROM sarvajna.ground_truth g "
        "LEFT JOIN (SELECT trace_id, argMin(user_id, t_correlate) AS user_id "
        "           FROM sarvajna.detections "
        "           WHERE run_id IN %(ids)s "
        "             AND alert_type = 'RCE_COMMAND_INJECTION' AND correlated = 1 "
        "           GROUP BY trace_id) d ON g.victim_trace = d.trace_id "
        "WHERE g.run_id IN %(ids)s AND g.attack_type = 'RCE_FORGERY' "
        "SETTINGS join_use_nulls = 1",
        {"ids": tuple(run_ids)},
    )
    attempted, correlated, misattributed, correct = (int(v) for v in rows[0])
    return {
        "attempted": attempted,
        "correlated_via_forged_token": correlated,
        "attributed_to_victim": misattributed,
        "attributed_to_attacker": correct,
        "misattribution_rate": (
            round(misattributed / correlated, 4) if correlated else None
        ),
    }


def check_invariants(cells, metrics):
    """Re-assert from the stored rows what the harness gated on at collection.

    The harness already refused to continue past a cell that violated these, so
    a failure here would mean the archive does not say what the harness saw. It
    is restated so a reader can verify the central structural claim from the
    exported data alone, without the collection logs.
    """
    print(f"\n{'=' * 74}\n  STRUCTURAL INVARIANTS\n{'=' * 74}")
    ok = True
    by_cell = {m["cell"]: m for m in metrics if m["class"] == "RCE_COMMAND_INJECTION"}

    for c in cells:
        m = by_cell.get(c["cell"])
        if not m:
            continue
        if c["mode"] in ("temporal", "spatial"):
            good = m["detected"] == 0
            ok &= good
            print(
                f"  [{'PASS' if good else 'FAIL'}] {c['cell']:<28} "
                f"execution TP = {m['detected']}/{m['attempts']} "
                f"({c['mode']} cannot bind an execution)"
            )
        elif c["mode"] == "deterministic" and m["attempts"]:
            good = m["detected"] == m["attempts"]
            ok &= good
            print(
                f"  [{'PASS' if good else 'FAIL'}] {c['cell']:<28} "
                f"execution TP = {m['detected']}/{m['attempts']} "
                f"(declared identifier binds every execution)"
            )

    for c in cells:
        if c["mode"] != "temporal" and c["fp"]:
            ok = False
            print(
                f"  [FAIL] {c['cell']:<28} {c['fp']} false positive(s) under "
                f"{c['mode']} mode"
            )

    print(f"\n  VERDICT: {'invariants hold' if ok else 'INVARIANT VIOLATED'}")
    return ok


def analyse(suite):
    os.makedirs(OUT, exist_ok=True)
    ch = Client(**CH)
    print(f"\n{'=' * 74}\n  ANALYSIS  suite {suite}\n{'=' * 74}")
    led, cells = load_cells(suite)
    print(f"  {len(cells)} cells under analysis\n")

    conf_rows, metric_rows, lat_rows, pair_rows, coll_rows = [], [], [], [], []
    rev_rows, res_rows = [], []

    for c in cells:
        rid = c["run_id"]
        conf = confusion(ch, rid)

        tp = fn = fp = 0
        misattributed = 0
        blocked_attacks = 0
        per_class = {}

        # A type in no category is silently excluded from every pooled figure
        # below, which is how an added attack class would quietly stop being
        # counted. Named rather than dropped.
        known = (
            set(ATTACK_CLASSES)
            | set(ADVERSARIAL_CLASSES)
            | set(BENIGN_CLASSES)
            | {MISATTRIBUTION_CLASS}
        )
        unknown = {r["attack_type"] for r in conf} - known
        if unknown:
            print(
                f"  !! {c['cell']}: attack_type(s) in no category: "
                f"{sorted(unknown)}. They enter no pooled figure. Classify "
                f"them before reporting."
            )

        for row in conf:
            at, lbl = row["attack_type"], row["label"]
            rec = dict(row)
            rec.update({
                k: c[k]
                for k in (
                    "key",
                    "cell",
                    "mode",
                    "window_ms",
                    "horizon_ms",
                    "enrich_retries",
                    "enrich_delay_s",
                    "adversarial",
                    "enforce",
                    "tier2",
                )
            })
            conf_rows.append(rec)

            if lbl == 1:
                blocked_attacks += row["blocked"]
                if at in ATTACK_CLASSES:
                    tp += row["detected"]
                    fn += row["n"] - row["detected"]
                per_class[at] = row
            else:
                if at == MISATTRIBUTION_CLASS:
                    misattributed += row["detected"]
                else:
                    fp += row["detected"]

        for at in ATTACK_CLASSES + ADVERSARIAL_CLASSES:
            row = per_class.get(at)
            if not row:
                continue
            n, det = row["n"], row["detected"]
            recall = det / n if n else None
            lo, hi = wilson(det, n)
            metric_rows.append({
                "key": c["key"],
                "cell": c["cell"],
                "mode": c["mode"],
                "window_ms": c["window_ms"],
                "horizon_ms": c["horizon_ms"],
                "enrich_retries": c["enrich_retries"],
                "enrich_delay_s": c["enrich_delay_s"],
                "adversarial": c["adversarial"],
                "enforce": c["enforce"],
                "class": at,
                "attempts": n,
                "detected": det,
                "blocked": row["blocked"],
                "recall": round(recall, 4) if recall is not None else None,
                "recall_lo": lo,
                "recall_hi": hi,
                "predicate": row["predicate"],
            })

        precision = tp / (tp + fp) if (tp + fp) else None
        recall_all = tp / (tp + fn) if (tp + fn) else None

        # Every attack the cell issued, including the evasion and forgery
        # variants. The primary-class denominator above excludes those, so a
        # cell built to defeat attribution would report perfect recall while
        # none of its evasion attempts were attributed.
        #
        # Two questions are separated because they have different answers. An
        # alert raised against the wrong principal is a detection that happened
        # and an attribution that failed; a stripped execution is neither.
        attack_total = sum(r["n"] for r in conf if r["label"] == 1)
        alerts = tp + misattributed
        attribution_recall = tp / attack_total if attack_total else None
        detection_recall = alerts / attack_total if attack_total else None

        f1 = (
            2 * precision * attribution_recall / (precision + attribution_recall)
            if precision and attribution_recall
            else None
        )
        p_lo, p_hi = wilson(tp, tp + fp)
        r_lo, r_hi = wilson(tp, tp + fn)
        ar_lo, ar_hi = wilson(tp, attack_total)

        c.update({
            "tp": tp,
            "fn": fn,
            "fp": fp,
            "misattributed": misattributed,
            "blocked_attacks": blocked_attacks,
            "attacks_total": attack_total,
            "attributed": tp,
            "unattributed": attack_total - tp,
            "alerts_raised": alerts,
            "precision": round(precision, 4) if precision is not None else None,
            "precision_lo": p_lo,
            "precision_hi": p_hi,
            "recall": round(recall_all, 4) if recall_all is not None else None,
            "recall_lo": r_lo,
            "recall_hi": r_hi,
            "attribution_recall": (
                round(attribution_recall, 4) if attribution_recall is not None else None
            ),
            "attribution_recall_lo": ar_lo,
            "attribution_recall_hi": ar_hi,
            "detection_recall": (
                round(detection_recall, 4) if detection_recall is not None else None
            ),
            "f1": round(f1, 4) if f1 is not None else None,
        })

        for r in latency(ch, rid):
            r.update({
                "key": c["key"],
                "cell": c["cell"],
                "mode": c["mode"],
                "window_ms": c["window_ms"],
                "enrich_retries": c["enrich_retries"],
                "enrich_delay_s": c["enrich_delay_s"],
            })
            lat_rows.append(r)

        for r in pairing(ch, rid):
            r.update({
                "key": c["key"],
                "cell": c["cell"],
                "mode": c["mode"],
                "window_ms": c["window_ms"],
                "horizon_ms": c["horizon_ms"],
            })
            pair_rows.append(r)

        for r in collection(rid):
            r.update({
                "key": c["key"],
                "cell": c["cell"],
                "enrich_retries": c["enrich_retries"],
                "enrich_delay_s": c["enrich_delay_s"],
            })
            coll_rows.append(r)

        # Only the enforcement cells, because elsewhere the response worker
        # records the action without writing it to the store the application
        # reads, so no refusal can follow and the measurement is vacuous.
        if c["enforce"]:
            for r in revocation_effect(ch, rid):
                r.update({"key": c["key"], "cell": c["cell"], "mode": c["mode"]})
                rev_rows.append(r)

        for r in resources(rid):
            r.update({"key": c["key"], "cell": c["cell"]})
            res_rows.append(r)

        print(
            f"  {c['cell']:<28} P={c['precision']} "
            f"R={c['attribution_recall']} (primary {c['recall']}) "
            f"attributed={tp}/{attack_total} FP={fp}"
            + (f" misattributed={misattributed}" if misattributed else "")
        )

    # ---- enforcement: what the response cost legitimate users -------
    enf_rows = []
    for c in cells:
        if not c["enforce"]:
            continue
        issued, blocked, principals = ch.execute(
            "SELECT count(), countIf(blocked = 1), uniqExactIf(user_id, blocked = 1) "
            "FROM sarvajna.ground_truth WHERE run_id = %(r)s",
            {"r": c["run_id"]},
        )[0]
        benign_blocked, attack_blocked = ch.execute(
            "SELECT countIf(label = 0 AND blocked = 1), "
            "       countIf(label = 1 AND blocked = 1) "
            "FROM sarvajna.ground_truth WHERE run_id = %(r)s",
            {"r": c["run_id"]},
        )[0]
        revs, revoked_principals = ch.execute(
            "SELECT count(), uniqExact(principal_user) FROM sarvajna.revocations "
            "WHERE run_id = %(r)s",
            {"r": c["run_id"]},
        )[0]
        enf_rows.append({
            "key": c["key"],
            "cell": c["cell"],
            "mode": c["mode"],
            "adversarial": c["adversarial"],
            "revocations": int(revs),
            "revoked_principals": int(revoked_principals),
            "requests_issued": int(issued),
            "requests_refused": int(blocked),
            "benign_refused": int(benign_blocked),
            # An attack refused before it reached the vulnerable route is the
            # only sense in which the user-scoped tier prevented anything.
            "attacks_refused": int(attack_blocked),
            "principals_refused": int(principals),
            "refused_pct": round(100 * blocked / issued, 2) if issued else 0.0,
            "precision": c["precision"],
            "false_positives": c["fp"],
            "misattributed": c["misattributed"],
        })

    # ---- tier 2 containment -----------------------------------------
    tier2_rows = []
    for c in cells:
        if not c["tier2"]:
            continue
        p = f"{DIAG}/quarantine_{c['run_id']}.json"
        if not os.path.exists(p):
            continue
        with open(p) as f:
            q = json.load(f)
        tier2_rows.append({
            "key": c["key"],
            # Polled from inside the pod at 0.1 s resolution from the moment the
            # action was taken. The other field starts its poll only after the
            # cell's fixed wait, so it reports when the harness looked rather
            # than when the datapath converged.
            "egress_severed_s": q.get("egress_failure_latency_s"),
            "endpoint_enforced_s_upper_bound": q.get("containment_latency_s"),
            "egress_reachable_before": q.get("egress_was_reachable_before"),
        })

    check_invariants(cells, metric_rows)

    adv_ids = [c["run_id"] for c in cells if c["adversarial"]]
    audit = forgery_audit(ch, adv_ids)
    if audit:
        print(f"\n{'=' * 74}\n  FORGERY ATTRIBUTION AUDIT\n{'=' * 74}")
        print(f"  Attempted                    {audit['attempted']}")
        print(f"  Bound via the forged token   {audit['correlated_via_forged_token']}")
        print(f"  Attributed to the victim     {audit['attributed_to_victim']}")
        print(f"  Attributed to the attacker   {audit['attributed_to_attacker']}")
        if audit["misattribution_rate"] is not None:
            print(
                f"  Misattribution rate          "
                f"{100 * audit['misattribution_rate']:.1f}%"
            )
        with open(f"{OUT}/_forgery_audit.json", "w") as f:
            json.dump(audit, f, indent=2)
        print(f"  wrote {OUT}/_forgery_audit.json")

    # ---- write ------------------------------------------------------
    frames = {
        "_cells": pd.DataFrame(cells),
        "_confusion": pd.DataFrame(conf_rows),
        "_metrics": pd.DataFrame(metric_rows),
        "_latency": pd.DataFrame(lat_rows),
        "_pairing": pd.DataFrame(pair_rows),
        "_collection": pd.DataFrame(coll_rows),
        "_revocation_effect": pd.DataFrame(rev_rows),
        "_resources": pd.DataFrame(res_rows),
        "_enforcement": pd.DataFrame(enf_rows),
        "_tier2": pd.DataFrame(tier2_rows),
    }
    for name, df in frames.items():
        if df.empty:
            continue
        path = f"{OUT}/{name}.csv"
        df.to_csv(path, index=False)
        print(f"  wrote {path}  ({len(df)} rows)")

    make_figures(frames)

    print(f"\n{'=' * 74}")
    print(f"  Next: python benchmarks/make_tables.py --suite {suite}")
    print(f"{'=' * 74}\n")


# =====================================================================
#  FIGURES
# =====================================================================
def make_figures(frames):
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    cells = frames["_cells"]
    metrics = frames["_metrics"]
    pair = frames["_pairing"]
    lat = frames["_latency"]
    coll = frames["_collection"]
    enf = frames["_enforcement"]

    def save(fig, name):
        fig.tight_layout()
        fig.savefig(f"{OUT}/{name}", dpi=200)
        plt.close(fig)
        print(f"  wrote {OUT}/{name}")

    def err(v, lo, hi):
        v = v.fillna(0).to_numpy()
        return [
            (v - lo.fillna(0).to_numpy()).clip(0),
            (hi.fillna(0).to_numpy() - v).clip(0),
        ]

    # --- ablation ----------------------------------------------------
    # Attribution recall rather than primary-class recall, so the adversarial
    # configuration is shown against every attack it issued.
    ladder = cells[cells.cell.str.startswith("B")].sort_values("cell")
    if not ladder.empty:
        fig, ax = plt.subplots(figsize=(8.5, 4.5))
        x = list(range(len(ladder)))
        w = 0.38
        ax.bar(
            [i - w / 2 for i in x],
            ladder.precision.fillna(0),
            w,
            label="Precision",
            capsize=3,
            yerr=err(ladder.precision, ladder.precision_lo, ladder.precision_hi),
        )
        ax.bar(
            [i + w / 2 for i in x],
            ladder.attribution_recall.fillna(0),
            w,
            label="Attribution recall",
            capsize=3,
            yerr=err(
                ladder.attribution_recall,
                ladder.attribution_recall_lo,
                ladder.attribution_recall_hi,
            ),
        )
        ax.set_xticks(x)
        ax.set_xticklabels([n.replace("_", "\n") for n in ladder.cell], fontsize=8)
        ax.set_ylim(0, 1.05)
        ax.set_ylabel("Score (95% Wilson interval)")
        ax.set_title("Correlation predicate ablation, over every attack issued")
        ax.legend()
        ax.grid(axis="y", alpha=0.3)
        save(fig, "fig1_ablation.png")

    # --- execution recall by predicate -------------------------------
    rce = metrics[
        (metrics["class"] == "RCE_COMMAND_INJECTION") & metrics.cell.str.startswith("B")
    ].sort_values("cell")
    if not rce.empty:
        fig, ax = plt.subplots(figsize=(8, 4))
        ax.bar(range(len(rce)), rce.recall.fillna(0))
        ax.set_xticks(range(len(rce)))
        ax.set_xticklabels([n.replace("_", "\n") for n in rce.cell], fontsize=8)
        ax.set_ylim(0, 1.05)
        ax.set_ylabel("Recall")
        ax.set_title("Process-execution attribution by correlation predicate")
        ax.grid(axis="y", alpha=0.3)
        save(fig, "fig2_execution_recall.png")

    # --- window sweep: spurious pairing ------------------------------
    win = pair[
        (pair.cell.str.startswith("WINDOW"))
        & (pair.predicate.isin(["file_path", "trace_id", "dest_endpoint"]))
    ]
    if not win.empty:
        fig, ax = plt.subplots(figsize=(8.5, 4.5))
        for pred in ("file_path", "dest_endpoint", "trace_id"):
            sub = win[
                (win.predicate == pred) & (win.window_ms == win.horizon_ms)
            ].sort_values("window_ms")
            if sub.empty:
                continue
            ax.plot(sub.window_ms, sub.pct, marker="o", label=pred)
        dec = win[(win.window_ms != win.horizon_ms) & (win.predicate == "file_path")]
        if not dec.empty:
            ax.scatter(
                dec.window_ms,
                dec.pct,
                marker="s",
                s=80,
                zorder=5,
                label="file_path, 2000 ms window, 60 s buffer horizon",
            )
        ax.set_xlabel("Correlation window (ms)")
        ax.set_ylabel("Cross-request pairs (%)")
        ax.set_title("Spurious pairing against window width, by join predicate")
        ax.legend(fontsize=8)
        ax.grid(alpha=0.3)
        save(fig, "fig3_window_pairing.png")

    # --- enrichment sweep -------------------------------------------
    ex = coll[(coll.event_type == "execve") & coll.cell.str.startswith("ENRICH")].copy()
    if not ex.empty:
        ex["ceiling_s"] = ex.enrich_retries * ex.enrich_delay_s
        ex = ex.sort_values("ceiling_s")
        rec = metrics[
            (metrics["class"] == "RCE_COMMAND_INJECTION")
            & metrics.cell.str.startswith("ENRICH")
        ].copy()
        rec["ceiling_s"] = rec.enrich_retries * rec.enrich_delay_s
        rec = rec.sort_values("ceiling_s")

        fig, ax = plt.subplots(figsize=(8.5, 4.5))
        ax.plot(
            ex.ceiling_s, ex.p50 / 1000.0, marker="o", label="Export delay, p50 (s)"
        )
        ax.set_xlabel("Enrichment retry ceiling (s)")
        ax.set_ylabel("Kernel export delay (s)")
        ax.grid(alpha=0.3)
        ax2 = ax.twinx()
        ax2.plot(
            rec.ceiling_s,
            rec.recall,
            marker="s",
            linestyle="--",
            color="tab:red",
            label="Execution recall",
        )
        ax2.set_ylabel("Recall")
        ax2.set_ylim(0, 1.05)
        ax.set_title("Enrichment retry budget: cost without benefit")
        h1, l1 = ax.get_legend_handles_labels()
        h2, l2 = ax2.get_legend_handles_labels()
        ax.legend(h1 + h2, l1 + l2, loc="center right", fontsize=8)
        save(fig, "fig4_enrichment.png")

    # --- latency decomposition ---------------------------------------
    base = lat[lat.cell == "B3_DeterministicBridge"]
    if not base.empty:
        order = [
            "BOLA_AUTHORIZATION_BYPASS",
            "SSRF_UNAUTHORIZED_PROBE",
            "RCE_COMMAND_INJECTION",
        ]
        base = (
            base.set_index("alert_type")
            .reindex([o for o in order if o in set(base.alert_type)])
            .reset_index()
        )
        fig, ax = plt.subplots(figsize=(8.5, 4.5))
        labels = [a.split("_")[0] for a in base.alert_type]
        spawn = base.spawn_p50.clip(lower=0)
        export = base.export_p50.clip(lower=0)
        pipe = base.pipeline_p50.clip(lower=0)
        ax.bar(labels, spawn, label="Process spawn (application)")
        ax.bar(
            labels, export, bottom=spawn, label="Kernel export (observability layer)"
        )
        ax.bar(
            labels,
            pipe,
            bottom=spawn + export,
            label="Correlation and response (this work)",
        )
        ax.set_ylabel("Median latency (ms)")
        ax.set_title("Where the end-to-end time is spent")
        ax.legend(fontsize=8)
        ax.grid(axis="y", alpha=0.3)
        save(fig, "fig5_latency_decomposition.png")

    # --- enforcement collateral damage -------------------------------
    # Benign and attack refusals plotted separately: the whole measured effect
    # of the user-scoped tier fell on legitimate traffic.
    if not enf.empty:
        e = enf.sort_values("requests_refused")
        fig, ax = plt.subplots(figsize=(8.5, 4.5))
        labels = [n.replace("ENFORCE_", "") for n in e.cell]
        ax.barh(labels, e.benign_refused, label="Legitimate requests refused")
        ax.barh(
            labels,
            e.attacks_refused,
            left=e.benign_refused,
            label="Attacks refused",
        )
        ax.set_xlabel("Requests refused by an enforced revocation")
        ax.set_title("What the user-scoped response tier actually refused")
        ax.legend(fontsize=8)
        ax.grid(axis="x", alpha=0.3)
        save(fig, "fig6_enforcement.png")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", required=True)
    analyse(ap.parse_args().suite)
