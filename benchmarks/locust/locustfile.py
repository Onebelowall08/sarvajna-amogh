"""
Sarvajna-Amogh: workload generator.

WHAT CHANGED AND WHY
--------------------
Earlier versions drove benign traffic exclusively at one public object and
never at the network route. No benign request therefore reached a code path
capable of producing a false positive under the resource-identity or bridge
configurations, and their precision of 1.000 followed from the workload rather
than from any discrimination the correlator performed.

Benign traffic here reaches the same objects and the same destination host as
the attacks, authorised. The kernel events are of the same type on the same
paths; the only difference is the verdict the application reached. A
configuration that still reports no false positive has discriminated.

The command-injection route has no benign counterpart, and that is deliberate.
Its detection signal is the process execution itself, because the application
has no legitimate reason to spawn a subprocess. Adding benign subprocess
traffic would measure the detection rule rather than the correlation predicate.
Precision on that class is a property of the application and is reported as
such rather than implied to be measured.

IDENTIFIER UNIQUENESS
---------------------
Each authorisation failure names a distinct object and each probe a distinct
port, drawn from monotonic counters rather than at random. With a shared
target, several concurrent attacks index under one key and the correlator pairs
an application event with a kernel event arbitrarily among them: the counts
stay correct while the attributed principal does not. Distinct keys make
per-request attribution checkable.
"""

import csv
import itertools
import os
import random
import socket
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone

from locust import HttpUser, between, events, task

RUN_ID = os.getenv("BENCHMARK_RUN_ID", "default_run")
ADVERSARIAL = os.getenv("RUN_ADVERSARIAL", "false").lower() == "true"
CONFIDENTIAL_COUNT = int(os.getenv("CONFIDENTIAL_FILE_COUNT", "512"))

# Probe destination: a real pod address, so a closed port is refused
# immediately rather than timing out. A virtual service address with no backing
# listener black-holes the packet and each probe would cost the full client
# timeout, cutting the attack volume per cell several-fold.
SSRF_TARGET_IP = os.getenv("SSRF_TARGET_IP", "")
SSRF_OPEN_PORT = int(os.getenv("SSRF_OPEN_PORT", "8123"))
SSRF_PORT_BASE = int(os.getenv("SSRF_PORT_BASE", "20000"))
SSRF_PORT_SPAN = int(os.getenv("SSRF_PORT_SPAN", "40000"))

# Permitted outbound endpoint for benign traffic. Also a pod address, so benign
# and attack connections traverse an identical network path and differ only in
# the verdict the application recorded.
PREVIEW_ALLOWED_IP = os.getenv("PREVIEW_ALLOWED_IP", "")
PREVIEW_ALLOWED_PORT = int(os.getenv("PREVIEW_ALLOWED_PORT", "4222"))

if not SSRF_TARGET_IP:
    try:
        SSRF_TARGET_IP = socket.gethostbyname(
            "clickhouse.sarvajna-infra.svc.cluster.local"
        )
    except Exception:
        SSRF_TARGET_IP = "10.43.0.1"

if not PREVIEW_ALLOWED_IP:
    try:
        PREVIEW_ALLOWED_IP = socket.gethostbyname(
            "nats.sarvajna-infra.svc.cluster.local"
        )
    except Exception:
        PREVIEW_ALLOWED_IP = SSRF_TARGET_IP

# Victims are a dedicated population rather than a slice of the general benign
# pool. A revocation issued against a principal who rarely transacts again
# produces no observable consequence, so collateral damage would have to be
# inferred from an aggregate dip. These users transact continuously, so blocked
# requests attach to the specific revocation that caused them.
VICTIM_TENANT = "tenant_victim"
VICTIM_USERS = [f"victim_user_{i}" for i in range(1, 21)]

_lock = threading.Lock()
_file_seq = itertools.count()
_benign_file_seq = itertools.count(CONFIDENTIAL_COUNT // 2)
_port_seq = itertools.count()

GT_FILE = f"benchmarks/ground_truth_{RUN_ID}.csv"
_gt = open(GT_FILE, "a", newline="")
_w = csv.writer(_gt)
if os.path.getsize(GT_FILE) == 0:
    _w.writerow([
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
    ])


def next_attack_file() -> str:
    with _lock:
        return f"confidential_{next(_file_seq) % CONFIDENTIAL_COUNT}.pdf"


def next_benign_file() -> str:
    # Offset by half the pool so benign and attack traffic sweep the same
    # objects out of phase, producing frequent near-simultaneous access and
    # denial on one path. That coincidence is the discrimination test; the
    # analysis reports how often it actually occurred.
    with _lock:
        return f"confidential_{next(_benign_file_seq) % CONFIDENTIAL_COUNT}.pdf"


def next_probe_port() -> int:
    with _lock:
        return SSRF_PORT_BASE + (next(_port_seq) % SSRF_PORT_SPAN)


def record(
    attack_id,
    label,
    attack_type,
    user_id,
    tenant_id,
    payload,
    victim_user="",
    victim_trace="",
    http_status=0,
    blocked=0,
):
    """Writes one ground-truth row after the response returns.

    The outcome fields require the response, so the row cannot be written
    earlier. A task interrupted by the run-time limit between the response and
    this call leaves telemetry with no ground-truth row: measured two of 1531
    in one cell, both within a second of the generator exiting. The harness
    passes --stop-timeout so in-flight tasks finish, and the dry run gates on
    the residual.
    """
    with _lock:
        _w.writerow([
            RUN_ID,
            attack_id,
            label,
            attack_type,
            user_id,
            tenant_id,
            payload,
            victim_user,
            victim_trace,
            int(http_status),
            int(blocked),
            datetime.now(timezone.utc).isoformat(),
        ])
        _gt.flush()


def outcome(resp):
    """HTTP status, and whether the request was refused because its principal
    had been revoked by a previous response action."""
    try:
        status = int(resp.status_code)
    except Exception:
        return 0, 0
    blocked = 1 if (status == 403 and resp.headers.get("x-revoked") == "true") else 0
    return status, blocked


@events.quitting.add_listener
def _close(**kw):
    _gt.close()


class SecurityBenchmarkUser(HttpUser):
    wait_time = between(0.02, 0.08)

    def on_start(self):
        """Establish this user's connection before any recorded request.

        Traffic reaches the application through a port-forward, which
        negotiates a separate stream per connection and refuses a share of them
        when every user connects at once. Measured: the first 1.5 s of a cell
        delivered 44 of 276 requests while every later second delivered all of
        them, uniformly across request types.

        Those failures belong to the access path, not to the application, but
        without this they enter ground truth as attacks that were issued and
        never served, and an attack that never reached the application looks
        exactly like one the correlator failed to detect.

        Retried outside any task, so the connection pool is warm before the
        first recorded request and no ground-truth row is written for a request
        the apparatus dropped.
        """
        for _ in range(40):
            try:
                r = self.client.get("/api/health", name="[warmup]", timeout=5)
                if r.status_code == 200:
                    return
            except Exception:
                pass
            time.sleep(0.25)

    # ---------------------------------------------------------------- benign

    @task(6)
    def benign_public_read(self):
        aid = f"benign-{uuid.uuid4().hex[:12]}"
        user = f"legit_user_{random.randint(1, 100)}"
        tenant = f"tenant_{random.randint(1, 5)}"
        with self.client.get(
            "/api/reports?file=default.txt",
            headers={"x-user-id": user, "x-tenant-id": tenant, "x-attack-id": aid},
            name="/api/reports [Benign public]",
            catch_response=True,
        ) as r:
            st, blk = outcome(r)
            r.success()
        record(
            aid,
            "benign",
            "none",
            user,
            tenant,
            "default.txt",
            http_status=st,
            blocked=blk,
        )

    @task(4)
    def benign_authorized_confidential(self):
        """A permitted read of a restricted object by its owner.

        The kernel sees a file open on exactly the path an authorisation
        failure would produce. Only the application's verdict separates the
        two, so a configuration that alerts here has failed to discriminate."""
        aid = f"benign-{uuid.uuid4().hex[:12]}"
        user = random.choice(VICTIM_USERS)
        target = next_benign_file()
        with self.client.get(
            f"/api/reports?file={target}",
            headers={
                "x-user-id": user,
                "x-tenant-id": VICTIM_TENANT,
                "x-attack-id": aid,
            },
            name="/api/reports [Benign authorized]",
            catch_response=True,
        ) as r:
            st, blk = outcome(r)
            r.success()
        record(
            aid,
            "benign",
            "authorized_access",
            user,
            VICTIM_TENANT,
            target,
            http_status=st,
            blocked=blk,
        )

    @task(3)
    def benign_allowed_preview(self):
        """A permitted outbound fetch to an allowlisted endpoint."""
        aid = f"benign-{uuid.uuid4().hex[:12]}"
        user = f"legit_user_{random.randint(1, 100)}"
        tenant = f"tenant_{random.randint(1, 5)}"
        target = f"http://{PREVIEW_ALLOWED_IP}:{PREVIEW_ALLOWED_PORT}/"
        with self.client.post(
            "/api/preview",
            json={
                "targetUrl": target,
                "userId": user,
                "tenantId": tenant,
                "attackId": aid,
            },
            headers={"x-attack-id": aid, "x-user-id": user},
            name="/api/preview [Benign allowed]",
            catch_response=True,
        ) as r:
            st, blk = outcome(r)
            r.success()
        record(
            aid,
            "benign",
            "allowed_fetch",
            user,
            tenant,
            target,
            http_status=st,
            blocked=blk,
        )

    # ---------------------------------------------------------------- attacks

    @task(2)
    def exploit_rce(self):
        aid = f"atk-{uuid.uuid4().hex[:12]}"
        user = f"attacker_{uuid.uuid4().hex[:6]}"
        payload = "127.0.0.1; whoami"
        with self.client.post(
            "/api/ping",
            json={
                "host": payload,
                "userId": user,
                "tenantId": "adversary_corp",
                "attackId": aid,
            },
            headers={"x-attack-id": aid, "x-user-id": user},
            name="/api/ping [RCE]",
            catch_response=True,
        ) as r:
            st, blk = outcome(r)
            r.success()
        record(
            aid,
            "attack",
            "RCE_COMMAND_INJECTION",
            user,
            "adversary_corp",
            payload,
            http_status=st,
            blocked=blk,
        )

    @task(2)
    def exploit_bola(self):
        aid = f"atk-{uuid.uuid4().hex[:12]}"
        user = f"attacker_{uuid.uuid4().hex[:6]}"
        target = next_attack_file()
        with self.client.get(
            f"/api/reports?file={target}",
            headers={
                "x-user-id": user,
                "x-tenant-id": "adversary_corp",
                "x-attack-id": aid,
            },
            name="/api/reports [BOLA]",
            catch_response=True,
        ) as r:
            st, blk = outcome(r)
            r.success()
        record(
            aid,
            "attack",
            "BOLA_AUTHORIZATION_BYPASS",
            user,
            "adversary_corp",
            target,
            http_status=st,
            blocked=blk,
        )

    @task(2)
    def exploit_ssrf(self):
        aid = f"atk-{uuid.uuid4().hex[:12]}"
        user = f"attacker_{uuid.uuid4().hex[:6]}"
        # One probe in sixteen reaches the service that is actually listening,
        # so the condition is a port sweep that occasionally succeeds rather
        # than a uniform scan of closed ports.
        port = SSRF_OPEN_PORT if random.random() < 0.0625 else next_probe_port()
        target = f"http://{SSRF_TARGET_IP}:{port}/ping"
        with self.client.post(
            "/api/preview",
            json={
                "targetUrl": target,
                "userId": user,
                "tenantId": "adversary_corp",
                "attackId": aid,
            },
            headers={"x-attack-id": aid, "x-user-id": user},
            name="/api/preview [SSRF]",
            catch_response=True,
        ) as r:
            st, blk = outcome(r)
            r.success()
        record(
            aid,
            "attack",
            "SSRF_UNAUTHORIZED_PROBE",
            user,
            "adversary_corp",
            target,
            http_status=st,
            blocked=blk,
        )

    # ----------------------------------------------------------- adversarial

    @task(2 if ADVERSARIAL else 0)
    def exploit_rce_evasion_strip(self):
        """env -i clears the environment of the spawned process, so the label
        never reaches the kernel."""
        aid = f"atk-evade-{uuid.uuid4().hex[:12]}"
        user = f"attacker_{uuid.uuid4().hex[:6]}"
        payload = "127.0.0.1; env -i whoami"
        with self.client.post(
            "/api/ping",
            json={
                "host": payload,
                "userId": user,
                "tenantId": "adversary_corp",
                "attackId": aid,
            },
            headers={"x-attack-id": aid, "x-user-id": user},
            name="/api/ping [Evasion Strip]",
            catch_response=True,
        ) as r:
            st, blk = outcome(r)
            r.success()
        record(
            aid,
            "attack",
            "RCE_EVASION_STRIP",
            user,
            "adversary_corp",
            payload,
            http_status=st,
            blocked=blk,
        )

    @task(2 if ADVERSARIAL else 0)
    def exploit_rce_forgery(self):
        """Harvest a victim's request identifier, then declare it on a payload
        the attacker spawns.

        The identifier is read from the victim's own response body, which is
        the weakest assumption available: no access to the victim's process
        environment or to application state is required."""
        recon_id = f"recon-{uuid.uuid4().hex[:12]}"
        aid = f"atk-forge-{uuid.uuid4().hex[:12]}"
        attacker = f"attacker_{uuid.uuid4().hex[:6]}"
        victim = random.choice(VICTIM_USERS)

        with self.client.get(
            "/api/reports?file=default.txt",
            headers={
                "x-user-id": victim,
                "x-tenant-id": VICTIM_TENANT,
                "x-attack-id": recon_id,
            },
            name="/api/reports [Forgery Recon]",
            catch_response=True,
        ) as r:
            st, blk = outcome(r)
            r.success()
            try:
                victim_trace = r.json().get("trace_id", "")
            except Exception:
                victim_trace = ""
        record(
            recon_id,
            "benign",
            "forgery_recon",
            victim,
            VICTIM_TENANT,
            "default.txt",
            http_status=st,
            blocked=blk,
        )

        if not victim_trace:
            # A revoked victim returns 403 and no identifier, so there is
            # nothing to forge. Recorded above; no attack row is written,
            # because an attempt that was never issued must not enter a recall
            # denominator.
            return

        payload = f"127.0.0.1; TRACE_ID={victim_trace} whoami"
        with self.client.post(
            "/api/ping",
            json={
                "host": payload,
                "userId": attacker,
                "tenantId": "adversary_corp",
                "attackId": aid,
            },
            headers={"x-attack-id": aid, "x-user-id": attacker},
            name="/api/ping [Forgery]",
            catch_response=True,
        ) as r:
            st, blk = outcome(r)
            r.success()
        record(
            aid,
            "attack",
            "RCE_FORGERY",
            attacker,
            "adversary_corp",
            payload,
            victim_user=victim,
            victim_trace=victim_trace,
            http_status=st,
            blocked=blk,
        )
