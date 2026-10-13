# Sarvajna-Amogh

A cross-layer correlation and response framework that attributes kernel events
to the application requests that caused them, and measures what acting on that
attribution costs.

This repository is the artifact of record for suite **S20261006-134605**. The
code here is what produced the numbers in `benchmarks/tables/`, and the
archived rows under `benchmarks/archive/S20261006-134605/` are sufficient to
re-derive every one of them without a cluster.

## Re-deriving the results without running anything

```bash
pip install clickhouse-driver nats-py pandas numpy matplotlib locust
python benchmarks/analyze.py     --suite S20261006-134605
python benchmarks/make_tables.py --suite S20261006-134605
```

`analyze.py` reads the ledger at `benchmarks/diag/S20261006-134605_ledger.json`,
which records which cells passed and under which run identifier. Cells that
failed leave their diagnostic files on disk after their rows are purged, so an
analysis that discovered cells by scanning the diagnostics directory would read
three cells that no longer exist in the data. `make_tables.py` reads only the
CSVs that `analyze.py` writes, never the database, so a number in a table traces
to a row in a file that is itself derived from the archived export.

## Collecting a new suite

Requires Docker, k3d, kubectl, helm, jq, and a Linux host with a kernel new
enough for eBPF with BTF. Reference environment: AMD Ryzen 7 7840HS, 16 logical
CPUs, 15 GiB RAM, kernel 6.15, Docker 28.5.2, k3s v1.35.5+k3s1.

```bash
./bootstrap.sh
python benchmarks/verify_environment.py     # acceptance test, ~80 checks
python benchmarks/run_benchmark.py --dry-run --reset
python benchmarks/run_benchmark.py --reset --reps 1
```

A campaign is twenty cells and takes roughly 100 minutes. Each cell verifies
itself against its own gates immediately after collection, and a cell that
fails stops the campaign with the failing gate named. Fix the cause and resume:

```bash
python benchmarks/run_benchmark.py --resume <SUITE_ID>
python benchmarks/run_benchmark.py --resume <SUITE_ID> --status
```

On resume, cells that already passed are skipped, the failed cell's rows are
deleted and verified gone before it is collected again, and rows left behind by
an interrupted attempt the ledger never recorded are purged first. Each cell
therefore appears exactly once in the data whether the campaign ran in one pass
or several.

Then:

```bash
python benchmarks/analyze.py     --suite <SUITE_ID>
python benchmarks/make_tables.py --suite <SUITE_ID>
./benchmarks/export_suite.sh     <SUITE_ID>
```

## What lives where

| Path | Role |
|---|---|
| `app/` | Target application with three deliberately vulnerable routes |
| `ebpf/` | Tetragon values and the two TracingPolicies |
| `pipeline/` | Backing services, collector configuration, database schemas |
| `stream/` | The correlator |
| `soar/` | Response worker and the quarantine network policy |
| `benchmarks/` | Harness, verifier, workload, analysis, table generator |
| `cluster/` | k3d cluster definition |

## Things a reproducer should know

**Port-forwards must be running.** The harness reaches the application,
ClickHouse and NATS over `localhost`. `bootstrap.sh` prints the three loops to
run. The harness replaces the application pod during preflight, so a forward
bound to the old pod dies with it and must restart.

**The last two preflight layers are destructive and self-restoring.** One
applies the quarantine label, polls until the network plugin reports
enforcement, probes reachability in both directions, removes the label and
waits for the datapath to recover. The other issues an attack against a probe
principal and times how long until that principal is refused. Both exist
because an enforcement mechanism that writes a record without producing an
effect would pass every static check.

**Collection and analysis are separate on purpose.** All raw data persists in
ClickHouse partitioned by run identifier. Ten of the thirty catalogued
measurement defects were in analysis and were corrected by re-running the
analysis against stored data at no collection cost.

**`cilium-dbg` is assumed.** That binary name arrived in Cilium 1.16. Earlier
versions ship `cilium` instead and the enforcement checks will need adjusting.

**Versions.** Cilium 1.20.1, Tetragon 1.7.1, ClickHouse 26.8.2.7, PostgreSQL
16-alpine, NATS 2.10-alpine, Vector 0.58.0-alpine, Node 20-alpine, Python
3.11-slim, k3s v1.35.5+k3s1. The resolved image for every component is also
recorded in `benchmarks/diag/environment.json` under `images`.

**Credentials are development defaults** and appear in plaintext in the
manifests. The cluster has no external network exposure and the application is
deliberately vulnerable. Do not run this on a shared or reachable host.

**Post-collection changes.** Suite S20261006-134605 was collected on 6 October
2026. Every change to this repository after that date is listed here, so that
the artifact can be read against the data it produced:

- Explanatory comments added to `stream/cep-engine.yaml`. No executed code.
- `app/src/app/api/reports/route.ts`: the fallback for
  `CONFIDENTIAL_FILE_COUNT` was raised from 64 to 512 so that it agrees with
  the health route and the harness. The deployment manifest has always set this
  variable explicitly, so the fallback was never read during collection, and
  the deployed image is unchanged.
- The object-count check in `benchmarks/checks.py`,
  `benchmarks/run_benchmark.py` and `benchmarks/precreate_objects.sh` now
  globs `confidential_[0-9]*.pdf` rather than `confidential_*.pdf`. The looser
  glob also matched one fixture object outside the 512-object pool, so the
  check reported 513 of 512 and passed on a count that did not mean what its
  name said. It now reports 512 of 512. The gate was satisfied under both.
- Superseded table files from an earlier, discarded suite were removed from
  `benchmarks/tables/`.

No reported figure depends on any of these.


---

# Suite S20261006-134605

`S20261006-134605_ledger.json` is the authority for which cells are analysed.
Three cells appear twice here, under two run identifiers each:

| Cell | Analysed | Failed attempt, rows purged |
|---|---|---|
| B4_AdversarialRobustness | 8d5891 | f8b521 |
| ENFORCE_Forgery | 8edcc1 | 471a3f |
| QUARANTINE_Enforced | bcf9ba | d53d6f |

Each pair is one attempt that failed its gates and one that passed. The failed
attempt's rows were deleted from the database and verified gone before the
cell was collected again, but its diagnostic JSON and workload logs remain on
disk, which is why both appear here. Only the analysed identifier enters any
figure: analyze.py reads the ledger and processes the run identifier recorded
as passing for each cell, so each cell contributes exactly once to the pooled
results. This is the reason the analysis reads the ledger rather than globbing
this directory. The three failures and their causes are described in
Section 4.2.
