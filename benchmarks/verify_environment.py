#!/usr/bin/env python3
"""
Standalone environment audit.

Runs the same checks the harness runs before collecting, so a third party can
establish that their environment matches the one these results were produced on
without running a suite or installing the harness's dependencies.

    python benchmarks/verify_environment.py              # full, ~5 min
    python benchmarks/verify_environment.py --static     # read-only, ~90 s
    python benchmarks/verify_environment.py --no-quarantine

Exit 0 ready, 1 blocking failure, 2 warnings only.
Writes benchmarks/diag/verification_<timestamp>.json for the record.
"""

import argparse, sys
from datetime import datetime
import checks as K


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--static",
        action="store_true",
        help="read-only layers; skips the live test and quarantine",
    )
    ap.add_argument(
        "--no-quarantine",
        action="store_true",
        help="skip the destructive enforcement check",
    )
    ap.add_argument("--no-smoke", action="store_true")
    ap.add_argument("--smoke-n", type=int, default=10)
    ap.add_argument("--objects", type=int, default=512)
    a = ap.parse_args()

    print(f"{K.B}Sarvajna-Amogh environment verification{K.X}")
    print(f"{datetime.now():%Y-%m-%d %H:%M:%S}   node={K.K3D_NODE}")

    c = K.Checker()
    ep = K.run_static(c, a.objects)

    if not a.static:
        if ep and not a.no_quarantine:
            try:
                K.check_quarantine_enforcement(c, ep)
            except Exception as e:
                c.add(7, "quarantine check crashed", "FAIL", str(e)[:80])
        if ep and not a.no_smoke:
            try:
                K.l10_smoke(c, ep, a.smoke_n)
            except Exception as e:
                c.add(10, "end-to-end check crashed", "FAIL", str(e)[:80])
            try:
                K.l11_revocation_effect(c, ep)
            except Exception as e:
                c.add(11, "revocation effect check crashed", "FAIL", str(e)[:80])

    path = f"{K.DIAG}/verification_{datetime.now():%Y%m%d_%H%M%S}.json"
    verdict, fails, warns = K.summarise(c, path)
    sys.exit(1 if fails else (2 if warns else 0))


if __name__ == "__main__":
    main()
