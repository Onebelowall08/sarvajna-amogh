# Adds a PostgreSQL client to the worker base image.
#
# pg8000 rather than psycopg2: it is pure Python, so it needs no compiler and
# no libc-specific wheel. psycopg2-binary publishes manylinux wheels only, and
# fails to install on a musl-based image without a build toolchain. The driver
# is not on any hot path, so the performance difference is irrelevant here.
#
# Installed at build time rather than container start, so a run does not depend
# on package-index reachability.
FROM python:3.11-slim

# Install ca-certificates and curl for health probes / debugging
RUN apt-get update && apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install all dependencies for both CEP engine and SOAR worker
RUN pip install --no-cache-dir --no-input \
  "clickhouse-driver>=0.2.6" \
  "nats-py>=2.6.0" \
  "kubernetes>=28.1.0" \
  "pg8000>=1.31.0,<2"

# Verification smoke test during build
RUN python -c "import pg8000.native, clickhouse_driver, nats, kubernetes; print('deps ok')"
