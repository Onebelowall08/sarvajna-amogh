import { Pool } from 'pg';
import { logEvent } from '@/lib/logger';

/**
 * Revocation state for user-scoped response.
 *
 * The response worker writes a row to Postgres when it acts against a
 * principal. This module keeps an in-memory mirror refreshed on a timer, so
 * the request path costs a Set lookup rather than a database round trip. A
 * per-request query would add a variable database latency to exactly the
 * measurement the enrichment sweep is trying to isolate.
 *
 * Enforcement is OFF by default. The ablation and sweep cells measure
 * attribution, and enforcement perturbs the traffic being attributed: a
 * revoked user stops issuing requests, so the benign population shrinks during
 * the cell. Dedicated enforcement cells switch it on to measure that effect on
 * purpose instead of letting it contaminate every cell.
 *
 * Failure is open. If Postgres is unreachable the mirror is left as it is and
 * the condition is logged. A fail-closed mirror would convert a database
 * outage into a total application outage, which would be a worse experimental
 * artefact than a missed revocation.
 */

const POLL_MS = Number(process.env.REVOCATION_POLL_MS || '500');

export const ENFORCE_REVOCATION =
  (process.env.ENFORCE_REVOCATION || 'false').toLowerCase() === 'true';

interface RevocationState {
  pool: Pool | null;
  revoked: Set<string>;
  lastRefresh: number;
  lastError: string;
  refreshes: number;
  started: boolean;
}

const g = globalThis as unknown as {
  __SARVAJNA_REVOCATION__?: RevocationState;
};

const state: RevocationState =
  g.__SARVAJNA_REVOCATION__ ??
  (g.__SARVAJNA_REVOCATION__ = {
    pool: null,
    revoked: new Set<string>(),
    lastRefresh: 0,
    lastError: '',
    refreshes: 0,
    started: false,
  });

function pool(): Pool {
  if (!state.pool) {
    state.pool = new Pool({
      host: process.env.PG_HOST || 'postgres.sarvajna-infra.svc.cluster.local',
      port: Number(process.env.PG_PORT || '5432'),
      user: process.env.PG_USER || 'sarvajna',
      password: process.env.PG_PASSWORD || 'amogh_secure_pwd',
      database: process.env.PG_DB || 'sarvajna_db',
      max: 2,
      connectionTimeoutMillis: 2000,
      idleTimeoutMillis: 30000,
    });
    state.pool.on('error', (e) => {
      state.lastError = String(e?.message || e);
    });
  }
  return state.pool;
}

async function refresh(): Promise<void> {
  try {
    const r = await pool().query('SELECT principal_user FROM revocations');
    const next = new Set<string>();
    for (const row of r.rows) {
      if (row.principal_user) next.add(String(row.principal_user));
    }
    state.revoked = next;
    state.lastRefresh = Date.now();
    state.lastError = '';
    state.refreshes += 1;
  } catch (e: any) {
    state.lastError = String(e?.message || e);
  }
}

/**
 * Starts the refresh timer once per process. Safe to call from every request
 * handler: the started flag lives on globalThis, so Next.js module reloading
 * in development cannot start a second timer.
 */
export function startRevocationPolling(): void {
  if (state.started) return;
  state.started = true;
  void refresh();
  const t = setInterval(() => {
    void refresh();
  }, POLL_MS);
  if (typeof t.unref === 'function') t.unref();

  // Heartbeat on the application's own output stream.
  //
  // The collector releases a file handle when a file goes quiet and, on
  // rediscovery, resumes from its stored offset rather than from the end. This
  // log is silent for 75 s between collection cells, so the next cell's opening
  // seconds are delivered as backlog: measured 9853 ms on the first bucket
  // after an idle gap, against 9 ms when the file was written continuously.
  //
  // A deployed application serving real traffic is never silent, so this
  // reproduces that steady state rather than compensating for a testbed
  // artefact downstream. It carries no `type` field, so the collector's
  // transform leaves it unclassified and the filter discards it before
  // transport.
  const hb = setInterval(() => {
    logEvent({ heartbeat: 1, timestamp: new Date().toISOString() });
  }, 2000);
  if (typeof hb.unref === 'function') hb.unref();

  logEvent({
    type: 'revocation_poller_init',
    enforce: ENFORCE_REVOCATION,
    poll_ms: POLL_MS,
    timestamp: new Date().toISOString(),
  });
}

export function isRevoked(userId: string): boolean {
  if (!ENFORCE_REVOCATION) return false;
  return state.revoked.has(userId);
}

export function revocationStatus() {
  return {
    enforce: ENFORCE_REVOCATION,
    revoked_count: state.revoked.size,
    last_refresh_ms_ago: state.lastRefresh ? Date.now() - state.lastRefresh : -1,
    refreshes: state.refreshes,
    last_error: state.lastError,
  };
}

/**
 * Shared rejection path. Emits app_revoked_request so that a request blocked
 * by a previous response action is distinguishable in telemetry from a request
 * that simply failed, and returns 403 with a header the workload generator
 * reads to classify the outcome.
 */
export function revokedResponse(
  NextResponse: typeof import('next/server').NextResponse,
  ctx: {
    traceId: string;
    userId: string;
    tenantId: string;
    attackId: string;
    podName: string;
    route: string;
  }
) {
  logEvent({
    type: 'app_revoked_request',
    route: ctx.route,
    trace_id: ctx.traceId,
    attack_id: ctx.attackId,
    user_id: ctx.userId,
    tenant_id: ctx.tenantId,
    pod_name: ctx.podName,
    timestamp: new Date().toISOString(),
  });
  return NextResponse.json(
    { error: 'principal revoked', trace_id: ctx.traceId, revoked: true },
    { status: 403, headers: { 'x-revoked': 'true' } }
  );
}
