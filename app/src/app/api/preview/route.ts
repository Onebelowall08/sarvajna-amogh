import { NextRequest, NextResponse } from 'next/server';
import dns from 'dns/promises';
import { asyncLocalStorage } from '@/lib/otel-context';
import { logEvent } from '@/lib/logger';
import {
  ENFORCE_REVOCATION,
  isRevoked,
  revokedResponse,
  startRevocationPolling,
} from '@/lib/revocation';
import crypto from 'crypto';

export const runtime = 'nodejs';

const dnsCache = new Map<string, string>();

/**
 * Permitted outbound endpoints, supplied by the harness as a comma-separated
 * list of "address:port" pairs.
 *
 * Endpoint rather than address scope matters for two reasons. An allowlist
 * that names a host but not a service is not a policy anyone would deploy.
 * And the correlator keys outbound joins on address and port together, so a
 * verdict reached on the address alone would classify at a coarser granularity
 * than the join it is supposed to explain.
 */
const ALLOWED = new Set(
  (process.env.PREVIEW_ALLOWED_ENDPOINTS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
);

function defaultPort(protocol: string): number {
  return protocol === 'https:' ? 443 : 80;
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  startRevocationPolling();

  const body = await req.json().catch(() => ({}));
  const targetUrl = body.targetUrl || 'http://127.0.0.1';
  const userId = body.userId || req.headers.get('x-user-id') || 'anonymous';
  const tenantId =
    body.tenantId || req.headers.get('x-tenant-id') || 'default_tenant';
  const attackId = req.headers.get('x-attack-id') || body.attackId || '';
  const traceId = `trace-${crypto.randomUUID()}`;
  const podName = process.env.POD_NAME || process.env.HOSTNAME || 'target-app';

  if (ENFORCE_REVOCATION && isRevoked(userId)) {
    return revokedResponse(NextResponse, {
      traceId,
      userId,
      tenantId,
      attackId,
      podName,
      route: '/api/preview',
    });
  }

  let resolvedIp = '';
  let targetPort = 0;
  try {
    const urlObj = new URL(targetUrl);
    targetPort = urlObj.port
      ? Number(urlObj.port)
      : defaultPort(urlObj.protocol);
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(urlObj.hostname)) {
      resolvedIp = urlObj.hostname;
    } else if (dnsCache.has(urlObj.hostname)) {
      resolvedIp = dnsCache.get(urlObj.hostname)!;
    } else {
      const lookup = await dns.lookup(urlObj.hostname);
      resolvedIp = lookup.address;
      dnsCache.set(urlObj.hostname, resolvedIp);
    }
  } catch (e) {
    resolvedIp = '';
    targetPort = 0;
  }

  const endpoint = resolvedIp ? `${resolvedIp}:${targetPort}` : '';
  const allowed = endpoint !== '' && ALLOWED.has(endpoint);

  return asyncLocalStorage.run({ traceId, userId, tenantId, attackId }, async () => {
    logEvent({
      type: allowed ? 'app_fetch_allowed' : 'app_ssrf_denial',
      trace_id: traceId,
      attack_id: attackId,
      user_id: userId,
      tenant_id: tenantId,
      target_ip: resolvedIp,
      target_port: targetPort,
      allowed,
      pod_name: podName,
      timestamp: new Date().toISOString(),
    });

    // The fetch proceeds whichever verdict was reached. The connection is what
    // the kernel observes; the verdict exists only in application state, which
    // is the asymmetry the whole study is about.
    try {
      const resp = await fetch(targetUrl, {
        headers: { Connection: 'close' },
        signal: AbortSignal.timeout(600),
      });
      const data = await resp.text();
      return NextResponse.json({
        content: data.slice(0, 100),
        trace_id: traceId,
        allowed,
      });
    } catch (err: any) {
      // A refused or timed-out connection still issued a tcp_connect, so the
      // kernel event exists. Reachability of the probed endpoint is not the
      // quantity under test, so this is not an error for the experiment.
      return NextResponse.json(
        { error: err.message, trace_id: traceId, allowed },
        { status: 200 }
      );
    }
  });
}
