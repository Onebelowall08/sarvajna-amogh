import { NextRequest, NextResponse } from 'next/server';
import { exec } from 'child_process';
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

/**
 * Command injection sink.
 *
 * No authorisation verdict is recorded here, and there is no benign
 * counterpart in the workload. The detection signal for this class is the
 * process execution itself: this application has no legitimate reason to spawn
 * a subprocess, so any execve in the pod is anomalous. Precision on this class
 * is therefore a property of the application rather than a measured
 * discrimination, and the evaluation says so rather than manufacturing a
 * benign subprocess to imply otherwise.
 *
 * The other two routes do carry a verdict, and both benign and attack traffic
 * reach them, so precision on those classes is measured.
 */
export async function POST(req: NextRequest): Promise<NextResponse> {
  startRevocationPolling();

  const body = await req.json().catch(() => ({}));
  const host = body.host || '127.0.0.1';
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
      route: '/api/ping',
    });
  }

  const result = await asyncLocalStorage.run(
    { traceId, userId, tenantId, attackId },
    async () => {
      // Written synchronously before the child process is spawned, so the
      // application record of intent cannot reach the collector after the
      // kernel event it explains. See lib/logger.ts for why this uses
      // fs.writeSync rather than console.log.
      logEvent({
        type: 'app_log',
        action: 'ping',
        trace_id: traceId,
        attack_id: attackId,
        user_id: userId,
        tenant_id: tenantId,
        pod_name: podName,
        timestamp: new Date().toISOString(),
      });

      return new Promise<NextResponse>((resolve) => {
        exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
          resolve(
            NextResponse.json({ output: stdout || stderr, trace_id: traceId })
          );
        });
      });
    }
  );

  return result;
}
