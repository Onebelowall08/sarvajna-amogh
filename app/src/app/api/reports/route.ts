import { NextRequest, NextResponse } from 'next/server';
import fs from 'fs';
import path from 'path';
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
 * Object ownership.
 *
 * CONFIDENTIAL_COUNT distinct files are owned by tenant_victim. One file per
 * attack matters for attribution: with a single shared target, several
 * concurrent authorisation failures index under the same path and the
 * correlator cannot tell which request a given kernel file_open belongs to.
 * It will still pair one app event with one kernel event, so the counts are
 * right, but which attacker is named is then arbitrary. Distinct objects make
 * the pairing checkable per request.
 *
 * The same files are read legitimately by tenant_victim itself. That is the
 * discrimination test: identical kernel events on identical paths, separated
 * only by the authorisation verdict the application reached.
 */
const CONFIDENTIAL_COUNT = Number(process.env.CONFIDENTIAL_FILE_COUNT || '512');

const OWNERSHIP: Record<string, string> = {
  'default.txt': 'public',
  'quarterly_summary.txt': 'public',
  'confidential_payroll.pdf': 'tenant_victim',
  'merger_notes.pdf': 'tenant_victim',
};
for (let i = 0; i < CONFIDENTIAL_COUNT; i++) {
  OWNERSHIP[`confidential_${i}.pdf`] = 'tenant_victim';
}

function checkAccess(tenantId: string, fileName: string): boolean {
  const owner = OWNERSHIP[fileName];
  if (!owner) return false;
  return owner === 'public' || owner === tenantId;
}

export async function GET(req: NextRequest): Promise<NextResponse> {
  startRevocationPolling();

  const { searchParams } = new URL(req.url);
  // basename only: the study does not evaluate path traversal, and an escape
  // from /tmp would write outside the directory the TracingPolicy watches.
  const fileName = path.basename(searchParams.get('file') || 'default.txt');
  const userId = req.headers.get('x-user-id') || 'unauth';
  const tenantId = req.headers.get('x-tenant-id') || 'unauth';
  const attackId = req.headers.get('x-attack-id') || '';
  const traceId = `trace-${crypto.randomUUID()}`;
  const podName = process.env.POD_NAME || process.env.HOSTNAME || 'target-app';

  if (ENFORCE_REVOCATION && isRevoked(userId)) {
    return revokedResponse(NextResponse, {
      traceId,
      userId,
      tenantId,
      attackId,
      podName,
      route: '/api/reports',
    });
  }

  return asyncLocalStorage.run({ traceId, userId, tenantId, attackId }, () => {
    const allowed = checkAccess(tenantId, fileName);

    // Written before the file is touched, so the authorisation verdict always
    // precedes the kernel event it explains.
    logEvent({
      type: allowed ? 'app_file_access' : 'app_authz_denial',
      trace_id: traceId,
      attack_id: attackId,
      user_id: userId,
      tenant_id: tenantId,
      requested_file_name: fileName,
      allowed,
      pod_name: podName,
      timestamp: new Date().toISOString(),
    });

    // The read proceeds whether or not access was granted. That is the
    // vulnerability: the application logs a denial and then serves the object
    // anyway, so the kernel event is identical in both cases and the only
    // discriminator available to the correlator is the application verdict.

    // Read only. Objects are created by benchmarks/precreate_objects.sh before
    // collection, so the request path performs exactly one file operation.
    // The earlier version checked for existence and wrote the object when it
    // was missing, which made the number of kernel events per request depend
    // on whether that object had been touched before. Whichever cell ran first
    // then carried the creation cost for the whole suite, which is a property
    // of collection order rather than of any configuration under test.
    //
    // A missing object yields 404. Preflight verifies the full set exists, so
    // a 404 during collection indicates a broken environment and should not be
    // repaired silently by the request path.
    const filePath = path.join('/tmp', fileName);
    try {
      const data = fs.readFileSync(filePath, 'utf-8');
      return NextResponse.json({ data, trace_id: traceId, allowed });
    } catch (e: any) {
      return NextResponse.json(
        { error: e.message, trace_id: traceId, allowed },
        { status: 404 }
      );
    }
  });
}
