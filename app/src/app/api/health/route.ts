import { NextResponse } from 'next/server';
import { revocationStatus, startRevocationPolling } from '@/lib/revocation';

export const runtime = 'nodejs';

export async function GET(): Promise<NextResponse> {
  startRevocationPolling();
  return NextResponse.json({
    ok: true,
    pod_name: process.env.POD_NAME || process.env.HOSTNAME || 'target-app',
    revocation: revocationStatus(),
    confidential_file_count: Number(process.env.CONFIDENTIAL_FILE_COUNT || '512'),
    // Endpoint-scoped: "address:port" pairs. An empty list means every
    // outbound fetch is classed as a denial, so benign network traffic
    // becomes indistinguishable from a probe and SSRF precision stops being
    // measurable. The harness sets this per cell; it must be non-empty during
    // collection.
    preview_allowed_endpoints: (process.env.PREVIEW_ALLOWED_ENDPOINTS || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  });
}
