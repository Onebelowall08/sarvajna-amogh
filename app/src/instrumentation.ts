import { logEvent } from '@/lib/logger';

export async function register() {
  if (process.env.NEXT_RUNTIME !== 'nodejs') return;

  const cp = require('child_process');
  let asyncLocalStorage: any;
  try {
    asyncLocalStorage = require('./lib/otel-context').asyncLocalStorage;
  } catch (e) {
    console.error("[BRIDGE] Failed to load OpenTelemetry AsyncLocalStorage:", e);
  }

  const orig = {
    spawn: cp.spawn,
    spawnSync: cp.spawnSync,
    exec: cp.exec,
    execSync: cp.execSync,
    execFile: cp.execFile,
    execFileSync: cp.execFileSync,
    fork: cp.fork,
  };

  function withTraceEnv(args: any[], from: number): any[] {
    const store = asyncLocalStorage?.getStore?.();
    const traceId = store?.traceId ?? 'unknown-context';

    const a = Array.from(args);
    let idx = -1;
    for (let i = from; i < a.length; i++) {
      if (typeof a[i] === 'function') break;
      if (a[i] && typeof a[i] === 'object' && !Array.isArray(a[i])) {
        idx = i;
        break;
      }
    }
    if (idx === -1) {
      let insertAt = a.length;
      for (let i = from; i < a.length; i++) {
        if (typeof a[i] === 'function') {
          insertAt = i;
          break;
        }
      }
      a.splice(insertAt, 0, {});
      idx = insertAt;
    }

    a[idx] = { ...a[idx] };
    a[idx].env = {
      ...process.env,
      ...(a[idx].env || {}),
      TRACE_ID: traceId,
    };
    return a;
  }

  for (const name of Object.keys(orig) as (keyof typeof orig)[]) {
    cp[name] = function(this: any, ...args: any[]) {
      return (orig[name] as Function).apply(this, withTraceEnv(args, 1));
    };
  }

  logEvent({
    type: 'bridge_init',
    patched: Object.keys(orig),
    timestamp: new Date().toISOString(),
  });

  try {
    const canaryId = `canary-${Date.now()}`;
    asyncLocalStorage.run(
      { traceId: canaryId, userId: 'system', tenantId: 'system' },
      () => {
        cp.exec('echo $TRACE_ID', (err: any, stdout: string) => {
          const seen = (stdout || '').trim();
          const ok = seen === canaryId;
          logEvent({
            type: 'bridge_canary',
            expected: canaryId,
            observed: seen,
            passed: ok,
            timestamp: new Date().toISOString(),
          });
          if (!ok) {
            console.error(
              '[BRIDGE CANARY FAILED] TRACE_ID did not reach the child process. ' +
              'Refusing to start silently.'
            );
          }
        });
      }
    );
  } catch (err) {
    console.error('[BRIDGE CANARY ERROR]', err);
  }
}
