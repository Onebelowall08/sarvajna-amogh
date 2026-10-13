import fs from 'fs';

/**
 * Synchronous structured logging.
 *
 * console.log writes into Node's stdout stream buffer, which under a pipe
 * (i.e. every container runtime) is drained asynchronously by the event loop.
 * Under load that defers the write far enough that the kernel event for a
 * child process reaches the collector long before the application log line
 * that explains it, which breaks event-time correlation.
 *
 * fs.writeSync(1, ...) writes directly to fd 1 and returns only once the
 * bytes are handed to the kernel.
 */
export function logEvent(obj: Record<string, unknown>): void {
  const line = JSON.stringify(obj) + '\n';
  const buf = Buffer.from(line, 'utf8');
  let offset = 0;
  while (offset < buf.length) {
    try {
      offset += fs.writeSync(1, buf, offset, buf.length - offset);
    } catch (e: any) {
      // Non-blocking fd can return EAGAIN under pressure. Retry rather than
      // drop, since a dropped line is a lost correlation.
      if (e.code === 'EAGAIN') continue;
      return;
    }
  }
}
