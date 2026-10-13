import { AsyncLocalStorage } from 'async_hooks';

export interface SecurityContext {
  traceId: string;
  userId: string;
  tenantId: string;
  attackId?: string;
}

const globalForContext = globalThis as unknown as {
  __SARVAJNA_ASYNC_STORAGE__?: AsyncLocalStorage<SecurityContext>;
};

export const asyncLocalStorage =
  globalForContext.__SARVAJNA_ASYNC_STORAGE__ ??
  (globalForContext.__SARVAJNA_ASYNC_STORAGE__ = new AsyncLocalStorage<SecurityContext>());
