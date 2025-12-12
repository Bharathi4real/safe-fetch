/**
 * SafeFetch – Optimized Typed Fetch utility for Next.js 16
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * Memory-optimized with unified retry, timeout & adaptive pooling
 * https://github.com/Bharathi4real/safe-fetch/
 */

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] as const;

export type HttpMethod = (typeof HTTP_METHODS)[number];
export type RequestBody = Record<string, unknown> | FormData | string | null;
export type QueryParams = Record<string, string | number | boolean | null | undefined>;

// Next.js 16 fetch cache options
export interface NextFetchConfig {
  revalidate?: number | false;
  tags?: string[];
}

export interface RequestOptions<TBody extends RequestBody = RequestBody, TResponse = unknown> {
  data?: TBody;
  params?: QueryParams;
  retries?: number;
  timeout?: number | ((attempt: number) => number);
  headers?: Record<string, string>;
  transform?(data: TResponse): TResponse;
  priority?: 'high' | 'normal' | 'low';
  signal?: AbortSignal;
  logTypes?: boolean;
  cache?: RequestCache;
  next?: NextFetchConfig; // Updated for Next.js 16
  dedupeKey?: string | null;
}

export interface ApiError {
  readonly name: string;
  readonly message: string;
  readonly status: number;
  readonly retryable?: boolean;
  readonly url?: string;
  readonly method?: string;
}

export type ApiResponse<T = unknown> =
  | { success: true; status: number; data: T; headers: Record<string, string> }
  | { success: false; status: number; error: ApiError; data: null };

// -------------------- Configuration --------------------
const IS_BUN = typeof globalThis !== 'undefined' && 'Bun' in globalThis;
const RETRY_CODES = new Set([408, 429, 500, 502, 503, 504]);
const IDEMPOTENT = new Set<HttpMethod>(['GET', 'PUT', 'DELETE']);

const CFG = {
  API_URL: process.env?.NEXT_PUBLIC_API_URL || process.env?.BASE_URL || '',
  TIMEOUT: 60000,
  RETRIES: 2,
  MAX_CONCURRENT: IS_BUN ? 20 : 10,
  IS_DEV: process.env?.NODE_ENV === 'development',
  LOG_LIMIT: 50000,
  RATE_MAX: 100,
  RATE_WINDOW: 60000,
};

// -------------------- Rate Limiter --------------------
class RateLimiter {
  private req: number[] = [];
  constructor(private max = CFG.RATE_MAX, private win = CFG.RATE_WINDOW) {}

  async check(): Promise<void> {
    const now = Date.now();
    this.req = this.req.filter((t) => now - t < this.win);

    if (this.req.length >= this.max) {
      await new Promise((r) => setTimeout(r, this.win - (now - this.req[0])));
      return this.check();
    }
    this.req.push(now);
  }

  stats() {
    const now = Date.now();
    this.req = this.req.filter((t) => now - t < this.win);
    return { current: this.req.length, limit: this.max, windowMs: this.win };
  }
}

const limiter = new RateLimiter();

// -------------------- Request Pool --------------------
class Pool {
  private q: Array<{
    fn: () => Promise<unknown>;
    res: (v: unknown) => void;
    rej: (e?: unknown) => void;
    pri: number;
  }> = [];
  private act = 0;
  private pend = new Map<string, Promise<unknown>>();

  constructor(private max = CFG.MAX_CONCURRENT) {}

  async exec<T>(fn: () => Promise<T>, pri: 'high' | 'normal' | 'low' = 'normal', key?: string | null): Promise<T> {
    if (key && this.pend.has(key)) return this.pend.get(key) as Promise<T>;

    const run = async (): Promise<T> => {
      if (this.act < this.max) return this.run(fn, key);

      const p = { high: 3, normal: 2, low: 1 }[pri];
      return new Promise<T>((res, rej) => {
        let i = 0;
        while (i < this.q.length && this.q[i].pri >= p) i++;
        this.q.splice(i, 0, {
          fn: fn as () => Promise<unknown>,
          res: res as (v: unknown) => void,
          rej,
          pri: p,
        });
      });
    };

    const p = run();
    if (key) {
      this.pend.set(key, p);
      p.finally(() => this.pend.delete(key));
    }
    return p;
  }

  private async run<T>(fn: () => Promise<T>, key?: string | null): Promise<T> {
    this.act++;
    try {
      return await fn();
    } finally {
      this.act--;
      if (key) this.pend.delete(key);
      this.process();
    }
  }

  private process(): void {
    while (this.q.length && this.act < this.max) {
      const t = this.q.shift();
      if (t) this.run(t.fn).then(t.res).catch(t.rej);
    }
  }

  stats() {
    return { active: this.act, queued: this.q.length, max: this.max, pending: this.pend.size };
  }
}

const pool = new Pool();

// -------------------- Utilities --------------------
// Robust buildUrl — handles base with/without trailing slashes and endpoint with/without leading slashes.
// Accepts absolute URLs as-is.
const buildUrl = (ep: string, params?: QueryParams): string => {
  let url = ep;
  if (!/^https?:\/\//i.test(ep)) {
    const base = CFG.API_URL.replace(/\/+$/, ''); // strip all trailing slashes
    const clean = ep.replace(/^\/+/, ''); // strip all leading slashes
    url = base ? `${base}/${clean}` : clean;
  }

  if (!params) return url;

  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v != null) sp.append(k, String(v));
  }
  const qs = sp.toString();
  return qs ? `${url}?${qs}` : url;
};

// Auth header getter with lightweight caching and runtime compatibility
const getAuth = (() => {
  let cache: Record<string, string> | null = null;
  let last = 0;

  return (): Record<string, string> => {
    const now = Date.now();
    if (cache && now - last < 300000) return cache;

    const h: Record<string, string> = {};
    const env = process?.env || (globalThis as any)['__ENV__'] || {};
    const { AUTH_USERNAME: u, AUTH_PASSWORD: p, API_TOKEN: t } = env;

    if (u && p) {
      // prefer btoa in browser/Bun, Buffer in Node — safe fallback
      let enc: string;
      try {
        if (IS_BUN || typeof btoa !== 'undefined') {
          enc = btoa(`${u}:${p}`);
        } else if (typeof Buffer !== 'undefined') {
          enc = (Buffer as any).from(`${u}:${p}`).toString('base64');
        } else {
          // last resort — very small shim (not ideal for production but avoids crash)
          enc = typeof window !== 'undefined' ? btoa(`${u}:${p}`) : Buffer.from(`${u}:${p}`).toString('base64');
        }
      } catch {
        enc = `${u}:${p}`; // fallback — best-effort
      }
      h.Authorization = `Basic ${enc}`;
    } else if (t) {
      h.Authorization = `Bearer ${t}`;
    }

    cache = h;
    last = now;
    return h;
  };
})();

const sanitize = (h: Record<string, string>): Record<string, string> => {
  const s = { ...h };
  if (s.Authorization) s.Authorization = '[REDACTED]';
  if (s['X-API-Key']) s['X-API-Key'] = '[REDACTED]';
  if (s.Cookie) s.Cookie = '[REDACTED]';
  return s;
};

const err = (name: string, msg: string, status: number, retry = false, url?: string, method?: string): ApiError => ({
  name,
  message: msg,
  status,
  retryable: retry,
  url,
  method,
});

// -------------------- Type Inference --------------------
const inferType = (v: unknown, d = 0): string => {
  if (d > 8) return 'unknown';
  if (v === null) return 'null';
  if (v === undefined) return 'undefined';

  if (Array.isArray(v)) {
    if (!v.length) return 'unknown[]';
    const types = [...new Set(v.slice(0, 3).map((i) => inferType(i, d + 1)))];
    return types.length === 1 ? `${types[0]}[]` : `(${types.join(' | ')})[]`;
  }

  if (typeof v === 'object') {
    const e = Object.entries(v).slice(0, 15);
    if (!e.length) return 'Record<string, unknown>';
    const props = e.map(([k, val]) => `  ${k}: ${inferType(val, d + 1)};`).join('\n');
    return `{\n${props}\n}`;
  }

  return typeof v;
};

const logTypes = <T>(
  ep: string,
  method: string,
  data: T,
  meta?: { duration?: number; attempt?: number },
): void => {
  if (!CFG.IS_DEV) return;

  try {
    let payload = data;
    if (payload && typeof payload === 'object' && 'success' in payload) {
      payload = (payload as { data?: unknown }).data as T;
    }

    if (payload == null) {
      console.log(`🔍 [SafeFetch] ${method} "${ep}"\ntype Response = ${payload === null ? 'null' : 'undefined'};`);
      return;
    }

    const t = typeof payload;
    if (t === 'string' || t === 'number' || t === 'boolean') {
      console.log(`🔍 [SafeFetch] ${method} "${ep}"\ntype Response = ${t};`);
      return;
    }

    const str = JSON.stringify(payload);
    if (str.length > CFG.LOG_LIMIT) {
      console.log(`🔍 [SafeFetch] ${method} "${ep}" - Response too large (${str.length} chars)`);
      return;
    }

    const name = ep.replace(/[^\w]/g, '_') || 'Api';
    console.log(`🔍 [SafeFetch] ${method} "${ep}"\ntype ${name}Response = ${inferType(payload)};`);

    if (meta?.duration) {
      console.log(`⏱️ ${meta.duration}ms${meta.attempt ? ` (attempt ${meta.attempt})` : ''}`);
    }
  } catch (e) {
    console.error('[SafeFetch] logTypes error:', e);
  }
};

// -------------------- Response Handler --------------------
const handleResp = async <T>(res: Response, url: string, method: string): Promise<ApiResponse<T>> => {
  const h: Record<string, string> = {};
  res.headers.forEach((v, k) => {
    h[k] = v;
  });

  const isJson = res.headers.get('content-type')?.includes('application/json');
  let data: unknown;
  try {
    data = isJson ? await res.json() : await res.text();
  } catch {
    data = null;
  }

  if (res.ok) return { success: true, status: res.status, data: data as T, headers: h };

  let msg = `HTTP ${res.status}`;
  if (typeof data === 'string') msg = data;
  else if (data && typeof data === 'object') {
    if ('message' in data && typeof (data as any).message === 'string') msg = (data as any).message;
    else if ('error' in data && typeof (data as any).error === 'string') msg = (data as any).error;
  }

  return {
    success: false,
    status: res.status,
    error: err('HttpError', msg, res.status, RETRY_CODES.has(res.status), url, method),
    data: null,
  };
};

// -------------------- Core Request --------------------
const execReq = async <T>(
  method: HttpMethod,
  url: string,
  opts: {
    body?: BodyInit;
    headers: Record<string, string>;
    timeout: number;
    signal?: AbortSignal;
    cache?: RequestCache;
    next?: NextFetchConfig;
  },
): Promise<ApiResponse<T>> => {
  const ctrl = new AbortController();
  const tid = setTimeout(() => ctrl.abort(), opts.timeout);

  let cleanup: (() => void) | null = null;
  if (opts.signal) {
    if (opts.signal.aborted) {
      clearTimeout(tid);
      return {
        success: false,
        status: 0,
        error: err('AbortError', 'Request was aborted', 0),
        data: null,
      };
    }
    cleanup = () => ctrl.abort();
    opts.signal.addEventListener('abort', cleanup);
  }

  try {
    const fo: RequestInit = {
      method,
      headers: opts.headers,
      signal: ctrl.signal,
      cache: opts.cache,
      next: opts.next,
    };
    if (opts.body) fo.body = opts.body;

    const res = await fetch(url, fo);
    clearTimeout(tid);
    if (cleanup && opts.signal) opts.signal.removeEventListener('abort', cleanup);

    return await handleResp<T>(res, url, method);
  } catch (e) {
    clearTimeout(tid);
    if (cleanup && opts.signal) opts.signal.removeEventListener('abort', cleanup);

    if (e instanceof Error && e.name === 'AbortError') {
      const isTimeout = !opts.signal?.aborted;
      return {
        success: false,
        status: isTimeout ? 408 : 0,
        error: err(
          isTimeout ? 'TimeoutError' : 'AbortError',
          isTimeout ? 'Request timed out' : 'Request was aborted by caller',
          isTimeout ? 408 : 0,
          isTimeout,
          url,
          method,
        ),
        data: null,
      };
    }

    return {
      success: false,
      status: 0,
      error: err('NetworkError', e instanceof Error ? e.message : 'Request failed', 0, true, url, method),
      data: null,
    };
  }
};

// -------------------- Retry Logic --------------------
const retryDelay = (att: number): number => Math.min(1000, 100 * 2 ** (att - 1) + Math.random() * 100);

const canRetry = (method: HttpMethod, status: number, attempt: number, max: number): boolean => {
  if (attempt > max) return false;
  if (status === 0 || status === 408) return true;
  return IDEMPOTENT.has(method) && RETRY_CODES.has(status);
};

// -------------------- Main API --------------------
export default async function apiRequest<TResponse = unknown, TBody extends RequestBody = RequestBody>(
  method: HttpMethod,
  endpoint: string,
  opts: RequestOptions<TBody, TResponse> = {},
): Promise<ApiResponse<TResponse>> {
  if (!HTTP_METHODS.includes(method)) {
    return {
      success: false,
      status: 400,
      error: err('ValidationError', `Invalid method: ${method}`, 400),
      data: null,
    };
  }

  const {
    data,
    params,
    retries = CFG.RETRIES,
    timeout = CFG.TIMEOUT,
    headers: custom = {},
    transform,
    priority = 'normal',
    signal,
    logTypes: log = false,
    cache,
    next,
    dedupeKey = null,
  } = opts;

  const url = buildUrl(endpoint, params);
  const headers: Record<string, string> = { Accept: 'application/json', ...getAuth(), ...custom };

  let body: BodyInit | undefined;
  if (data instanceof FormData) body = data;
  else if (typeof data === 'string') body = data;
  else if (data != null) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(data);
  }

  // Ensure dedupe key is a string (if not provided, fallback to stable generated key)
  const safeBodyForKey = typeof body === 'string' ? body : body instanceof FormData ? '[formdata]' : body ? JSON.stringify(body).slice(0, 200) : '';
  const key = dedupeKey !== null ? dedupeKey : `${method}:${url}:${safeBodyForKey}`;

  const start = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();

  return pool.exec(
    async (): Promise<ApiResponse<TResponse>> => {
      let att = 0;

      while (true) {
        att++;
        await limiter.check();

        const to = typeof timeout === 'function' ? timeout(att) : timeout;
        const res = await execReq<TResponse>(method, url, {
          body,
          headers,
          timeout: to,
          signal,
          cache,
          next,
        });

        if (res.success) {
          if (log)
            logTypes(endpoint, method, res.data, {
              duration: Math.round((typeof performance !== 'undefined' && performance.now ? performance.now() - start : Date.now() - start) as number),
              attempt: att > 1 ? att : undefined,
            });
          return transform ? { ...res, data: transform(res.data) } : res;
        }

        if (!canRetry(method, res.status, att, retries)) return res;
        await new Promise((r) => setTimeout(r, retryDelay(att)));
      }
    },
    priority,
    key,
  );
}

// -------------------- Helper Functions --------------------
apiRequest.isSuccess = <T>(r: ApiResponse<T>): r is Extract<ApiResponse<T>, { success: true }> => r.success;
apiRequest.isError = <T>(r: ApiResponse<T>): r is Extract<ApiResponse<T>, { success: false }> => !r.success;
apiRequest.utils = {
  getStats: () => ({
    pool: pool.stats(),
    rateLimit: limiter.stats(),
    runtime: IS_BUN ? 'bun' : 'node',
  }),
  timeout: (ms: number): AbortSignal => {
    const c = new AbortController();
    setTimeout(() => c.abort(), ms);
    return c.signal;
  },
  sanitizeHeaders: sanitize,
  // Next.js 16 cache tag helpers
  revalidateTag: async (tag: string, profile: string | { expire: number } = 'max') => {
    if (typeof window === 'undefined') {
      const { revalidateTag } = await import('next/cache');
      return revalidateTag(tag, profile);
    }
  },
  revalidatePath: async (path: string, type?: 'page' | 'layout') => {
    if (typeof window === 'undefined') {
      const { revalidatePath } = await import('next/cache');
      return revalidatePath(path, type);
    }
  },
} as const;
