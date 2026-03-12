/**
 * SafeFetch – Optimized Typed Fetch utility for Next.js
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * Memory-optimized with unified retry, timeout & adaptive pooling
 * https://github.com/Bharathi4real/safe-fetch/
 */

import { type ZodSchema } from 'zod';

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] as const;
export type HttpMethod = (typeof HTTP_METHODS)[number];
export type RequestBody =
  | Record<string, unknown>
  | FormData
  | ArrayBuffer
  | Buffer
  | string
  | null
  | unknown[];
export type QueryParams = Record<string, string | number | boolean | null | undefined>;

interface ErrShape {
  status?: number;
  name?: string;
  msg?: string;
  message?: string;
}

export interface RequestOptions<TBody extends RequestBody = RequestBody, TResponse = unknown> {
  data?: TBody;
  params?: QueryParams;
  retries?: number;
  timeout?: number | ((attempt: number) => number);
  headers?: Record<string, string>;
  transform?(data: TResponse): TResponse;
  schema?: ZodSchema<TResponse>;
  priority?: 'high' | 'normal' | 'low';
  signal?: AbortSignal;
  logTypes?: boolean;
  cache?: RequestCache;
  next?: { revalidate?: number | false; tags?: string[] };
  dedupeKey?: string | null;
  skipAuth?: boolean;
}

export type ApiResponse<T = unknown> =
  | { success: true; status: number; data: T; headers: Record<string, string> }
  | { success: false; status: number; error: ApiError; data: null };

export interface ApiError {
  readonly name: string;
  readonly message: string;
  readonly status: number;
  readonly retryable?: boolean;
  readonly url?: string;
  readonly method?: string;
}

const IS_BUN = typeof globalThis !== 'undefined' && 'Bun' in globalThis;
const RETRY_CODES = new Set([408, 429, 500, 502, 503, 504]);
const PRIORITY_VALUES = { high: 3, normal: 2, low: 1 } as const;

interface GlobalEnv {
  __ENV__?: Record<string, string>;
}

/* --- Environment --- */
// getEnv() is called lazily at each use site so the cache
// initialises on first actual request, not at import time.
const getEnv = (() => {
  let cachedEnv: ReturnType<typeof createEnv> | null = null;

  function createEnv() {
    const env = process.env || (globalThis as unknown as GlobalEnv).__ENV__ || {};
    return {
      API_URL: env.API_URL || env.NEXT_PUBLIC_API_URL || '',
      AUTH_USERNAME: env.AUTH_USERNAME || env.API_USERNAME || '',
      AUTH_PASSWORD: env.AUTH_PASSWORD || env.API_PASSWORD || '',
      API_TOKEN: env.AUTH_TOKEN || env.API_TOKEN || '',
      NODE_ENV: env.NODE_ENV || 'development',
    };
  }

  const get = () => {
    if (!cachedEnv) {
      cachedEnv = createEnv();
      if (!cachedEnv.API_URL) {
        console.error('\x1b[31m%s\x1b[0m', '❌ [SafeFetch] Missing API_URL');
      }
      if (!cachedEnv.AUTH_USERNAME && !cachedEnv.API_TOKEN) {
        console.error('\x1b[31m%s\x1b[0m', '❌ [SafeFetch] Missing Auth Credentials');
      }
    }
    return cachedEnv;
  };

  if (process.env.NODE_ENV !== 'production') {
    (get as { __resetCache?: () => void }).__resetCache = () => {
      cachedEnv = null;
    };
  }

  return get;
})();

export const __resetEnvCache =
  process.env.NODE_ENV !== 'production'
    ? () => (getEnv as { __resetCache?: () => void }).__resetCache?.()
    : undefined;

const CFG = {
  RETRIES: 2,
  TIMEOUT: 60000,
  MAX_CONCURRENT: IS_BUN ? 20 : 10,
  RATE_MAX: 100,
  RATE_WINDOW: 60000,
  AUTH_CACHE_TTL: 300000,
} as const;

/* --- Rate Limiter --- */
class RateLimiter {
  private readonly timestamps: Float64Array;
  private head = 0;
  private size = 0;

  constructor(private readonly capacity = CFG.RATE_MAX) {
    this.timestamps = new Float64Array(capacity);
  }

  async check(max = CFG.RATE_MAX, win = CFG.RATE_WINDOW): Promise<void> {
    const now = Date.now();
    const cutoff = now - win;

    while (this.size > 0 && this.timestamps[this.head] < cutoff) {
      this.head = (this.head + 1) % this.capacity;
      this.size--;
    }

    if (this.size >= max) {
      const waitTime = win - (now - this.timestamps[this.head]);
      await new Promise((r) => setTimeout(r, waitTime));
      return this.check(max, win);
    }

    const index = (this.head + this.size) % this.capacity;
    this.timestamps[index] = now;
    this.size++;
  }

  stats = () => ({ current: this.size });
}

const limiter = new RateLimiter();

/* --- Connection Pool --- */
class Pool {
  private readonly queue: Array<{ fn: () => void; pri: number }> = [];
  private active = 0;
  private readonly pending = new Map<string, Promise<unknown>>();

  constructor(private readonly max = CFG.MAX_CONCURRENT) {}

  async exec<T>(
    fn: () => Promise<T>,
    pri: 'high' | 'normal' | 'low' = 'normal',
    key?: string | null,
  ): Promise<T> {
    if (key) {
      const existing = this.pending.get(key);
      if (existing) return existing as Promise<T>;
    }

    const task = new Promise<T>((resolve, reject) => {
      const run = async () => {
        this.active++;
        try {
          resolve(await fn());
        } catch (e) {
          // [F6] Ensure pending key is removed even when fn() rejects hard
          if (key) this.pending.delete(key);
          reject(e);
        } finally {
          this.active--;
          if (key) this.pending.delete(key); // no-op if already deleted above
          this.processQueue();
        }
      };

      if (this.active < this.max) {
        run();
      } else {
        this.enqueue(run, pri);
      }
    });

    if (key) this.pending.set(key, task);
    return task;
  }

  private processQueue(): void {
    if (this.queue.length > 0 && this.active < this.max) {
      this.queue.shift()?.fn();
    }
  }

  private enqueue(fn: () => void, pri: 'high' | 'normal' | 'low'): void {
    const priVal = PRIORITY_VALUES[pri];
    let left = 0;
    let right = this.queue.length;

    while (left < right) {
      const mid = (left + right) >>> 1;
      if (this.queue[mid].pri >= priVal) {
        left = mid + 1;
      } else {
        right = mid;
      }
    }

    this.queue.splice(left, 0, { fn, pri: priVal });
  }

  stats = () => ({ active: this.active, queued: this.queue.length });
}

const pool = new Pool();

/* --- Auth --- */
const { getAuthHeaders, invalidateAuthCache } = (() => {
  let cache: Record<string, string> | null = null;
  let lastUpdate = 0;
  let dirty = false;

  const build = (): Record<string, string> => {
    const { AUTH_USERNAME: u, AUTH_PASSWORD: p, API_TOKEN: t } = getEnv();
    const headers: Record<string, string> = {};

    if (u && p) {
      const credentials = `${u}:${p}`;
      const encoded =
        typeof btoa !== 'undefined'
          ? btoa(credentials)
          : Buffer.from(credentials).toString('base64');
      headers.Authorization = `Basic ${encoded}`;
    } else if (t) {
      headers.Authorization = `Bearer ${t}`;
    }

    return headers;
  };

  return {
    getAuthHeaders(): Record<string, string> {
      const now = Date.now();
      if (cache && !dirty && now - lastUpdate < CFG.AUTH_CACHE_TTL) return cache;
      dirty = false;
      lastUpdate = now;
      cache = build();
      return cache;
    },
    invalidateAuthCache(): void {
      dirty = true;
    },
  };
})();

export { invalidateAuthCache };

/* --- URL Builder --- */
// LRU: on cache hit, delete + re-set moves entry to Map tail (MRU position).
// Eviction always removes the Map head (LRU position) via .keys().next().
const buildUrl = (() => {
  const cache = new Map<string, string>();
  const MAX_CACHE = 100;

  return (ep: string, p?: QueryParams): string => {
    const cacheKey = p ? `${ep}:${JSON.stringify(p)}` : ep;
    const cached = cache.get(cacheKey);

    if (cached) {
      // Move to MRU position
      cache.delete(cacheKey);
      cache.set(cacheKey, cached);
      return cached;
    }

    let url = ep;
    if (!/^https?:\/\//i.test(ep)) {
      const base =
        getEnv().API_URL || (typeof window !== 'undefined' ? window.location.origin : '');
      url = `${base.replace(/\/+$/, '')}/${ep.replace(/^\/+/, '')}`;
    }

    if (p) {
      const params = new URLSearchParams();
      for (const [k, v] of Object.entries(p)) {
        if (v != null) params.append(k, String(v));
      }
      const qs = params.toString();
      if (qs) url += `?${qs}`;
    }

    if (cache.size >= MAX_CACHE) {
      // Evict LRU (Map head)
      const firstKey = cache.keys().next().value;
      if (firstKey !== undefined) cache.delete(firstKey);
    }
    cache.set(cacheKey, url);
    return url;
  };
})();

/* --- Dev Utilities --- */
const inferType = (v: unknown, d = 0): string => {
  if (d >= 8) return 'unknown';
  if (v === null) return 'null';
  if (v === undefined) return 'undefined';

  const type = typeof v;
  if (type !== 'object') return type;

  if (Array.isArray(v)) {
    return v.length ? `(${inferType(v[0], d + 1)})[]` : 'unknown[]';
  }

  const entries = Object.entries(v as Record<string, unknown>).slice(0, 10);
  if (entries.length === 0) return '{}';

  const props = entries.map(([k, val]) => `  ${k}: ${inferType(val, d + 1)}`).join(',\n');
  return `{\n${props}\n}`;
};

const logTypes = (
  ep: string,
  method: string,
  data: unknown,
  meta?: { time: number; att?: number },
): void => {
  const payload =
    typeof data === 'object' && data !== null && 'data' in data
      ? (data as { data: unknown }).data
      : data;

  const attemptInfo = meta?.att ? ` [attempt ${meta.att}]` : '';
  console.log(
    `🔍 [SafeFetch] ${method} ${ep} (${meta?.time}ms)${attemptInfo}\nType: ${inferType(payload)}`,
  );
};

/* --- Helpers --- */
const calculateBackoff = (attempt: number): number => Math.min(10000, 100 * 2 ** (attempt - 1));

const createErrorResponse = (error: unknown, url: string, method: string): ApiResponse<never> => {
  const err =
    typeof error === 'object' && error !== null ? (error as ErrShape) : { message: String(error) };

  const status = err.status || (err.name === 'AbortError' ? 408 : 0);

  return {
    success: false,
    status,
    error: {
      name: err.name || 'Error',
      message: err.msg || err.message || 'Unknown error',
      status,
      retryable: false,
      url,
      method,
    },
    data: null,
  };
};

const parseResponse = async (res: Response): Promise<unknown> => {
  const contentType = res.headers.get('content-type') ?? '';
  try {
    return contentType.includes('json') ? await res.json() : await res.text();
  } catch {
    // Parse failure (e.g. malformed JSON in a 500 body) — return null and
    // let the !res.ok branch below surface the real HTTP error.
    return null;
  }
};

const extractErrorMessage = (data: unknown, statusText: string): string => {
  if (typeof data === 'string') return data;
  if (typeof data === 'object' && data !== null) {
    const obj = data as Record<string, unknown>;
    if (typeof obj.message === 'string') return obj.message;
    if (typeof obj.error === 'string') return obj.error;
  }
  return statusText;
};

const isRetryableError = (status: number, attempt: number, maxRetries: number): boolean =>
  attempt <= maxRetries && (status === 408 || status >= 500 || RETRY_CODES.has(status));

const buildObjectFingerprint = (obj: Record<string, unknown>): string =>
  Object.entries(obj)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : String(v)}`)
    .join('&');

const buildDedupeKey = (method: HttpMethod, url: string, data?: RequestBody): string => {
  if (!data) return `${method}:${url}`;

  if (data instanceof FormData) return `${method}:${url}:formdata`;
  if (data instanceof ArrayBuffer) return `${method}:${url}:arraybuffer`;
  if (typeof Buffer !== 'undefined' && data instanceof Buffer) return `${method}:${url}:buffer`;
  if (typeof data === 'string') return `${method}:${url}:${data}`;
  if (Array.isArray(data)) return `${method}:${url}:array:${JSON.stringify(data)}`;

  return `${method}:${url}:${buildObjectFingerprint(data as Record<string, unknown>)}`;
};

/* --- Core Request --- */
export default async function apiRequest<T = unknown>(
  method: HttpMethod,
  endpoint: string,
  opts: RequestOptions<RequestBody, T> = {},
): Promise<ApiResponse<T>> {
  if (!HTTP_METHODS.includes(method)) {
    return {
      success: false,
      status: 400,
      error: { name: 'ValidationError', message: 'Invalid HTTP method', status: 400 },
      data: null,
    };
  }

  const { retries = CFG.RETRIES, timeout = CFG.TIMEOUT, priority = 'normal' } = opts;

  const url = buildUrl(endpoint, opts.params);
  const key =
    opts.dedupeKey !== undefined ? opts.dedupeKey : buildDedupeKey(method, url, opts.data);

  const start = performance.now();

  return pool.exec(
    async () => {
      let attempt = 0;

      // eslint-disable-next-line no-constant-condition
      while (true) {
        attempt++;
        await limiter.check();

        const ctrl = new AbortController();
        const timeoutDuration = typeof timeout === 'function' ? timeout(attempt) : timeout;
        const timeoutId = setTimeout(() => ctrl.abort(), timeoutDuration);

        const composedSignal =
          opts.signal
            ? AbortSignal.any([opts.signal, ctrl.signal])
            : ctrl.signal;

        try {
          const headers: Record<string, string> = {
            Accept: 'application/json',
            ...(!opts.skipAuth ? getAuthHeaders() : {}),
            ...opts.headers,
          };

          if (opts.data && !(opts.data instanceof FormData)) {
            headers['Content-Type'] = 'application/json';
          }

          const body = opts.data
            ? opts.data instanceof FormData ||
              opts.data instanceof ArrayBuffer ||
              (typeof Buffer !== 'undefined' && opts.data instanceof Buffer)
              ? (opts.data as BodyInit)
              : JSON.stringify(opts.data)
            : undefined;

          const res = await fetch(url, {
            method,
            headers,
            body,
            signal: composedSignal,
            ...(opts.next !== undefined && { next: opts.next }),
            ...(opts.cache !== undefined && { cache: opts.cache }),
          });

          clearTimeout(timeoutId);

          const data = await parseResponse(res);

          if (!res.ok) {
            throw { status: res.status, msg: extractErrorMessage(data, res.statusText) };
          }

          if (opts.logTypes && getEnv().NODE_ENV === 'development') {
            logTypes(endpoint, method, data, {
              time: Math.round(performance.now() - start),
              att: attempt > 1 ? attempt : undefined,
            });
          }

          const responseHeaders: Record<string, string> = {};
          res.headers.forEach((v, k) => {
            responseHeaders[k] = v;
          });

          const transformed = opts.transform ? opts.transform(data as T) : (data as T);

          if (opts.schema) {
            const parsed = opts.schema.safeParse(transformed);
            if (!parsed.success) {
              return {
                success: false as const,
                status: res.status,
                error: {
                  name: 'ValidationError',
                  message: parsed.error.message,
                  status: res.status,
                  retryable: false,
                  url,
                  method,
                },
                data: null,
              };
            }
            return {
              success: true as const,
              status: res.status,
              data: parsed.data,
              headers: responseHeaders,
            };
          }

          return {
            success: true as const,
            status: res.status,
            data: transformed,
            headers: responseHeaders,
          };
        } catch (e: unknown) {
          clearTimeout(timeoutId);
          
          const err = (
            typeof e === 'object' && e !== null ? e : { message: String(e) }
          ) as ErrShape;

          const status = err.status || (err.name === 'AbortError' ? 408 : 0);

          if (!isRetryableError(status, attempt, retries)) {
            return createErrorResponse(e, url, method);
          }

          await new Promise((r) => setTimeout(r, calculateBackoff(attempt)));
        }
      }
    },
    priority,
    key,
  );
}

/* --- Type Guards --- */
apiRequest.isSuccess = <T>(r: ApiResponse<T>): r is Extract<ApiResponse<T>, { success: true }> =>
  r.success;

apiRequest.isError = <T>(r: ApiResponse<T>): r is Extract<ApiResponse<T>, { success: false }> =>
  !r.success;

apiRequest.utils = {
  getStats: () => ({
    pool: pool.stats(),
    rateLimit: limiter.stats(),
    runtime: IS_BUN ? 'bun' : 'node',
  }),
  sanitizeHeaders: (h: Record<string, string>): Record<string, string> => {
    const sanitized = { ...h };
    const sensitiveHeaders = ['Authorization', 'X-API-Key', 'Cookie'];
    for (const key of sensitiveHeaders) {
      if (sanitized[key]) sanitized[key] = '[REDACTED]';
    }
    return sanitized;
  },
};

export const api = {
  get<T>(endpoint: string, opts?: Omit<RequestOptions<never, T>, 'data'>): Promise<ApiResponse<T>> {
    return apiRequest<T>('GET', endpoint, opts as RequestOptions<RequestBody, T>);
  },
  post<T>(endpoint: string, opts?: RequestOptions<RequestBody, T>): Promise<ApiResponse<T>> {
    return apiRequest<T>('POST', endpoint, opts);
  },
  put<T>(endpoint: string, opts?: RequestOptions<RequestBody, T>): Promise<ApiResponse<T>> {
    return apiRequest<T>('PUT', endpoint, opts);
  },
  patch<T>(endpoint: string, opts?: RequestOptions<RequestBody, T>): Promise<ApiResponse<T>> {
    return apiRequest<T>('PATCH', endpoint, opts);
  },
  delete<T>(
    endpoint: string,
    opts?: Omit<RequestOptions<never, T>, 'data'>,
  ): Promise<ApiResponse<T>> {
    return apiRequest<T>('DELETE', endpoint, opts as RequestOptions<RequestBody, T>);
  },
} as const;
