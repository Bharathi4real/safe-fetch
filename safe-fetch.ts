/**
 * SafeFetch – Optimized Typed Fetch utility for Next.js
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * Memory-optimized with unified retry, timeout & adaptive pooling
 * https://github.com/Bharathi4real/safe-fetch/
 */

import { type ZodSchema } from 'zod';

/* ─── Public Types ─────────────────────────────────────────────────────────── */

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

export interface ApiError {
  readonly name: string;
  readonly message: string;
  readonly status: number;
  readonly retryable?: boolean;
  readonly url?: string;
  readonly method?: string;
}

export type ApiResponse<T = unknown> =
  | { success: true; status: number; data: T; headers: Record<string, string>; requestId: string }
  | { success: false; status: number; error: ApiError; data: null };

type BodylessOptions<T> = Omit<RequestOptions<never, T>, 'data'>;

/* ─── Runtime Detection ─────────────────────────────────────────────────────── */

const IS_BUN = typeof globalThis !== 'undefined' && 'Bun' in globalThis;

const IS_DEV =
  typeof process !== 'undefined' &&
  process.env.NODE_ENV !== 'production' &&
  process.env.NODE_ENV !== 'test';

const RETRY_CODES = new Set([408, 429, 500, 502, 503, 504]);
const PRIORITY_VALUES = { high: 3, normal: 2, low: 1 } as const;

/* ─── Default Config ─────────────────────────────────────────────────────────── */

const DEFAULT_CFG = {
  RETRIES: 2,
  TIMEOUT: 60_000,
  MAX_CONCURRENT: IS_BUN ? 20 : 10,
  RATE_MAX: 100,
  RATE_WINDOW: 60_000,
  AUTH_CACHE_TTL: 300_000,
} as const;

const composeSignals = (a: AbortSignal, b: AbortSignal): AbortSignal => {
  if (typeof AbortSignal.any === 'function') return AbortSignal.any([a, b]);

  const ctrl = new AbortController();
  const abort = () => ctrl.abort();
  a.addEventListener('abort', abort, { once: true });
  b.addEventListener('abort', abort, { once: true });
  // If either is already aborted, fire immediately
  if (a.aborted || b.aborted) ctrl.abort();
  return ctrl.signal;
};

class RateLimiter {
  private readonly timestamps: Float64Array;
  private head = 0;
  private size = 0;

  constructor(private readonly capacity: number) {
    this.timestamps = new Float64Array(capacity);
  }

  async check(max: number, win: number): Promise<void> {
    while (true) {
      const now = Date.now();
      const cutoff = now - win;

      // Evict expired timestamps from the ring-buffer head
      while (this.size > 0 && this.timestamps[this.head] < cutoff) {
        this.head = (this.head + 1) % this.capacity;
        this.size--;
      }

      if (this.size < max) break;

      const waitTime = win - (now - this.timestamps[this.head]);
      await new Promise<void>((r) => setTimeout(r, Math.max(0, waitTime)));
    }

    // Record this request
    const index = (this.head + this.size) % this.capacity;
    this.timestamps[index] = Date.now();
    this.size++;
  }

  stats = () => ({ current: this.size });
}

/* ─── Connection Pool ───────────────────────────────────────────────────────── */
class Pool {
  private readonly queue: Array<{ fn: () => void; pri: number }> = [];
  private active = 0;
  private readonly pending = new Map<string, Promise<unknown>>();

  constructor(private readonly max: number) {}

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
          if (key) this.pending.delete(key);
          reject(e);
        } finally {
          this.active--;
          if (key) this.pending.delete(key);
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
      if (this.queue[mid].pri >= priVal) left = mid + 1;
      else right = mid;
    }

    this.queue.splice(left, 0, { fn, pri: priVal });
  }

  stats = () => ({ active: this.active, queued: this.queue.length });
}

/* ─── Environment ───────────────────────────────────────────────────────────── */
interface GlobalEnv {
  __ENV__?: Record<string, string>;
}

const getEnv = (() => {
  let cachedEnv: ReturnType<typeof createEnv> | null = null;

  function createEnv() {
    const env = process.env || (globalThis as unknown as GlobalEnv).__ENV__ || {};
    return {
      API_URL: env.API_URL || env.NEXT_PUBLIC_API_URL || '',
      AUTH_USERNAME: env.AUTH_USERNAME || env.API_USERNAME || '',
      AUTH_PASSWORD: env.AUTH_PASSWORD || env.API_PASSWORD || '',
      API_TOKEN: env.AUTH_TOKEN || env.API_TOKEN || '',
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

  if (IS_DEV) {
    (get as { __resetCache?: () => void }).__resetCache = () => {
      cachedEnv = null;
    };
  }

  return get;
})();

export const __resetEnvCache = IS_DEV
  ? () => (getEnv as { __resetCache?: () => void }).__resetCache?.()
  : undefined;

/* ─── Auth Header Cache ─────────────────────────────────────────────────────── */
const buildAuthCache = (cacheTtl: number) => {
  let cache: Record<string, string> | null = null;
  let lastUpdate = 0;
  let dirty = false;

  const build = (): Record<string, string> => {
    const env = getEnv();
    const headers: Record<string, string> = {};

    if (env?.AUTH_USERNAME && env.AUTH_PASSWORD) {
      const credentials = `${env.AUTH_USERNAME}:${env.AUTH_PASSWORD}`;
      const encoded =
        typeof btoa !== 'undefined'
          ? btoa(credentials)
          : Buffer.from(credentials).toString('base64');
      headers.Authorization = `Basic ${encoded}`;
    } else if (env?.API_TOKEN) {
      headers.Authorization = `Bearer ${env.API_TOKEN}`;
    }

    return headers;
  };

  return {
    getAuthHeaders(): Record<string, string> {
      const now = Date.now();
      if (cache && !dirty && now - lastUpdate < cacheTtl) return cache;
      dirty = false;
      lastUpdate = now;
      cache = build();
      return cache;
    },
    invalidateAuthCache(): void {
      dirty = true;
    },
  };
};

/* ─── URL Builder (LRU cache) ───────────────────────────────────────────────── */
const buildUrlFactory = (maxCache = 100) => {
  const cache = new Map<string, string>();

  return (ep: string, base: string, p?: QueryParams): string => {
    const cacheKey = p ? `${ep}:${JSON.stringify(p)}` : ep;
    const cached = cache.get(cacheKey);

    if (cached) {
      cache.delete(cacheKey);
      cache.set(cacheKey, cached);
      return cached;
    }

    let url = ep;
    if (!/^https?:\/\//i.test(ep)) {
      const resolvedBase =
        base || (typeof window !== 'undefined' ? window.location.origin : '');
      url = `${resolvedBase.replace(/\/+$/, '')}/${ep.replace(/^\/+/, '')}`;
    }

    if (p) {
      const params = new URLSearchParams();
      for (const [k, v] of Object.entries(p)) {
        if (v != null) params.append(k, String(v));
      }
      const qs = params.toString();
      if (qs) url += `?${qs}`;
    }

    if (cache.size >= maxCache) {
      const firstKey = cache.keys().next().value;
      if (firstKey !== undefined) cache.delete(firstKey);
    }

    cache.set(cacheKey, url);
    return url;
  };
};

const sortedStringify = (v: unknown): string => {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(sortedStringify).join(',')}]`;

  const sorted = Object.keys(v as object)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${sortedStringify((v as Record<string, unknown>)[k])}`);

  return `{${sorted.join(',')}}`;
};

const buildDedupeKey = (method: HttpMethod, url: string, data?: RequestBody): string => {
  if (!data) return `${method}:${url}`;
  if (data instanceof FormData) return `${method}:${url}:formdata`;
  if (data instanceof ArrayBuffer) return `${method}:${url}:arraybuffer`;
  if (typeof Buffer !== 'undefined' && data instanceof Buffer) return `${method}:${url}:buffer`;
  if (typeof data === 'string') return `${method}:${url}:${data}`;
  if (Array.isArray(data)) return `${method}:${url}:array:${sortedStringify(data)}`;
  return `${method}:${url}:${sortedStringify(data)}`;
};

const calculateBackoff = (attempt: number): number => {
  const cap = 10_000;
  const ceiling = Math.min(cap, 100 * 2 ** (attempt - 1));
  return Math.random() * ceiling;
};

interface NormalizedError {
  status: number;
  name: string;
  message: string;
}

const normalizeError = (e: unknown): NormalizedError => {
  if (e instanceof DOMException && e.name === 'AbortError') {
    return { status: 408, name: 'AbortError', message: 'Request aborted' };
  }
  if (typeof e === 'object' && e !== null) {
    const obj = e as Record<string, unknown>;
    return {
      status: typeof obj.status === 'number' ? obj.status : 0,
      name: typeof obj.name === 'string' ? obj.name : 'Error',
      message:
        typeof obj.msg === 'string'
          ? obj.msg
          : typeof obj.message === 'string'
            ? obj.message
            : 'Unknown error',
    };
  }
  return { status: 0, name: 'Error', message: String(e) };
};

const createErrorResponse = (
  e: unknown,
  url: string,
  method: string,
  retryable = false,
): ApiResponse<never> => {
  const { status, name, message } = normalizeError(e);
  return {
    success: false,
    status,
    error: { name, message, status, retryable, url, method },
    data: null,
  };
};

type ParseResult =
  | { ok: true; data: unknown }
  | { ok: false; reason: 'parse_error' | 'empty' };

const parseResponse = async (res: Response): Promise<ParseResult> => {
  const contentType = res.headers.get('content-type') ?? '';
  let text: string;

  try {
    text = await res.text();
  } catch {
    return { ok: false, reason: 'parse_error' };
  }

  if (!text.trim()) return { ok: false, reason: 'empty' };

  if (contentType.includes('json')) {
    try {
      return { ok: true, data: JSON.parse(text) };
    } catch {
      return { ok: false, reason: 'parse_error' };
    }
  }

  return { ok: true, data: text };
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

/* ─── Dev Utilities ──────────────────────────────────────────────────────────── */
const inferType = (v: unknown, d = 0): string => {
  if (d >= 8) return 'unknown';
  if (v === null) return 'null';
  if (v === undefined) return 'undefined';
  const type = typeof v;
  if (type !== 'object') return type;
  if (Array.isArray(v)) return v.length ? `(${inferType(v[0], d + 1)})[]` : 'unknown[]';
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

export interface SafeFetchConfig {
  /** Base URL. Defaults to API_URL / NEXT_PUBLIC_API_URL env var. */
  baseUrl?: string;
  retries?: number;
  timeout?: number;
  maxConcurrent?: number;
  rateMax?: number;
  rateWindow?: number;
  authCacheTtl?: number;
  /** Override the default env-based auth header builder. */
  getAuthHeaders?: () => Record<string, string>;
}

export function createSafeFetch(instanceConfig: SafeFetchConfig = {}) {
  const cfg = {
    retries: instanceConfig.retries ?? DEFAULT_CFG.RETRIES,
    timeout: instanceConfig.timeout ?? DEFAULT_CFG.TIMEOUT,
    maxConcurrent: instanceConfig.maxConcurrent ?? DEFAULT_CFG.MAX_CONCURRENT,
    rateMax: instanceConfig.rateMax ?? DEFAULT_CFG.RATE_MAX,
    rateWindow: instanceConfig.rateWindow ?? DEFAULT_CFG.RATE_WINDOW,
    authCacheTtl: instanceConfig.authCacheTtl ?? DEFAULT_CFG.AUTH_CACHE_TTL,
  };

  const pool = new Pool(cfg.maxConcurrent);
  const limiter = new RateLimiter(cfg.rateMax);
  const buildUrl = buildUrlFactory();
  const authCache = buildAuthCache(cfg.authCacheTtl);

  const resolveAuthHeaders = instanceConfig.getAuthHeaders ?? authCache.getAuthHeaders;

  /* ── Core Request ────────────────────────────────────────────────────────── */
  async function apiRequest<T = unknown>(
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

    const {
      retries = cfg.retries,
      timeout = cfg.timeout,
      priority = 'normal',
    } = opts;

    const baseUrl = instanceConfig.baseUrl ?? getEnv()?.API_URL ?? '';
    const url = buildUrl(endpoint, baseUrl, opts.params);
    const key =
      opts.dedupeKey !== undefined ? opts.dedupeKey : buildDedupeKey(method, url, opts.data);

    const start = performance.now();

    return pool.exec(
      async () => {
        let attempt = 0;

        // eslint-disable-next-line no-constant-condition
        while (true) {
          attempt++;
          await limiter.check(cfg.rateMax, cfg.rateWindow);

          const ctrl = new AbortController();
          const timeoutDuration = typeof timeout === 'function' ? timeout(attempt) : timeout;
          const timeoutId = setTimeout(() => ctrl.abort(), timeoutDuration);

          const composedSignal = opts.signal
            ? composeSignals(opts.signal, ctrl.signal)
            : ctrl.signal;

          try {
            const requestId =
              opts.headers?.['X-Request-Id'] ??
              (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
                ? crypto.randomUUID()
                : `${Date.now()}-${Math.random().toString(36).slice(2)}`);

            const headers: Record<string, string> = {
              Accept: 'application/json',
              'X-Request-Id': requestId,
              ...(!opts.skipAuth ? resolveAuthHeaders() : {}),
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

            const parsed = await parseResponse(res);

            const rawData: unknown = parsed.ok ? parsed.data : null;

            if (!res.ok) {
              const message = parsed.ok
                ? extractErrorMessage(rawData, res.statusText)
                : res.statusText;
              throw { status: res.status, msg: message };
            }

            if (!parsed.ok && IS_DEV) {
              console.warn(
                `[SafeFetch] ${method} ${endpoint} — body parse failed (${parsed.reason}). ` +
                  `Response data will be null.`,
              );
            }

            if (opts.logTypes && IS_DEV) {
              logTypes(endpoint, method, rawData, {
                time: Math.round(performance.now() - start),
                att: attempt > 1 ? attempt : undefined,
              });
            }

            const responseHeaders: Record<string, string> = {};
            res.headers.forEach((v, k) => {
              responseHeaders[k] = v;
            });

            const transformed = opts.transform ? opts.transform(rawData as T) : (rawData as T);

            if (opts.schema) {
              const result = opts.schema.safeParse(transformed);
              if (!result.success) {
                return {
                  success: false as const,
                  status: res.status,
                  error: {
                    name: 'ValidationError',
                    message: result.error.message,
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
                data: result.data,
                headers: responseHeaders,
                requestId,
              };
            }

            return {
              success: true as const,
              status: res.status,
              data: transformed,
              headers: responseHeaders,
              requestId,
            };
          } catch (e: unknown) {
            clearTimeout(timeoutId);

            const { status } = normalizeError(e);

            if (!isRetryableError(status, attempt, retries)) {
              return createErrorResponse(e, url, method, false);
            }

            await new Promise<void>((r) => setTimeout(r, calculateBackoff(attempt)));
          }
        }
      },
      priority,
      key,
    );
  }

  /* ── Type Guards ─────────────────────────────────────────────────────────── */
  apiRequest.isSuccess = <T>(
    r: ApiResponse<T>,
  ): r is Extract<ApiResponse<T>, { success: true }> => r.success;

  apiRequest.isError = <T>(
    r: ApiResponse<T>,
  ): r is Extract<ApiResponse<T>, { success: false }> => !r.success;

  apiRequest.utils = {
    getStats: () => ({
      pool: pool.stats(),
      rateLimit: limiter.stats(),
      runtime: IS_BUN ? 'bun' : 'node',
    }),
    sanitizeHeaders: (h: Record<string, string>): Record<string, string> => {
      const sanitized = { ...h };
      for (const key of ['Authorization', 'X-API-Key', 'Cookie']) {
        if (sanitized[key]) sanitized[key] = '[REDACTED]';
      }
      return sanitized;
    },
  };

  const api = {
    get<T>(endpoint: string, opts?: BodylessOptions<T>): Promise<ApiResponse<T>> {
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
    delete<T>(endpoint: string, opts?: BodylessOptions<T>): Promise<ApiResponse<T>> {
      return apiRequest<T>('DELETE', endpoint, opts as RequestOptions<RequestBody, T>);
    },
  } as const;

  return { apiRequest, api, invalidateAuthCache: authCache.invalidateAuthCache };
}

/* ─── Default Singleton ──────────────────────────────────────────────────────── */
export const { apiRequest, api, invalidateAuthCache } = createSafeFetch();
export default apiRequest;
