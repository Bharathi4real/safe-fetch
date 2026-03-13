/**
 * SafeFetch – Optimized Typed Fetch utility for Next.js
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * Memory-optimized with unified retry, timeout & adaptive pooling
 * https://github.com/Bharathi4real/safe-fetch/
 */

import { createHash } from "node:crypto";
import type { ZodSchema } from "zod";

/* ─── Public Types ─────────────────────────────────────────────────────────── */

const HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"] as const;
export type HttpMethod = (typeof HTTP_METHODS)[number];

export type RequestBody =
  | Record<string, unknown>
  | FormData
  | ArrayBuffer
  | Buffer
  | string
  | null
  | unknown[];

export type QueryParams = Record<
  string,
  string | number | boolean | null | undefined
>;

export interface RequestOptions<
  TBody extends RequestBody = RequestBody,
  TResponse = unknown,
> {
  data?: TBody;
  params?: QueryParams;
  retries?: number;
  timeout?: number | ((attempt: number) => number);
  headers?: Record<string, string>;
  transform?(data: TResponse): TResponse;
  schema?: ZodSchema<TResponse>;
  priority?: "high" | "normal" | "low";
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
  | {
      success: true;
      status: number;
      data: T;
      headers: Record<string, string>;
      requestId: string;
    }
  | { success: false; status: number; error: ApiError; data: null };

type BodylessOptions<T> = Omit<RequestOptions<never, T>, "data">;

/* ─── Constants ─────────────────────────────────────────────────────────────── */

const IS_BUN = typeof globalThis !== "undefined" && "Bun" in globalThis;

const IS_DEV =
  process.env.NODE_ENV !== "production" && process.env.NODE_ENV !== "test";

const RETRY_CODES = new Set([408, 429, 500, 502, 503, 504]);
const PRIORITY_VALUES = { high: 3, normal: 2, low: 1 } as const;

const DEFAULT_CFG = {
  RETRIES: 2,
  TIMEOUT: 60_000,
  MAX_CONCURRENT: IS_BUN ? 20 : 10,
  RATE_MAX: 100,
  RATE_WINDOW: 60_000,
  AUTH_CACHE_TTL: 300_000,
} as const;

const composeSignals = (a: AbortSignal, b: AbortSignal): AbortSignal => {
  if (typeof AbortSignal.any === "function") return AbortSignal.any([a, b]);
  const ctrl = new AbortController();
  if (a.aborted || b.aborted) {
    ctrl.abort();
    return ctrl.signal;
  }
  const abortA = () => {
    b.removeEventListener("abort", abortB);
    ctrl.abort();
  };
  const abortB = () => {
    a.removeEventListener("abort", abortA);
    ctrl.abort();
  };
  a.addEventListener("abort", abortA, { once: true });
  b.addEventListener("abort", abortB, { once: true });
  return ctrl.signal;
};

/* ─── Rate Limiter ──────────────────────────────────────────────────────────── */

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
      while (this.size > 0 && this.timestamps[this.head] < cutoff) {
        this.head = (this.head + 1) % this.capacity;
        this.size--;
      }
      if (this.size < max) break;
      await new Promise<void>((r) =>
        setTimeout(r, Math.max(0, win - (now - this.timestamps[this.head]))),
      );
    }
    this.timestamps[(this.head + this.size) % this.capacity] = Date.now();
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
    pri: "high" | "normal" | "low" = "normal",
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
          reject(e);
        } finally {
          this.active--;
          if (key) this.pending.delete(key);
          this.processQueue();
        }
      };
      this.active < this.max ? run() : this.enqueue(run, pri);
    });

    if (key) this.pending.set(key, task);
    return task;
  }

  private processQueue(): void {
    if (this.queue.length > 0 && this.active < this.max)
      this.queue.shift()?.fn();
  }

  private enqueue(fn: () => void, pri: "high" | "normal" | "low"): void {
    const priVal = PRIORITY_VALUES[pri];
    let l = 0,
      r = this.queue.length;
    while (l < r) {
      const m = (l + r) >>> 1;
      if (this.queue[m].pri >= priVal) {
        l = m + 1;
      } else {
        r = m;
      }
    }
    this.queue.splice(l, 0, { fn, pri: priVal });
  }

  stats = () => ({ active: this.active, queued: this.queue.length });
}

/* ─── Environment ───────────────────────────────────────────────────────────── */

interface GlobalEnv {
  __ENV__?: Record<string, string>;
}

const getEnv = (() => {
  let cached: ReturnType<typeof build> | null = null;

  function build() {
    const e: Record<string, string | undefined> =
      (typeof process !== "undefined" ? process.env : null) ||
      (globalThis as unknown as GlobalEnv).__ENV__ ||
      {};
    return {
      API_URL: e.API_URL || e.NEXT_PUBLIC_API_URL || "",
      AUTH_USERNAME: e.AUTH_USERNAME || e.API_USERNAME || "",
      AUTH_PASSWORD: e.AUTH_PASSWORD || e.API_PASSWORD || "",
      API_TOKEN: e.AUTH_TOKEN || e.API_TOKEN || "",
    };
  }

  const get = () => {
    if (!cached) {
      cached = build();
      if (!cached.API_URL)
        console.error("\x1b[31m%s\x1b[0m", "❌ [SafeFetch] Missing API_URL");
      if (!cached.AUTH_USERNAME && !cached.API_TOKEN)
        console.error(
          "\x1b[31m%s\x1b[0m",
          "❌ [SafeFetch] Missing Auth Credentials",
        );
    }
    return cached;
  };

  if (IS_DEV)
    (get as { __resetCache?: () => void }).__resetCache = () => {
      cached = null;
    };
  return get;
})();

export const __resetEnvCache = IS_DEV
  ? () => (getEnv as { __resetCache?: () => void }).__resetCache?.()
  : undefined;

/* ─── Auth Header Cache ─────────────────────────────────────────────────────── */

const buildAuthCache = (cacheTtl: number) => {
  let cache: Record<string, string> | null = null;
  let lastUpdate = 0;

  const build = (): Record<string, string> => {
    const env = getEnv();
    if (env?.AUTH_USERNAME && env.AUTH_PASSWORD) {
      const creds = `${env.AUTH_USERNAME}:${env.AUTH_PASSWORD}`;
      const encoded =
        typeof btoa !== "undefined"
          ? btoa(creds)
          : Buffer.from(creds).toString("base64");
      return { Authorization: `Basic ${encoded}` };
    }
    return env?.API_TOKEN ? { Authorization: `Bearer ${env.API_TOKEN}` } : {};
  };

  return {
    getAuthHeaders(): Record<string, string> {
      const now = Date.now();
      if (cache && now - lastUpdate < cacheTtl) return cache;
      lastUpdate = now;
      cache = build();
      return cache;
    },
    invalidateAuthCache(): void {
      lastUpdate = 0;
    },
  };
};

/* ─── URL Builder (LRU cache) ───────────────────────────────────────────────── */

const buildUrlFactory = (maxCache = 100) => {
  const cache = new Map<string, string>();

  return (
    ep: string,
    base: string,
    p?: QueryParams,
    allowedHosts?: string[],
  ): string => {
    if (!base && typeof window === "undefined") {
      throw new Error(
        "[SafeFetch] baseUrl is required in server contexts. " +
          "Set API_URL / NEXT_PUBLIC_API_URL or pass baseUrl to createSafeFetch().",
      );
    }

    const cacheKey = p ? `${ep}:${JSON.stringify(p)}` : ep;
    const cached = cache.get(cacheKey);
    if (cached) {
      cache.delete(cacheKey);
      cache.set(cacheKey, cached);
      return cached;
    }

    let url = /^https?:\/\//i.test(ep)
      ? ep
      : `${(base || (typeof window !== "undefined" ? window.location.origin : "")).replace(/\/+$/, "")}/${ep.replace(/^\/+/, "")}`;

    // SSRF guard
    if (allowedHosts?.length) {
      try {
        const { hostname } = new URL(url);
        if (!allowedHosts.includes(hostname)) {
          throw new Error(
            `[SafeFetch] Blocked request to disallowed host: ${hostname}`,
          );
        }
      } catch (err) {
        if ((err as Error).message.startsWith("[SafeFetch]")) throw err;
        throw new Error(
          `[SafeFetch] Could not parse URL for SSRF check: ${url}`,
        );
      }
    }

    if (p) {
      const params = new URLSearchParams();
      for (const [k, v] of Object.entries(p))
        if (v != null) params.append(k, String(v));
      const qs = params.toString();
      if (qs) url += `?${qs}`;
    }

    if (cache.size >= maxCache) {
      const first = cache.keys().next().value;
      if (first !== undefined) cache.delete(first);
    }
    cache.set(cacheKey, url);
    return url;
  };
};

/* ─── Helpers ───────────────────────────────────────────────────────────────── */

const sortedStringify = (v: unknown): string => {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(sortedStringify).join(",")}]`;
  return `{${Object.keys(v as object)
    .sort()
    .map(
      (k) =>
        `${JSON.stringify(k)}:${sortedStringify((v as Record<string, unknown>)[k])}`,
    )
    .join(",")}}`;
};

const buildDedupeKey = (
  method: HttpMethod,
  url: string,
  data?: RequestBody,
): string => {
  if (!data) return `${method}:${url}`;
  if (data instanceof FormData) return `${method}:${url}:formdata`;
  if (
    data instanceof ArrayBuffer ||
    (typeof Buffer !== "undefined" && data instanceof Buffer)
  )
    return `${method}:${url}:binary`;

  const raw = typeof data === "string" ? data : sortedStringify(data);
  const hash = createHash("sha256").update(raw).digest("hex").slice(0, 16);
  return `${method}:${url}:${hash}`;
};

const calculateBackoff = (attempt: number): number =>
  Math.random() * Math.min(10_000, 100 * 2 ** (attempt - 1));

interface NormalizedError {
  status: number;
  name: string;
  message: string;
  retryAfter?: string;
}

const normalizeError = (e: unknown): NormalizedError => {
  if (e instanceof DOMException && e.name === "AbortError")
    return { status: 408, name: "AbortError", message: "Request aborted" };
  if (typeof e === "object" && e !== null) {
    const o = e as Record<string, unknown>;
    return {
      status: typeof o.status === "number" ? o.status : 0,
      name: typeof o.name === "string" ? o.name : "Error",
      message:
        typeof o.msg === "string"
          ? o.msg
          : typeof o.message === "string"
            ? o.message
            : "Unknown error",
      retryAfter: typeof o.retryAfter === "string" ? o.retryAfter : undefined,
    };
  }
  return { status: 0, name: "Error", message: String(e) };
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
  | { ok: false; reason: "parse_error" | "empty" };

const parseResponse = async (res: Response): Promise<ParseResult> => {
  let text: string;
  try {
    text = await res.text();
  } catch {
    return { ok: false, reason: "parse_error" };
  }
  if (!text.trim()) return { ok: false, reason: "empty" };
  if ((res.headers.get("content-type") ?? "").includes("json")) {
    try {
      return { ok: true, data: JSON.parse(text) };
    } catch {
      return { ok: false, reason: "parse_error" };
    }
  }
  return { ok: true, data: text };
};

const extractErrorMessage = (data: unknown, statusText: string): string => {
  if (typeof data === "string") return data;
  if (typeof data === "object" && data !== null) {
    const o = data as Record<string, unknown>;
    if (typeof o.message === "string") return o.message;
    if (typeof o.error === "string") return o.error;
  }
  return statusText;
};

const isRetryableError = (
  status: number,
  attempt: number,
  maxRetries: number,
): boolean => attempt <= maxRetries && RETRY_CODES.has(status);

const parseRetryAfter = (retryAfter: string | undefined): number | null => {
  if (!retryAfter) return null;
  const seconds = Number(retryAfter);
  if (!Number.isNaN(seconds)) return seconds * 1_000;
  const date = new Date(retryAfter).getTime();
  if (!Number.isNaN(date)) return Math.max(0, date - Date.now());
  return null;
};

/* ─── Dev Logger ─────────────────────────────────────────────────────────────── */

const inferType = (v: unknown, d = 0): string => {
  if (d >= 8) return "unknown";
  if (v === null) return "null";
  if (v === undefined) return "undefined";
  if (typeof v !== "object") return typeof v;
  if (Array.isArray(v))
    return v.length ? `(${inferType(v[0], d + 1)})[]` : "unknown[]";
  const entries = Object.entries(v as Record<string, unknown>).slice(0, 10);
  if (!entries.length) return "{}";
  return `{\n${entries.map(([k, val]) => `  ${k}: ${inferType(val, d + 1)}`).join(",\n")}\n}`;
};

const logTypes = (
  ep: string,
  method: string,
  data: unknown,
  meta?: { time: number; att?: number },
): void => {
  const payload =
    typeof data === "object" && data !== null && "data" in data
      ? (data as { data: unknown }).data
      : data;
  console.log(
    `🔍 [SafeFetch] ${method} ${ep} (${meta?.time}ms)${meta?.att ? ` [attempt ${meta.att}]` : ""}\nType: ${inferType(payload)}`,
  );
};

/* ─── Factory ───────────────────────────────────────────────────────────────── */

export interface SafeFetchConfig {
  /** Base URL. Defaults to API_URL / NEXT_PUBLIC_API_URL env var. */
  baseUrl?: string;
  retries?: number;
  timeout?: number;
  maxConcurrent?: number;
  rateMax?: number;
  rateWindow?: number;
  authCacheTtl?: number;
  allowedHosts?: string[];
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
    allowedHosts: instanceConfig.allowedHosts,
  };

  const pool = new Pool(cfg.maxConcurrent);
  const limiter = new RateLimiter(cfg.rateMax);
  const buildUrl = buildUrlFactory();
  const authCache = buildAuthCache(cfg.authCacheTtl);
  const resolveAuthHeaders =
    instanceConfig.getAuthHeaders ?? authCache.getAuthHeaders;

  async function apiRequest<T = unknown>(
    method: HttpMethod,
    endpoint: string,
    opts: RequestOptions<RequestBody, T> = {},
  ): Promise<ApiResponse<T>> {
    if (!HTTP_METHODS.includes(method)) {
      return {
        success: false,
        status: 400,
        error: {
          name: "ValidationError",
          message: "Invalid HTTP method",
          status: 400,
        },
        data: null,
      };
    }

    const { retries = cfg.retries, priority = "normal" } = opts;
    const timeout = opts.timeout ?? cfg.timeout;

    const resolveTimeout = (attempt: number): number => {
      const ms = typeof timeout === "function" ? timeout(attempt) : timeout;
      if (ms <= 0)
        throw new RangeError(`[SafeFetch] timeout must be > 0, got ${ms}`);
      return ms;
    };

    const baseUrl = instanceConfig.baseUrl ?? getEnv()?.API_URL ?? "";
    const url = buildUrl(endpoint, baseUrl, opts.params, cfg.allowedHosts);
    const key =
      opts.dedupeKey !== undefined
        ? opts.dedupeKey
        : buildDedupeKey(method, url, opts.data);
    const start = performance.now();

    return pool.exec(
      async () => {
        let attempt = 0;

        // eslint-disable-next-line no-constant-condition
        while (true) {
          attempt++;
          await limiter.check(cfg.rateMax, cfg.rateWindow);

          const ctrl = new AbortController();
          const timeoutDuration = resolveTimeout(attempt);
          const timeoutId = setTimeout(() => ctrl.abort(), timeoutDuration);
          const composedSignal = opts.signal
            ? composeSignals(opts.signal, ctrl.signal)
            : ctrl.signal;

          try {
            const requestId =
              typeof crypto !== "undefined" &&
              typeof crypto.randomUUID === "function"
                ? crypto.randomUUID()
                : `${Date.now()}-${Math.random().toString(36).slice(2)}`;

            const headers: Record<string, string> = {
              Accept: "application/json",
              ...opts.headers,
              "X-Request-Id": requestId,
              ...(!opts.skipAuth ? resolveAuthHeaders() : {}),
            };

            if (opts.data && !(opts.data instanceof FormData)) {
              headers["Content-Type"] = "application/json";
            }

            const body = opts.data
              ? opts.data instanceof FormData ||
                opts.data instanceof ArrayBuffer ||
                (typeof Buffer !== "undefined" && opts.data instanceof Buffer)
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

            // FIX #15 (auth cache) — automatically invalidate the auth cache on
            // 401 so the next retry picks up fresh credentials rather than
            // replaying a stale token for the full cacheTtl window.
            if (res.status === 401) {
              authCache.invalidateAuthCache();
            }

            const parsed = await parseResponse(res);
            const rawData: unknown = parsed.ok ? parsed.data : null;

            if (!res.ok) {
              const message = parsed.ok
                ? extractErrorMessage(rawData, res.statusText)
                : res.statusText;

              const retryAfter = res.headers.get("Retry-After") ?? undefined;
              throw { status: res.status, msg: message, retryAfter };
            }

            if (!parsed.ok) {
              return {
                success: false as const,
                status: res.status,
                error: {
                  name: "ParseError",
                  message: `Response body could not be parsed (${parsed.reason})`,
                  status: res.status,
                  retryable: false,
                  url,
                  method,
                },
                data: null,
              };
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

            let transformed: T;
            try {
              transformed = opts.transform
                ? opts.transform(rawData as T)
                : (rawData as T);
            } catch (transformErr) {
              return {
                success: false as const,
                status: res.status,
                error: {
                  name: "TransformError",
                  message:
                    transformErr instanceof Error
                      ? transformErr.message
                      : "transform() threw an unexpected error",
                  status: res.status,
                  retryable: false,
                  url,
                  method,
                },
                data: null,
              };
            }

            if (opts.schema) {
              const result = opts.schema.safeParse(transformed);
              if (!result.success) {
                return {
                  success: false as const,
                  status: res.status,
                  error: {
                    name: "ValidationError",
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
            const normalized = normalizeError(e);
            if (!isRetryableError(normalized.status, attempt, retries))
              return createErrorResponse(e, url, method, false);

            const retryAfterMs = parseRetryAfter(normalized.retryAfter);
            const backoff =
              retryAfterMs !== null ? retryAfterMs : calculateBackoff(attempt);
            await new Promise<void>((r) => setTimeout(r, backoff));
          }
        }
      },
      priority,
      key,
    );
  }

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
      runtime: IS_BUN ? "bun" : "node",
    }),
    sanitizeHeaders: (h: Record<string, string>): Record<string, string> => {
      const s = { ...h };
      for (const k of ["Authorization", "X-API-Key", "Cookie"])
        if (s[k]) s[k] = "[REDACTED]";
      return s;
    },
  };

  const api = {
    get<T>(endpoint: string, opts?: BodylessOptions<T>) {
      return apiRequest<T>(
        "GET",
        endpoint,
        opts as RequestOptions<RequestBody, T>,
      );
    },
    post<T>(endpoint: string, opts?: RequestOptions<RequestBody, T>) {
      return apiRequest<T>("POST", endpoint, opts);
    },
    put<T>(endpoint: string, opts?: RequestOptions<RequestBody, T>) {
      return apiRequest<T>("PUT", endpoint, opts);
    },
    patch<T>(endpoint: string, opts?: RequestOptions<RequestBody, T>) {
      return apiRequest<T>("PATCH", endpoint, opts);
    },
    delete<T>(endpoint: string, opts?: BodylessOptions<T>) {
      return apiRequest<T>(
        "DELETE",
        endpoint,
        opts as RequestOptions<RequestBody, T>,
      );
    },
  } as const;

  return {
    apiRequest,
    api,
    invalidateAuthCache: authCache.invalidateAuthCache,
  };
}

/* ─── Default Singleton ──────────────────────────────────────────────────────── */
export const { apiRequest, api, invalidateAuthCache } = createSafeFetch();
export default apiRequest;
