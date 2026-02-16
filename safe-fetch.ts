/**
 * SafeFetch – Typed Fetch Utility for Next.js 16
 * (c) 2026 Bharathi4real – BSD 3-Clause License
 *
 * Architecture:
 *  - Environment Resolver
 *  - Auth Provider (TTL cached)
 *  - URL Builder (LRU cache)
 *  - Rate Limiter
 *  - Concurrency Pool (Priority + Stable Dedupe)
 *  - Retry Engine (Jittered Exponential Backoff)
 *  - Typed Endpoint Factory
 */

"use server";

import { createHash } from "node:crypto";

/* ======================================================
 * SECTION: Public Types
 * ====================================================== */

const HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"] as const;
export type HttpMethod = (typeof HTTP_METHODS)[number];

export type RequestBody = Record<string, unknown> | FormData | string | Blob | ArrayBuffer | URLSearchParams | null;

export type QueryParams = Record<string, string | number | boolean | null | undefined>;

export interface RequestOptions<TBody extends RequestBody = RequestBody, TRes = unknown> {
  data?: TBody;
  params?: QueryParams;
  retries?: number;
  timeout?: number | ((attempt: number) => number);
  headers?: Record<string, string>;
  transform?(data: TRes): TRes;
  priority?: "high" | "normal" | "low";
  signal?: AbortSignal;
  logTypes?: boolean;
  cache?: RequestCache;
  next?: { revalidate?: number | false; tags?: string[] };
  dedupeKey?: string | null;
  pathParams?: Record<string, string | number>;
}

export type ApiResponse<T = unknown> =
  | {
      success: true;
      status: number;
      data: T;
      headers: Record<string, string>;
    }
  | {
      success: false;
      status: number;
      error: ApiError;
      data: null;
    };

export interface ApiError {
  readonly name: string;
  readonly message: string;
  readonly status: number;
  readonly retryable?: boolean;
  readonly url?: string;
  readonly method?: string;
}

/* ======================================================
 * SECTION: Runtime Configuration
 * ====================================================== */

const IS_BUN = typeof globalThis !== "undefined" && "Bun" in globalThis;

const RETRYABLE_STATUS_CODES = new Set([408, 429, 500, 502, 503, 504]);

const PRIORITY_WEIGHT = {
  high: 3,
  normal: 2,
  low: 1,
} as const;

const RUNTIME_ENV = (() => {
  const env = process.env ?? {};
  return {
    API_URL: env.NEXT_PUBLIC_API_URL || env.BASE_URL || env.API_URL || "",
    AUTH_USERNAME: env.AUTH_USERNAME || env.API_USERNAME || "",
    AUTH_PASSWORD: env.AUTH_PASSWORD || env.API_PASSWORD || "",
    API_TOKEN: env.AUTH_TOKEN || env.API_TOKEN || "",
    NODE_ENV: env.NODE_ENV || "development",
  };
})();

const DEFAULT_CONFIG = {
  retries: 2,
  timeout: 60_000,
  maxConcurrent: IS_BUN ? 20 : 10,
  rateMax: 100,
  rateWindow: 60_000,
  authCacheTTL: 300_000,
} as const;

/* ======================================================
 * SECTION: Pure Utility Functions
 * ====================================================== */

function stableHash(input: unknown): string {
  if (!input || typeof input !== "object") {
    return createHash("sha1").update(String(input)).digest("hex");
  }

  const sorted = Object.keys(input as object)
    .sort()
    .reduce<Record<string, unknown>>((acc, key) => {
      acc[key] = (input as Record<string, unknown>)[key];
      return acc;
    }, {});

  return createHash("sha1").update(JSON.stringify(sorted)).digest("hex");
}

function interpolatePath(path: string, params?: Record<string, string | number>): string {
  if (!params) return path;

  return path.replace(/:([a-zA-Z0-9_]+)/g, (_, key) => encodeURIComponent(String(params[key])));
}

function exponentialBackoff(attempt: number): number {
  const maxDelay = Math.min(10_000, 100 * 2 ** (attempt - 1));
  return maxDelay / 2 + Math.random() * (maxDelay / 2);
}

function inferType(value: unknown, depth = 0): string {
  if (depth > 5) return "unknown";
  if (value === null) return "null";
  if (value === undefined) return "undefined";
  if (typeof value !== "object") return typeof value;

  if (Array.isArray(value)) {
    return value.length ? `(${inferType(value[0], depth + 1)})[]` : "unknown[]";
  }

  const entries = Object.entries(value).slice(0, 5);

  if (!entries.length) return "{}";

  return `{\n${entries.map(([key, val]) => `  ${key}: ${inferType(val, depth + 1)}`).join(",\n")}\n}`;
}

function devLogTypes(endpoint: string, method: string, data: unknown, duration: number, attempt?: number) {
  if (RUNTIME_ENV.NODE_ENV !== "development") return;

  console.log(
    `🔍 [SafeFetch] ${method} ${endpoint} (${duration}ms)${
      attempt ? ` [attempt ${attempt}]` : ""
    }\nType: ${inferType(data)}`,
  );
}

/* ======================================================
 * SECTION: Infrastructure Layer
 * ====================================================== */

/* ---------- Auth Provider (TTL Cached) ---------- */

const AuthProvider = (() => {
  let cachedHeaders: Record<string, string> | null = null;
  let lastResolved = 0;

  return {
    get(): Record<string, string> {
      const now = Date.now();

      if (cachedHeaders && now - lastResolved < DEFAULT_CONFIG.authCacheTTL) {
        return cachedHeaders;
      }

      const headers: Record<string, string> = {};

      if (RUNTIME_ENV.AUTH_USERNAME && RUNTIME_ENV.AUTH_PASSWORD) {
        headers.Authorization = `Basic ${Buffer.from(
          `${RUNTIME_ENV.AUTH_USERNAME}:${RUNTIME_ENV.AUTH_PASSWORD}`,
        ).toString("base64")}`;
      } else if (RUNTIME_ENV.API_TOKEN) {
        headers.Authorization = `Bearer ${RUNTIME_ENV.API_TOKEN}`;
      }

      cachedHeaders = headers;
      lastResolved = now;

      return headers;
    },
  };
})();

/* ---------- URL Builder (LRU Cache) ---------- */

const UrlBuilder = (() => {
  const cache = new Map<string, string>();
  const MAX_CACHE_SIZE = 100;

  function evictIfNeeded() {
    if (cache.size >= MAX_CACHE_SIZE) {
      const firstKey = cache.keys().next().value;
      if (firstKey) cache.delete(firstKey);
    }
  }

  return {
    build(endpoint: string, params?: QueryParams): string {
      const key = endpoint + JSON.stringify(params ?? {});

      const cached = cache.get(key);
      if (cached) return cached;

      const base = RUNTIME_ENV.API_URL || (typeof window !== "undefined" ? window.location.origin : "");

      let url = /^https?:\/\//i.test(endpoint)
        ? endpoint
        : `${base.replace(/\/+$/, "")}/${endpoint.replace(/^\/+/, "")}`;

      if (params) {
        const qs = new URLSearchParams();

        for (const [k, v] of Object.entries(params)) {
          if (v != null) qs.append(k, String(v));
        }

        const queryString = qs.toString();
        if (queryString) url += `?${queryString}`;
      }

      evictIfNeeded();
      cache.set(key, url);

      return url;
    },
  };
})();

/* ---------- Rate Limiter ---------- */

class RateLimiter {
  private timestamps: number[] = [];

  async check(max = DEFAULT_CONFIG.rateMax, windowMs = DEFAULT_CONFIG.rateWindow) {
    while (true) {
      const now = Date.now();

      this.timestamps = this.timestamps.filter((ts) => now - ts < windowMs);

      if (this.timestamps.length < max) {
        this.timestamps.push(now);
        return;
      }

      const waitTime = windowMs - (now - this.timestamps[0]);

      await new Promise((r) => setTimeout(r, waitTime));
    }
  }

  stats() {
    return { current: this.timestamps.length };
  }
}

/* ---------- Concurrency Pool ---------- */

class ConcurrencyPool {
  private activeCount = 0;
  private queue: {
    run: () => void;
    priority: number;
  }[] = [];
  private pendingMap = new Map<string, Promise<unknown>>();

  constructor(private maxConcurrent = DEFAULT_CONFIG.maxConcurrent) {}

  async execute<T>(fn: () => Promise<T>, priority: "high" | "normal" | "low", dedupeKey?: string | null): Promise<T> {
    if (dedupeKey && this.pendingMap.has(dedupeKey)) {
      return this.pendingMap.get(dedupeKey) as Promise<T>;
    }

    let resolve!: (value: T | PromiseLike<T>) => void;
    let reject!: (reason?: unknown) => void;

    const task = new Promise<T>((res, rej) => {
      resolve = res;
      reject = rej;
    });

    if (dedupeKey) {
      this.pendingMap.set(dedupeKey, task);
    }

    const runTask = async () => {
      this.activeCount++;
      try {
        resolve(await fn());
      } catch (err) {
        reject(err);
      } finally {
        this.activeCount--;
        if (dedupeKey) this.pendingMap.delete(dedupeKey);
        this.processNext();
      }
    };

    if (this.activeCount < this.maxConcurrent) {
      runTask();
    } else {
      this.queue.push({
        run: runTask,
        priority: PRIORITY_WEIGHT[priority],
      });

      this.queue.sort((a, b) => b.priority - a.priority);
    }

    return task;
  }

  private processNext() {
    if (this.queue.length && this.activeCount < this.maxConcurrent) {
      this.queue.shift()?.run();
    }
  }

  stats() {
    return {
      active: this.activeCount,
      queued: this.queue.length,
    };
  }
}

const rateLimiter = new RateLimiter();
const concurrencyPool = new ConcurrencyPool();

/* ======================================================
 * SECTION: Core Execution Engine
 * ====================================================== */

function buildHeaders(body: RequestBody, custom?: Record<string, string>) {
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...AuthProvider.get(),
    ...custom,
  };

  if (
    body &&
    typeof body === "object" &&
    !(
      body instanceof FormData ||
      body instanceof Blob ||
      body instanceof ArrayBuffer ||
      body instanceof URLSearchParams
    )
  ) {
    headers["Content-Type"] = "application/json";
  }

  return headers;
}

function serializeBody(body: RequestBody) {
  if (!body) return undefined;

  if (
    body instanceof FormData ||
    body instanceof Blob ||
    body instanceof ArrayBuffer ||
    body instanceof URLSearchParams
  ) {
    return body;
  }

  if (typeof body === "string") return body;

  return JSON.stringify(body);
}

async function executeWithRetry<T>(
  method: HttpMethod,
  url: string,
  options: RequestOptions<RequestBody, T>,
): Promise<ApiResponse<T>> {
  const maxAttempts = (options.retries ?? DEFAULT_CONFIG.retries) + 1;

  const startTime = performance.now();

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    await rateLimiter.check();

    const controller = new AbortController();

    const timeoutMs =
      typeof options.timeout === "function" ? options.timeout(attempt) : (options.timeout ?? DEFAULT_CONFIG.timeout);

    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    const combinedSignal = options.signal ? AbortSignal.any([options.signal, controller.signal]) : controller.signal;

    try {
      const response = await fetch(url, {
        method,
        headers: buildHeaders(options.data ?? null, options.headers),
        body: serializeBody(options.data ?? null),
        signal: combinedSignal,
        cache: options.cache,
        next: options.next,
      });

      clearTimeout(timeoutId);

      const data = response.headers.get("content-type")?.includes("json")
        ? await response.json()
        : await response.text();

      if (!response.ok) {
        throw {
          status: response.status,
          message: response.statusText,
        };
      }

      let finalData = data as T;

      if (options.transform) {
        finalData = options.transform(finalData);
      }

      if (options.logTypes) {
        devLogTypes(
          url,
          method,
          finalData,
          Math.round(performance.now() - startTime),
          attempt > 1 ? attempt : undefined,
        );
      }

      const headers: Record<string, string> = {};

      response.headers.forEach((v, k) => {
        headers[k] = v;
      });

      return {
        success: true,
        status: response.status,
        data: finalData,
        headers,
      };
    } catch (error: unknown) {
      clearTimeout(timeoutId);

      const status = (error as { status?: number })?.status ?? 0;

      const retryable = RETRYABLE_STATUS_CODES.has(status);

      if (attempt === maxAttempts || !retryable) {
        return {
          success: false,
          status,
          error: {
            name: (error as { name?: string })?.name || "Error",
            message: (error as { message?: string })?.message || "Request failed",
            status,
            retryable,
            url,
            method,
          },
          data: null,
        };
      }

      await new Promise((r) => setTimeout(r, exponentialBackoff(attempt)));
    }
  }

  throw new Error("Unreachable retry state");
}

/* ======================================================
 * SECTION: Public API
 * ====================================================== */

export default async function apiRequest<T = unknown>(
  method: HttpMethod,
  endpoint: string,
  options: RequestOptions<RequestBody, T> = {},
): Promise<ApiResponse<T>> {
  const resolvedPath = interpolatePath(endpoint, options.pathParams);

  const url = UrlBuilder.build(resolvedPath, options.params);

  const dedupeKey = options.dedupeKey ?? `${method}:${url}:${options.data ? stableHash(options.data) : ""}`;

  return concurrencyPool.execute(
    () => executeWithRetry<T>(method, url, options),
    options.priority ?? "normal",
    dedupeKey,
  );
}

/* ======================================================
 * SECTION: Endpoint Factory
 * ====================================================== */

export async function createEndpoint<
  TMethod extends HttpMethod,
  TPath extends string,
  TBody extends RequestBody = null,
  TRes = unknown,
>(config: { method: TMethod; path: TPath; defaults?: Partial<RequestOptions<TBody, TRes>> }) {
  return async (body?: TBody, options?: Omit<RequestOptions<TBody, TRes>, "data">): Promise<ApiResponse<TRes>> =>
    apiRequest<TRes>(config.method, config.path, {
      ...config.defaults,
      ...options,
      data: body ?? null,
    });
}

/* ======================================================
 * SECTION: Guards & Utilities
 * ====================================================== */

apiRequest.isSuccess = <T>(response: ApiResponse<T>): response is Extract<ApiResponse<T>, { success: true }> =>
  response.success;

apiRequest.isError = <T>(response: ApiResponse<T>): response is Extract<ApiResponse<T>, { success: false }> =>
  !response.success;

apiRequest.utils = {
  getStats: () => ({
    pool: concurrencyPool.stats(),
    rateLimit: rateLimiter.stats(),
    runtime: IS_BUN ? "bun" : "node",
  }),
  sanitizeHeaders: (headers: Record<string, string>) => {
    const copy = { ...headers };
    ["Authorization", "Cookie", "X-API-Key"].forEach((key) => {
      if (copy[key]) copy[key] = "[REDACTED]";
    });
    return copy;
  },
};
