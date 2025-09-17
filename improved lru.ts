/**
 * SafeFetch – Optimized Typed Fetch utility for Next.js 15
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * Memory-optimized with unified cache, coalescing & adaptive pooling
 */

'use server';

import { revalidatePath, revalidateTag, unstable_cache } from 'next/cache';

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] as const;

export type HttpMethod = (typeof HTTP_METHODS)[number];
export type RequestBody = Record<string, unknown> | FormData | string | null;
export type QueryParams = Record<string, string | number | boolean | null | undefined>;

export interface RequestOptions<TBody extends RequestBody = RequestBody, TResponse = unknown> {
  data?: TBody;
  params?: QueryParams;
  retries?: number;
  timeout?: number | ((attempt: number) => number);
  cache?: RequestCache;
  next?: { revalidate?: number | false; tags?: string[] };
  headers?: Record<string, string>;
  transform?<T = TResponse, R = TResponse>(data: T): R;
  priority?: 'high' | 'normal' | 'low';
  signal?: AbortSignal;
  batch?: boolean;
}

export interface ApiError {
  readonly name: string;
  readonly message: string;
  readonly status: number;
  readonly retryable?: boolean;
}

export type ApiResponse<T = unknown> =
  | { success: true; status: number; data: T; headers: Headers }
  | { success: false; status: number; error: ApiError; data: null };

// -------------------- Configuration --------------------
const CONFIG = {
  API_URL: process.env.NEXT_PUBLIC_API_URL ?? process.env.BASE_URL ?? '',
  RETRY_CODES: new Set([408, 429, 500, 502, 503, 504]),
  IDEMPOTENT_METHODS: new Set<HttpMethod>(['GET', 'PUT', 'DELETE']),
  DEFAULT_TIMEOUT: 60000,
  DEFAULT_RETRIES: 2,
  MAX_CONCURRENT: 10,
  CACHE_SIZE: 100,
  TTL_MS: 300_000,
  BATCH_SIZE: 10,
  BATCH_DELAY: 50,
} as const;

// -------------------- Unified Cache --------------------
interface CacheEntry<T> {
  value: T;
  timestamp: number;
  hits: number;
}

class Cache<K, V> {
  private cache = new Map<K, CacheEntry<V>>();
  private lastCleanup = Date.now();

  constructor(
    private maxSize: number,
    private ttl = CONFIG.TTL_MS,
  ) {}

  get(key: K): V | undefined {
    this.cleanup();
    const entry = this.cache.get(key);
    if (!entry || Date.now() - entry.timestamp > this.ttl) {
      this.cache.delete(key);
      return undefined;
    }
    entry.hits++;
    return entry.value;
  }

  set(key: K, value: V): void {
    // LRU eviction
    while (this.cache.size >= this.maxSize) {
      const [lruKey] = [...this.cache.entries()].sort(([, a], [, b]) => a.hits - b.hits)[0];
      this.cache.delete(lruKey);
    }
    this.cache.set(key, { value, timestamp: Date.now(), hits: 1 });
  }

  clear(): void {
    this.cache.clear();
  }

  size(): number {
    return this.cache.size;
  }

  private cleanup(): void {
    if (Date.now() - this.lastCleanup < 60000) return;
    this.lastCleanup = Date.now();
    const cutoff = Date.now() - this.ttl;
    for (const [key, entry] of this.cache) {
      if (entry.timestamp < cutoff) this.cache.delete(key);
    }
  }
}

// -------------------- Request Coalescing --------------------
interface BatchRequest {
  resolve: (value: ApiResponse<unknown>) => void;
  reject: (reason?: unknown) => void;
}

interface Batch {
  requests: Array<BatchRequest>;
  timer?: NodeJS.Timeout;
}

class Coalescer {
  private pending = new Map<string, Promise<ApiResponse<unknown>>>();
  private batches = new Map<string, Batch>();

  async coalesce<T>(
    key: string,
    factory: () => Promise<ApiResponse<T>>,
    batch = false,
  ): Promise<ApiResponse<T>> {
    if (!batch) {
      const existing = this.pending.get(key);
      if (existing) return existing as Promise<ApiResponse<T>>;

      const promise = factory().finally(() => this.pending.delete(key));
      this.pending.set(key, promise);
      return promise;
    }

    const batchKey = key.split(':')[0];
    return new Promise<ApiResponse<T>>((resolve, reject) => {
      let batch = this.batches.get(batchKey);
      if (!batch) {
        batch = { requests: [] };
        this.batches.set(batchKey, batch);
      }

      batch.requests.push({
        resolve: resolve as (value: ApiResponse<unknown>) => void,
        reject,
      });

      if (batch.requests.length >= CONFIG.BATCH_SIZE) {
        this.executeBatch(batchKey, factory);
      } else if (!batch.timer) {
        batch.timer = setTimeout(() => this.executeBatch(batchKey, factory), CONFIG.BATCH_DELAY);
      }
    });
  }

  private async executeBatch<T>(
    batchKey: string,
    factory: () => Promise<ApiResponse<T>>,
  ): Promise<void> {
    const batch = this.batches.get(batchKey);
    if (!batch) return;

    this.batches.delete(batchKey);
    if (batch.timer) clearTimeout(batch.timer);

    try {
      const result = await factory();
      // Use for-of loop instead of forEach to avoid linting issues
      for (const request of batch.requests) {
        request.resolve(result as ApiResponse<unknown>);
      }
    } catch (error) {
      // Use for-of loop instead of forEach to avoid linting issues
      for (const request of batch.requests) {
        request.reject(error);
      }
    }
  }
}

// -------------------- Adaptive Pool --------------------
interface QueuedTask<T> {
  fn: () => Promise<T>;
  resolve: (value: T) => void;
  reject: (reason?: unknown) => void;
  priority: number;
}

class Pool {
  private queue: Array<QueuedTask<unknown>> = [];
  private active = 0;
  private maxConcurrent = CONFIG.MAX_CONCURRENT;

  async execute<T>(
    fn: () => Promise<T>,
    priority: 'high' | 'normal' | 'low' = 'normal',
  ): Promise<T> {
    const priorityNum = { high: 3, normal: 2, low: 1 }[priority];

    if (this.active < this.maxConcurrent) {
      return this.run(fn);
    }

    return new Promise<T>((resolve, reject) => {
      this.queue.push({
        fn: fn as () => Promise<unknown>,
        resolve: resolve as (value: unknown) => void,
        reject,
        priority: priorityNum,
      });
      this.queue.sort((a, b) => b.priority - a.priority);
    });
  }

  private async run<T>(fn: () => Promise<T>): Promise<T> {
    this.active++;
    try {
      return await fn();
    } finally {
      this.active--;
      this.processQueue();
    }
  }

  private processQueue(): void {
    if (this.queue.length === 0 || this.active >= this.maxConcurrent) return;
    const task = this.queue.shift();
    if (!task) return;

    this.run(task.fn as () => Promise<unknown>)
      .then(task.resolve)
      .catch(task.reject);
  }

  getStats() {
    return {
      active: this.active,
      queued: this.queue.length,
      maxConcurrent: this.maxConcurrent,
    };
  }
}

// -------------------- Global Instances --------------------
const cache = new Cache<string, ApiResponse<unknown>>(CONFIG.CACHE_SIZE);
const urlCache = new Cache<string, string>(50);
const coalescer = new Coalescer();
const pool = new Pool();

// -------------------- Utilities --------------------
const buildUrl = (endpoint: string, params?: QueryParams): string => {
  const paramStr = params
    ? Object.entries(params)
        .filter(([, v]) => v != null)
        .map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`)
        .join('&')
    : '';

  const cacheKey = `${endpoint}|${paramStr}`;
  const cached = urlCache.get(cacheKey);
  if (cached) return cached;

  const isAbsolute = /^https?:\/\//.test(endpoint);
  const base = isAbsolute ? endpoint : `${CONFIG.API_URL}/${endpoint.replace(/^\//, '')}`;
  const url = paramStr ? `${base}?${paramStr}` : base;
  urlCache.set(cacheKey, url);
  return url;
};

const getAuthHeaders = (() => {
  let cached: Record<string, string> | null = null;
  let lastCheck = 0;

  return (): Record<string, string> => {
    if (cached && Date.now() - lastCheck < CONFIG.TTL_MS) return cached;

    const headers: Record<string, string> = {};
    const { AUTH_USERNAME: user, AUTH_PASSWORD: pass, API_TOKEN: token } = process.env;

    if (user && pass) {
      headers.Authorization = `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`;
    } else if (token) {
      headers.Authorization = `Bearer ${token}`;
    }

    cached = headers;
    lastCheck = Date.now();
    return headers;
  };
})();

const createError = (
  name: string,
  message: string,
  status: number,
  retryable = false,
): ApiError => ({ name, message, status, retryable });

// -------------------- Core Request Logic --------------------
interface RequestConfig {
  body?: BodyInit;
  headers: Record<string, string>;
  cache: RequestCache;
  timeout: number;
  next?: { revalidate?: number | false; tags?: string[] };
  signal?: AbortSignal;
}

const executeRequest = async <T>(
  method: HttpMethod,
  url: string,
  options: RequestConfig,
): Promise<ApiResponse<T>> => {
  const controller = new AbortController();
  const signal = options.signal
    ? (() => {
        const combined = new AbortController();
        const signals = [options.signal, controller.signal].filter(Boolean);
        for (const s of signals) {
          s.addEventListener('abort', () => combined.abort());
        }
        return combined.signal;
      })()
    : controller.signal;

  const timeoutId = setTimeout(() => controller.abort(), options.timeout);

  try {
    const fetchOptions: RequestInit = {
      method,
      headers: options.headers,
      body: options.body,
      cache: options.cache,
      signal,
    };

    if (options.next) {
      (fetchOptions as RequestInit & { next?: unknown }).next = options.next;
    }

    const response = await fetch(url, fetchOptions);
    clearTimeout(timeoutId);

    const isJson = response.headers.get('content-type')?.includes('application/json');
    const data = isJson ? await response.json() : await response.text();

    if (response.ok) {
      return {
        success: true,
        status: response.status,
        data: data as T,
        headers: response.headers,
      };
    }

    const message =
      typeof data === 'object' && data && 'message' in data && typeof data.message === 'string'
        ? data.message
        : typeof data === 'string'
          ? data
          : `HTTP ${response.status}`;

    return {
      success: false,
      status: response.status,
      error: createError(
        'HttpError',
        message,
        response.status,
        CONFIG.RETRY_CODES.has(response.status),
      ),
      data: null,
    };
  } catch (err) {
    clearTimeout(timeoutId);
    const isTimeout = err instanceof Error && /abort|timeout/i.test(err.message);

    return {
      success: false,
      status: isTimeout ? 408 : 0,
      error: createError(
        isTimeout ? 'TimeoutError' : 'NetworkError',
        err instanceof Error ? err.message : 'Request failed',
        isTimeout ? 408 : 0,
        true,
      ),
      data: null,
    };
  }
};

// -------------------- Main API Function --------------------
export default async function apiRequest<
  TResponse = unknown,
  TBody extends RequestBody = RequestBody,
>(
  method: HttpMethod,
  endpoint: string,
  options: RequestOptions<TBody, TResponse> = {},
): Promise<ApiResponse<TResponse>> {
  if (!HTTP_METHODS.includes(method)) {
    return {
      success: false,
      status: 400,
      error: createError('ValidationError', `Invalid method: ${method}`, 400),
      data: null,
    };
  }

  const {
    data,
    params,
    retries = CONFIG.DEFAULT_RETRIES,
    timeout = CONFIG.DEFAULT_TIMEOUT,
    cache: cachePolicy = 'default',
    next: nextOptions,
    headers: customHeaders,
    transform,
    priority = 'normal',
    signal,
    batch = false,
  } = options;

  const url = buildUrl(endpoint, params);
  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...getAuthHeaders(),
    ...customHeaders,
  };

  if (data && !(data instanceof FormData) && typeof data !== 'string') {
    headers['Content-Type'] = 'application/json';
  }

  const body =
    data instanceof FormData || typeof data === 'string'
      ? (data as BodyInit)
      : data
        ? JSON.stringify(data)
        : undefined;

  const cacheKey = `${method}:${url}:${body ? 'with-body' : 'no-body'}`;

  // Check cache for GET requests
  if (method === 'GET' && cachePolicy !== 'no-store') {
    const cached = cache.get(cacheKey);
    if (cached) return cached as ApiResponse<TResponse>;
  }

  const requestFactory = () =>
    pool.execute(async () => {
      let attempt = 0;

      while (true) {
        attempt++;
        const timeoutValue = typeof timeout === 'function' ? timeout(attempt) : timeout;

        const result = await executeRequest<TResponse>(method, url, {
          body,
          headers,
          cache: cachePolicy,
          timeout: timeoutValue,
          next: nextOptions,
          signal,
        });

        if (result.success) {
          // Cache successful GET requests
          if (method === 'GET' && cachePolicy !== 'no-store') {
            cache.set(cacheKey, result);
          }
          return transform ? { ...result, data: transform(result.data) } : result;
        }

        const shouldRetry =
          attempt < retries &&
          CONFIG.IDEMPOTENT_METHODS.has(method) &&
          (result.error.retryable || CONFIG.RETRY_CODES.has(result.error.status));

        if (!shouldRetry) return result;

        // Exponential backoff with jitter
        const delay = Math.min(1000, 100 * 2 ** (attempt - 1)) + Math.random() * 100;
        await new Promise<void>((resolve) => setTimeout(resolve, delay));
      }
    }, priority);

  return coalescer.coalesce(cacheKey, requestFactory, batch);
}

// -------------------- Utility Methods --------------------
apiRequest.isSuccess = <T>(
  response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: true }> => response.success;

apiRequest.isError = <T>(
  response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: false }> => !response.success;

apiRequest.utils = {
  getStats: () => ({
    pool: pool.getStats(),
    cache: cache.size(),
    urls: urlCache.size(),
  }),
  clearCaches: () => {
    cache.clear();
    urlCache.clear();
  },
  batch: <T>(requests: Array<() => Promise<ApiResponse<T>>>): Promise<Array<ApiResponse<T>>> =>
    Promise.all(requests.slice(0, CONFIG.BATCH_SIZE).map((req) => req())),
  timeout: (ms: number) => {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), ms);
    return controller.signal;
  },
};

// -------------------- Next.js 15 Cache Helpers --------------------
apiRequest.cacheHelpers = {
  revalidateTag,
  revalidatePath,
  cached: <TResponse = unknown, TBody extends RequestBody = RequestBody>(
    key: string,
    revalidateSeconds = 3600,
    tags: string[] = [],
  ) =>
    unstable_cache(
      (method: HttpMethod, endpoint: string, options: RequestOptions<TBody, TResponse> = {}) =>
        apiRequest<TResponse, TBody>(method, endpoint, options),
      [key],
      { revalidate: revalidateSeconds, tags },
    ),
};
