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
  logTypes?: boolean;
}

export interface ApiError {
  readonly name: string;
  readonly message: string;
  readonly status: number;
  readonly retryable?: boolean;
}

export type ApiResponse<T = unknown> =
  | { success: true; status: number; data: T; headers: Record<string, string> }
  | { success: false; status: number; error: ApiError; data: null };

// -------------------- Runtime Detection --------------------
const IS_BUN = typeof globalThis !== 'undefined' && 'Bun' in globalThis;
const IS_NODE = !IS_BUN && typeof process !== 'undefined';

// -------------------- Configuration --------------------
const CONFIG = {
  API_URL: process.env.NEXT_PUBLIC_API_URL ?? process.env.BASE_URL ?? '',
  RETRY_CODES: new Set([408, 429, 500, 502, 503, 504]),
  IDEMPOTENT_METHODS: new Set<HttpMethod>(['GET', 'PUT', 'DELETE']),
  DEFAULT_TIMEOUT: 60000,
  DEFAULT_RETRIES: 2,
  MAX_CONCURRENT: IS_BUN ? 20 : 10, // Bun handles concurrency better
  CACHE_SIZE: 100,
  TTL_MS: 300_000,
  BATCH_SIZE: IS_BUN ? 20 : 10,
  BATCH_DELAY: IS_BUN ? 25 : 50,
  CLEANUP_INTERVAL: 60000,
  EVICTION_RATIO: 0.15, // Remove 15% at once
  IS_DEV: process.env.NODE_ENV === 'development',
} as const;

// -------------------- Fast Hash Function --------------------
const fastHash = (str: string): number => {
  let hash = 0;
  for (let i = 0, len = str.length; i < len; i++) {
    hash = ((hash << 5) - hash + str.charCodeAt(i)) | 0;
  }
  return hash >>> 0;
};

// -------------------- Unified Cache --------------------
class Cache<K, V> {
  private readonly cache = new Map<K, { value: V; timestamp: number; hits: number }>();
  private lastCleanup = Date.now();
  private evictionList: K[] = [];
  private needsSort = false;

  constructor(
    private readonly maxSize: number,
    private readonly ttl = CONFIG.TTL_MS,
  ) {}

  get(key: K): V | undefined {
    if (this.needsCleanup()) this.cleanup();

    const entry = this.cache.get(key);
    if (!entry) return undefined;

    const now = Date.now();
    if (now - entry.timestamp > this.ttl) {
      this.cache.delete(key);
      return undefined;
    }

    entry.hits++;
    return entry.value;
  }

  set(key: K, value: V): void {
    const size = this.cache.size;

    if (size >= this.maxSize) {
      // Fast eviction without creating new arrays
      if (!this.evictionList.length || this.needsSort) {
        this.evictionList = Array.from(this.cache.keys());
        this.evictionList.sort((a, b) => {
          const entryA = this.cache.get(a)!;
          const entryB = this.cache.get(b)!;
          return entryA.hits - entryB.hits;
        });
        this.needsSort = false;
      }

      const toRemove = Math.ceil(this.maxSize * CONFIG.EVICTION_RATIO);
      for (let i = 0; i < toRemove; i++) {
        const key = this.evictionList[i];
        if (key) this.cache.delete(key);
      }
      this.evictionList = [];
      this.needsSort = true;
    }

    this.cache.set(key, { value, timestamp: Date.now(), hits: 1 });
  }

  clear(): void {
    this.cache.clear();
    this.evictionList = [];
  }

  size(): number {
    return this.cache.size;
  }

  private needsCleanup(): boolean {
    return Date.now() - this.lastCleanup >= CONFIG.CLEANUP_INTERVAL;
  }

  private cleanup(): void {
    this.lastCleanup = Date.now();
    const cutoff = this.lastCleanup - this.ttl;

    for (const [key, entry] of this.cache) {
      if (entry.timestamp < cutoff) this.cache.delete(key);
    }
  }
}

// -------------------- Request Coalescing --------------------
class Coalescer {
  private readonly pending = new Map<string, Promise<ApiResponse<unknown>>>();
  private readonly batches = new Map<
    string,
    {
      requests: Array<{
        resolve: (value: ApiResponse<unknown>) => void;
        reject: (reason?: unknown) => void;
      }>;
      timer?: NodeJS.Timeout;
    }
  >();

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
      let batchData = this.batches.get(batchKey);
      if (!batchData) {
        batchData = { requests: [] };
        this.batches.set(batchKey, batchData);
      }

      batchData.requests.push({
        resolve: resolve as (value: ApiResponse<unknown>) => void,
        reject,
      });

      const requestCount = batchData.requests.length;
      if (requestCount >= CONFIG.BATCH_SIZE) {
        this.executeBatch(batchKey, factory);
      } else if (!batchData.timer) {
        batchData.timer = setTimeout(
          () => this.executeBatch(batchKey, factory),
          CONFIG.BATCH_DELAY,
        );
      }
    });
  }

  private async executeBatch<T>(
    batchKey: string,
    factory: () => Promise<ApiResponse<T>>,
  ): Promise<void> {
    const batchData = this.batches.get(batchKey);
    if (!batchData) return;

    this.batches.delete(batchKey);
    if (batchData.timer) clearTimeout(batchData.timer);

    const { requests } = batchData;

    try {
      const result = await factory();
      for (let i = 0, len = requests.length; i < len; i++) {
        requests[i].resolve(result as ApiResponse<unknown>);
      }
    } catch (error) {
      for (let i = 0, len = requests.length; i < len; i++) {
        requests[i].reject(error);
      }
    }
  }
}

// -------------------- Adaptive Pool --------------------
class Pool {
  private readonly queue: Array<{
    fn: () => Promise<unknown>;
    resolve: (value: unknown) => void;
    reject: (reason?: unknown) => void;
    priority: number;
  }> = [];
  private active = 0;
  private readonly maxConcurrent = CONFIG.MAX_CONCURRENT;
  private readonly priorityMap = { high: 3, normal: 2, low: 1 };

  async execute<T>(
    fn: () => Promise<T>,
    priority: 'high' | 'normal' | 'low' = 'normal',
  ): Promise<T> {
    if (this.active < this.maxConcurrent) return this.run(fn);

    const priorityNum = this.priorityMap[priority];
    return new Promise<T>((resolve, reject) => {
      const task = {
        fn: fn as () => Promise<unknown>,
        resolve: resolve as (value: unknown) => void,
        reject,
        priority: priorityNum,
      };

      // Binary insert for sorted queue
      const idx = this.findInsertIndex(priorityNum);
      this.queue.splice(idx, 0, task);
    });
  }

  private findInsertIndex(priority: number): number {
    let left = 0;
    let right = this.queue.length;

    while (left < right) {
      const mid = (left + right) >>> 1;
      if (this.queue[mid].priority >= priority) {
        left = mid + 1;
      } else {
        right = mid;
      }
    }

    return left;
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
    while (this.queue.length > 0 && this.active < this.maxConcurrent) {
      const task = this.queue.shift()!;
      this.run(task.fn as () => Promise<unknown>)
        .then(task.resolve)
        .catch(task.reject);
    }
  }

  getStats(): { active: number; queued: number; maxConcurrent: number } {
    return {
      active: this.active,
      queued: this.queue.length,
      maxConcurrent: this.maxConcurrent,
    };
  }
}

// -------------------- Global Instances --------------------
const cache = new Cache<string, ApiResponse<unknown>>(CONFIG.CACHE_SIZE);
const urlCache = new Cache<number, string>(50);
const coalescer = new Coalescer();
const pool = new Pool();

// -------------------- Utilities --------------------
const buildUrl = (endpoint: string, params?: QueryParams): string => {
  if (!params) {
    const isAbsolute = endpoint.charCodeAt(0) === 104 && endpoint.startsWith('http');
    return isAbsolute ? endpoint : `${CONFIG.API_URL}/${endpoint.replace(/^\//, '')}`;
  }

  // Fast cache key using hash
  const paramStr = JSON.stringify(params);
  const cacheKey = fastHash(endpoint + paramStr);
  const cached = urlCache.get(cacheKey);
  if (cached) return cached;

  const isAbsolute = endpoint.charCodeAt(0) === 104 && endpoint.startsWith('http');
  const base = isAbsolute ? endpoint : `${CONFIG.API_URL}/${endpoint.replace(/^\//, '')}`;

  const searchParams = new URLSearchParams();
  const entries = Object.entries(params);
  for (let i = 0, len = entries.length; i < len; i++) {
    const [key, value] = entries[i];
    if (value != null) searchParams.append(key, String(value));
  }

  const queryStr = searchParams.toString();
  const url = queryStr ? `${base}?${queryStr}` : base;
  urlCache.set(cacheKey, url);
  return url;
};

// -------------------- Fast Auth Headers --------------------
const getAuthHeaders = (() => {
  let cached: Record<string, string> | null = null;
  let lastCheck = 0;
  let authString = '';

  return (): Record<string, string> => {
    const now = Date.now();
    if (cached && now - lastCheck < CONFIG.TTL_MS) return cached;

    const headers: Record<string, string> = {};
    const { AUTH_USERNAME: user, AUTH_PASSWORD: pass, API_TOKEN: token } = process.env;

    if (user && pass) {
      // Cache the base64 encoding
      if (!authString || now - lastCheck >= CONFIG.TTL_MS) {
        authString = IS_BUN
          ? btoa(`${user}:${pass}`)
          : Buffer.from(`${user}:${pass}`).toString('base64');
      }
      headers.Authorization = `Basic ${authString}`;
    } else if (token) {
      headers.Authorization = `Bearer ${token}`;
    }

    cached = headers;
    lastCheck = now;
    return headers;
  };
})();

const createError = (name: string, message: string, status: number, retryable = false): ApiError =>
  Object.freeze({ name, message, status, retryable });

// -------------------- Type Logging --------------------
const logTypes = <T>(
  endpoint: string,
  data: T,
  metadata?: { duration?: number; attempt?: number },
): void => {
  try {
    const dataStr = JSON.stringify(data);
    if (dataStr.length > 10000) return;

    const inferType = (val: unknown, depth = 0): string => {
      if (depth > 8) return '[Deep]';
      if (val == null) return val === null ? 'null' : 'undefined';

      if (Array.isArray(val)) {
        if (val.length === 0) return 'unknown[]';
        const types = [...new Set(val.slice(0, 3).map((item) => inferType(item, depth + 1)))];
        return types.length === 1 ? `${types[0]}[]` : `(${types.join(' | ')})[]`;
      }

      if (typeof val === 'object') {
        const entries = Object.entries(val).slice(0, 15);
        const props = entries.map(([k, v]) => `  ${k}: ${inferType(v, depth + 1)};`).join('\n');
        return `{\n${props}\n}`;
      }

      return typeof val;
    };

    const typeName = endpoint.replace(/[^\w]/g, '_') || 'ApiResponse';
    const typeDefinition = `type ${typeName}Response = ${inferType(data)};`;

    console.log(`🔍 [SafeFetch] "${endpoint}"\n${typeDefinition}`);
    if (metadata?.duration !== undefined) {
      console.log(
        `⏱️ ${metadata.duration}ms${metadata.attempt ? ` (attempt ${metadata.attempt})` : ''}`,
      );
    }
  } catch {
    // Silently fail on logging errors
  }
};

// -------------------- Core Request Logic --------------------
const executeRequest = async <T>(
  method: HttpMethod,
  url: string,
  options: {
    body?: BodyInit;
    headers: Record<string, string>;
    cache: RequestCache;
    timeout: number;
    next?: { revalidate?: number | false; tags?: string[] };
    signal?: AbortSignal;
  },
): Promise<ApiResponse<T>> => {
  const controller = new AbortController();
  let timeoutId: NodeJS.Timeout | undefined;

  // Optimized signal combination
  const signal = options.signal
    ? (() => {
        const combined = new AbortController();
        const abort = () => combined.abort();

        options.signal!.addEventListener('abort', abort, { once: true });
        controller.signal.addEventListener('abort', abort, { once: true });

        return combined.signal;
      })()
    : controller.signal;

  timeoutId = setTimeout(() => controller.abort(), options.timeout);

  try {
    const fetchOptions: RequestInit = {
      method,
      headers: options.headers,
      cache: options.cache,
      signal,
    };

    if (options.body !== undefined) fetchOptions.body = options.body;
    if (options.next) (fetchOptions as RequestInit & { next?: unknown }).next = options.next;

    const response = await fetch(url, fetchOptions);
    clearTimeout(timeoutId);

    const contentType = response.headers.get('content-type');
    const isJson = contentType?.includes('application/json') ?? false;

    // Parallel header extraction while parsing body
    const headersPromise = Object.fromEntries(response.headers.entries());
    const data = isJson ? await response.json() : await response.text();

    if (response.ok) {
      return {
        success: true,
        status: response.status,
        data: data as T,
        headers: headersPromise,
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
    if (timeoutId) clearTimeout(timeoutId);

    const isAbortError =
      err instanceof Error && (err.name === 'AbortError' || /abort|timeout/i.test(err.message));
    const errorName = isAbortError ? 'TimeoutError' : 'NetworkError';
    const errorStatus = isAbortError ? 408 : 0;
    const errorMessage = err instanceof Error ? err.message : 'Request failed';

    return {
      success: false,
      status: errorStatus,
      error: createError(errorName, errorMessage, errorStatus, true),
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
    logTypes: shouldLogTypes = false,
  } = options;

  const url = buildUrl(endpoint, params);
  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...getAuthHeaders(),
    ...customHeaders,
  };

  let body: BodyInit | undefined;
  if (data) {
    if (data instanceof FormData) {
      body = data;
    } else if (typeof data === 'string') {
      body = data;
    } else {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(data);
    }
  }

  const cacheKey = `${method}:${url}:${body ? 'with-body' : 'no-body'}`;

  // Fast cache check for GET requests
  if (method === 'GET' && cachePolicy !== 'no-store') {
    const cached = cache.get(cacheKey);
    if (cached) {
      if (shouldLogTypes === true && CONFIG.IS_DEV && cached.success) {
        logTypes(endpoint, cached.data, { duration: 0 });
      }
      return cached as ApiResponse<TResponse>;
    }
  }

  const startTime = Date.now();

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
          if (method === 'GET' && cachePolicy !== 'no-store') cache.set(cacheKey, result);

          const finalResult = transform ? { ...result, data: transform(result.data) } : result;

          if (shouldLogTypes === true && CONFIG.IS_DEV) {
            logTypes(endpoint, finalResult.data, {
              duration: Date.now() - startTime,
              attempt: attempt > 1 ? attempt : undefined,
            });
          }

          return finalResult;
        }

        const canRetry =
          attempt <= retries &&
          CONFIG.IDEMPOTENT_METHODS.has(method) &&
          (result.error.retryable || CONFIG.RETRY_CODES.has(result.status));

        if (!canRetry) return result;

        // Exponential backoff with jitter
        const baseDelay = 100 * (1 << (attempt - 1)); // Bit shift for power of 2
        const jitter = Math.random() * 100;
        const delay = Math.min(1000, baseDelay + jitter);

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
    runtime: IS_BUN ? 'bun' : IS_NODE ? 'node' : 'unknown',
  }),
  clearCaches: () => {
    cache.clear();
    urlCache.clear();
  },
  batch: <T>(requests: Array<() => Promise<ApiResponse<T>>>): Promise<Array<ApiResponse<T>>> => {
    const limitedRequests = requests.slice(0, CONFIG.BATCH_SIZE);
    return Promise.all(limitedRequests.map((req) => req()));
  },
  timeout: (ms: number): AbortSignal => {
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
