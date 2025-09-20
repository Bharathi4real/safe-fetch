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
  IS_DEV: process.env.NODE_ENV === 'development',
} as const;

// -------------------- Unified Cache --------------------
class Cache<K, V> {
  private cache = new Map<K, { value: V; timestamp: number; hits: number; sensitive?: boolean }>();
  private lastCleanup = Date.now();
  private cleanupTimer?: NodeJS.Timeout;

  constructor(
    private maxSize: number,
    private ttl = CONFIG.TTL_MS,
  ) {
    // Schedule periodic cleanup to prevent memory leaks
    this.cleanupTimer = setInterval(() => this.cleanup(), Math.min(this.ttl / 4, 60000));
  }

  get(key: K): V | undefined {
    this.cleanup();
    const entry = this.cache.get(key);
    if (!entry || Date.now() - entry.timestamp > this.ttl) {
      // Securely delete expired entries
      if (entry?.sensitive) {
        this.secureDelete(entry.value);
      }
      this.cache.delete(key);
      return undefined;
    }
    entry.hits++;
    return entry.value;
  }

  set(key: K, value: V, sensitive = false): void {
    // Clean up before adding to prevent unbounded growth
    this.cleanup();

    while (this.cache.size >= this.maxSize) {
      // Use LRU + age-based eviction for better memory management
      const entries = [...this.cache.entries()];
      const sorted = entries.sort(([, a], [, b]) => {
        // Prioritize old, low-hit entries for eviction
        const ageScore = (Date.now() - a.timestamp) / this.ttl;
        const hitScore = 1 / (a.hits + 1);
        const aScore = ageScore + hitScore;

        const bAgeScore = (Date.now() - b.timestamp) / this.ttl;
        const bHitScore = 1 / (b.hits + 1);
        const bScore = bAgeScore + bHitScore;

        return bScore - aScore;
      });

      const [lruKey, lruEntry] = sorted[0];
      if (lruEntry.sensitive) {
        this.secureDelete(lruEntry.value);
      }
      this.cache.delete(lruKey);
    }

    this.cache.set(key, { value, timestamp: Date.now(), hits: 1, sensitive });
  }

  // Mark cache entry as containing sensitive data
  setSensitive(key: K, value: V): void {
    this.set(key, value, true);
  }

  clear = (): void => {
    // Securely clear sensitive data
    for (const [, entry] of this.cache) {
      if (entry.sensitive) {
        this.secureDelete(entry.value);
      }
    }
    this.cache.clear();
  };

  size = (): number => this.cache.size;

  // cleanup with memory pressure handling
  private cleanup(): void {
    const now = Date.now();
    if (now - this.lastCleanup < 30000 && this.cache.size < this.maxSize * 0.8) return;

    this.lastCleanup = now;
    const cutoff = now - this.ttl;
    const toDelete: K[] = [];

    for (const [key, entry] of this.cache) {
      if (entry.timestamp < cutoff) {
        toDelete.push(key);
        if (entry.sensitive) {
          this.secureDelete(entry.value);
        }
      }
    }

    toDelete.forEach(key => this.cache.delete(key));
  }

  // Secure deletion for sensitive data
  private secureDelete(value: V): void {
    if (typeof value === 'object' && value !== null) {
      try {
        // Overwrite object properties
        Object.keys(value).forEach(key => {
          if (typeof (value as any)[key] === 'string') {
            (value as any)[key] = '';
          } else if (typeof (value as any)[key] === 'object') {
            (value as any)[key] = null;
          }
        });
      } catch {
        // Ignore errors for read-only objects
      }
    }
  }

  // Cleanup resources
  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = undefined;
    }
    this.clear();
  }
}

// -------------------- Request Coalescing --------------------
class Coalescer {
  private pending = new Map<string, Promise<ApiResponse<unknown>>>();
  private batches = new Map<
    string,
    {
      requests: Array<{
        resolve: (value: ApiResponse<unknown>) => void;
        reject: (reason?: unknown) => void;
      }>;
      timer?: NodeJS.Timeout;
      timestamp: number; // Track creation time
    }
  >();
  private cleanupTimer?: NodeJS.Timeout;

  constructor() {
    // Periodic cleanup of stale batches
    this.cleanupTimer = setInterval(() => this.cleanupStale(), 60000);
  }

  async coalesce<T>(
    key: string,
    factory: () => Promise<ApiResponse<T>>,
    batch = false,
  ): Promise<ApiResponse<T>> {
    if (!batch) {
      const existing = this.pending.get(key);
      if (existing) return existing as Promise<ApiResponse<T>>;

      const promise = factory()
        .finally(() => {
          this.pending.delete(key);
          // Clean up any remaining references
          if (this.pending.size === 0) {
            this.pending.clear();
          }
        });

      this.pending.set(key, promise);
      return promise;
    }

    const batchKey = key.split(':')[0];
    return new Promise<ApiResponse<T>>((resolve, reject) => {
      let batch = this.batches.get(batchKey);
      if (!batch) {
        batch = { requests: [], timestamp: Date.now() };
      }

      batch.requests.push({
        resolve: resolve as (value: ApiResponse<unknown>) => void,
        reject
      });
      this.batches.set(batchKey, batch);

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
    if (batch.timer) {
      clearTimeout(batch.timer);
    }

    try {
      const result = await factory();
      batch.requests.forEach((req) => {
        req.resolve(result as ApiResponse<unknown>);
      });
    } catch (error) {
      batch.requests.forEach((req) => {
        req.reject(error);
      });
    } finally {
      // Ensure cleanup
      batch.requests.length = 0;
    }
  }

  private cleanupStale(): void {
    const cutoff = Date.now() - 300000; // 5 minutes
    const staleKeys: string[] = [];

    for (const [key, batch] of this.batches) {
      if (batch.timestamp < cutoff) {
        staleKeys.push(key);
        if (batch.timer) {
          clearTimeout(batch.timer);
        }
        // Reject stale requests
        batch.requests.forEach(req => {
          req.reject(new Error('Request timeout - batch expired'));
        });
      }
    }

    staleKeys.forEach(key => this.batches.delete(key));
  }

  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = undefined;
    }

    // Clean up pending batches
    for (const [, batch] of this.batches) {
      if (batch.timer) {
        clearTimeout(batch.timer);
      }
    }
    this.batches.clear();
    this.pending.clear();
  }
}

// -------------------- Adaptive Pool --------------------
class Pool {
  private queue: Array<{
    fn: () => Promise<unknown>;
    resolve: (value: unknown) => void;
    reject: (reason?: unknown) => void;
    priority: number;
  }> = [];
  private active = 0;
  private maxConcurrent = CONFIG.MAX_CONCURRENT;

  async execute<T>(
    fn: () => Promise<T>,
    priority: 'high' | 'normal' | 'low' = 'normal',
  ): Promise<T> {
    const priorityNum = { high: 3, normal: 2, low: 1 }[priority];

    if (this.active < this.maxConcurrent) return this.run(fn);

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

  getStats = () => ({
    active: this.active,
    queued: this.queue.length,
    maxConcurrent: this.maxConcurrent,
  });
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
  const isAbsolute = /^https?:\/\//.test(endpoint);
  const base = isAbsolute ? endpoint : `${CONFIG.API_URL}/${endpoint.replace(/^\//, '')}`;
  return paramStr ? `${base}?${paramStr}` : base;
};

// -------------------- Auth Headers with TTL --------------------
const getAuthHeaders = (() => {
  let cached: Record<string, string> | null = null;
  let lastCheck = 0;
  let cleanupTimer: NodeJS.Timeout | null = null;

  const clearCache = () => {
    if (cached) {
      // Clear sensitive auth data
      Object.keys(cached).forEach(key => {
        if (key.toLowerCase().includes('authorization')) {
          cached![key] = '';
        }
      });
      cached = null;
    }
  };

  return (): Record<string, string> => {
    const now = Date.now();

    // Check if cache is still valid
    if (cached && now - lastCheck < CONFIG.TTL_MS) {
      return { ...cached }; // Return copy to prevent mutations
    }

    // Clear old cache
    clearCache();

    const headers: Record<string, string> = {};
    const { AUTH_USERNAME: user, AUTH_PASSWORD: pass, API_TOKEN: token } = process.env;

    if (user && pass) {
      headers.Authorization = `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`;
    } else if (token) {
      headers.Authorization = `Bearer ${token}`;
    }

    cached = { ...headers };
    lastCheck = now;

    // Set up automatic cleanup
    if (cleanupTimer) clearTimeout(cleanupTimer);
    cleanupTimer = setTimeout(clearCache, CONFIG.TTL_MS);

    return { ...headers };
  };
})();

const createError = (
  name: string,
  message: string,
  status: number,
  retryable = false,
): ApiError => ({ name, message, status, retryable });

// -------------------- Cache Key Generation --------------------
const generateCacheKey = (method: HttpMethod, url: string, body?: BodyInit): string => {
  // Avoid including sensitive data in cache keys
  const sanitizedBody = body ? 'with-body' : 'no-body';

  // Hash sensitive URLs to prevent cache key leaks
  if (url.includes('password') || url.includes('token') || url.includes('secret')) {
    // Simple hash function for Node.js environments
    let hash = 0;
    const str = url;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    const hashStr = Math.abs(hash).toString(16).substring(0, 8);
    return `${method}:${hashStr}:${sanitizedBody}`;
  }

  return `${method}:${url}:${sanitizedBody}`;
};

// -------------------- Type Logging --------------------
const logTypes = <T>(
  endpoint: string,
  data: T,
  metadata?: { duration?: number; attempt?: number },
): void => {
  if (!CONFIG.IS_DEV) return;

  const dataStr = JSON.stringify(data);
  if (dataStr.length > 10000) return;

  const inferType = (val: unknown, depth = 0): string => {
    if (depth > 8) return '[Deep]';
    if (val == null) return val === null ? 'null' : 'undefined';

    if (Array.isArray(val)) {
      if (!val.length) return 'unknown[]';
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

  try {
    const typeName = endpoint.replace(/[^\w]/g, '_') || 'ApiResponse';
    const typeDefinition = `type ${typeName}Response = ${inferType(data)};`;
    console.log(`[SafeFetch] "${endpoint}"\n${typeDefinition}`);
    if (metadata?.duration) console.log(`${metadata.duration}ms`);
  } catch {
    // Silently fail
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
  const signal = options.signal
    ? (() => {
        const combined = new AbortController();
        [options.signal, controller.signal].forEach((s) => {
          s.addEventListener('abort', () => combined.abort());
        });
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
    if (options.next) (fetchOptions as RequestInit & { next?: unknown }).next = options.next;

    const response = await fetch(url, fetchOptions);
    clearTimeout(timeoutId);

    const isJson = response.headers.get('content-type')?.includes('application/json');
    const data = isJson ? await response.json() : await response.text();

    if (response.ok) {
      return { success: true, status: response.status, data: data as T, headers: response.headers };
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
    logTypes: shouldLogTypes = CONFIG.IS_DEV,
  } = options;

  const url = buildUrl(endpoint, params);
  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...getAuthHeaders(),
    ...customHeaders,
  };

  if (data && !(data instanceof FormData) && typeof data !== 'string')
    headers['Content-Type'] = 'application/json';

  const body =
    data instanceof FormData || typeof data === 'string'
      ? (data as BodyInit)
      : data
        ? JSON.stringify(data)
        : undefined;

  // Use cache key generation
  const cacheKey = generateCacheKey(method, url, body);

  // Determine if response contains sensitive data
  const isSensitive = endpoint.includes('auth') ||
                     endpoint.includes('login') ||
                     endpoint.includes('token') ||
                     endpoint.includes('password') ||
                     headers.Authorization;

  // Check cache for GET requests
  if (method === 'GET' && cachePolicy !== 'no-store') {
    const cached = cache.get(cacheKey);
    if (cached) {
      if (shouldLogTypes && cached.success && !isSensitive) {
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
          // Cache with sensitivity awareness
          if (method === 'GET' && cachePolicy !== 'no-store') {
            if (isSensitive) {
              cache.setSensitive(cacheKey, result);
            } else {
              cache.set(cacheKey, result);
            }
          }

          const finalResult = transform ? { ...result, data: transform(result.data) } : result;
          if (shouldLogTypes && !isSensitive) { // Don't log sensitive data
            logTypes(endpoint, finalResult.data, {
              duration: Date.now() - startTime,
              attempt: attempt - 1,
            });
          }
          return finalResult;
        }

        const shouldRetry =
          attempt < retries &&
          CONFIG.IDEMPOTENT_METHODS.has(method) &&
          (result.error.retryable || CONFIG.RETRY_CODES.has(result.error.status));
        if (!shouldRetry) return result;

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
    urls: urlCache.size()
  }),
  clearCaches: () => {
    cache.clear();
    urlCache.clear();
  },
  // Secure cache cleanup
  secureClearCaches: () => {
    cache.destroy();
    urlCache.destroy();
    coalescer.destroy();
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

// -------------------- Process Exit Cleanup --------------------
if (typeof process !== 'undefined') {
  const cleanup = () => {
    try {
      apiRequest.utils.secureClearCaches();
    } catch (error) {
      console.error('Error during cleanup:', error);
    }
  };

  process.on('exit', cleanup);
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
  process.on('uncaughtException', cleanup);
}
