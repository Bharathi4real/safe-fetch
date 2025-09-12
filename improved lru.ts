/**
 * SafeFetch – Memory-Optimized Typed Fetch utility for Next.js
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * Supports Next.js 14.x.x & 15.x.x
 *
 * Memory optimizations: Bounded queues, stream cleanup, cache eviction, weak references
 */

'use server';

import { revalidatePath, revalidateTag, unstable_cache } from 'next/cache';

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] as const;

export type HttpMethod = (typeof HTTP_METHODS)[number];
export type RequestBody = Record<string, unknown> | FormData | string | null;
export type QueryParams = Record<string, string | number | boolean | null | undefined>;
export type NextJSRequestCache = 'default' | 'no-store' | 'reload' | 'no-cache' | 'force-cache';

export interface NextCacheOptions {
  revalidate?: number | false;
  tags?: string[];
}

export interface RequestOptions<TBody extends RequestBody = RequestBody, TResponse = unknown> {
  data?: TBody;
  params?: QueryParams;
  retries?: number;
  timeout?: number | ((attempt: number) => number);
  cache?: NextJSRequestCache;
  next?: NextCacheOptions;
  headers?: Record<string, string>;
  logTypes?: boolean;
  transform?: <T = TResponse, R = TResponse>(data: T) => R;
  priority?: 'high' | 'normal' | 'low';
  onProgress?: (progress: { loaded: number; total?: number; percent?: number }) => void;
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

const CONFIG = {
  API_URL: process.env.NEXT_PUBLIC_API_URL ?? process.env.BASE_URL ?? '',
  IS_DEV: process.env.NODE_ENV === 'development',
  RETRY_CODES: new Set([408, 429, 500, 502, 503, 504]),
  IDEMPOTENT_METHODS: new Set<HttpMethod>(['GET', 'PUT', 'DELETE']),
  DEFAULT_TIMEOUT: 60000,
  DEFAULT_RETRIES: 2,
  SENSITIVE_KEY_REGEX: /password|token|secret|key|auth/i,
  MAX_CONCURRENT_REQUESTS: 10,
  MAX_CACHE_SIZE: 25,
  MAX_URL_CACHE_SIZE: 100,
  MAX_TYPE_CACHE_SIZE: 25,
  FAILURE_DECAY_MS: 60_000,
  MAX_QUEUE_ITEMS: 500,
  CACHE_TTL_MS: 300_000,
  MAX_FAILURE_ENTRIES: 100,
} as const;

// -------------------- Utilities --------------------
const encodeParamValue = (v: string | number | boolean) => String(v);

const stableSerializeParams = (params?: QueryParams): string => {
  if (!params) return '';
  return Object.keys(params)
    .sort()
    .filter((k) => params[k] !== null && params[k] !== undefined)
    .map(
      (k) =>
        `${k}=${encodeURIComponent(encodeParamValue(params[k] as string | number | boolean))}`,
    )
    .join('&');
};

const createError = (
  name: string,
  message: string,
  status: number,
  retryable = false,
): ApiError => ({
  name,
  message,
  status,
  retryable,
});

// -------------------- LRU Cache --------------------
class LRUNode<K, V> {
  key!: K;
  value!: V;
  timestamp: number = Date.now();
  prev: LRUNode<K, V> | null = null;
  next: LRUNode<K, V> | null = null;
}

class MemoryEfficientLRUCache<K, V> {
  private map = new Map<K, LRUNode<K, V>>();
  private head: LRUNode<K, V> | null = null;
  private tail: LRUNode<K, V> | null = null;
  private capacity: number;
  private ttl: number;
  private lastCleanup = Date.now();

  constructor(capacity: number, ttlMs = CONFIG.CACHE_TTL_MS) {
    this.capacity = Math.max(1, capacity);
    this.ttl = ttlMs;
  }

  get size() {
    return this.map.size;
  }

  get(key: K): V | undefined {
    this.cleanupIfNeeded();
    const node = this.map.get(key);
    if (!node) return undefined;
    if (Date.now() - node.timestamp > this.ttl) {
      this.delete(key);
      return undefined;
    }
    this.moveToHead(node);
    return node.value;
  }

  set(key: K, value: V): void {
    this.cleanupIfNeeded();
    let node = this.map.get(key);
    if (node) {
      node.value = value;
      node.timestamp = Date.now();
      this.moveToHead(node);
      return;
    }
    node = new LRUNode<K, V>();
    node.key = key;
    node.value = value;
    node.timestamp = Date.now();
    this.map.set(key, node);
    this.addToHead(node);
    while (this.map.size > this.capacity) this.evictTail();
  }

  delete(key: K): void {
    const node = this.map.get(key);
    if (!node) return;
    this.removeNode(node);
    this.map.delete(key);
  }

  clear(): void {
    this.map.clear();
    this.head = this.tail = null;
  }

  private cleanupIfNeeded() {
    const now = Date.now();
    if (now - this.lastCleanup < 60_000) return;
    this.lastCleanup = now;
    for (const [key, node] of this.map) if (now - node.timestamp > this.ttl) this.delete(key);
  }

  private addToHead(node: LRUNode<K, V>) {
    node.prev = null;
    node.next = this.head;
    if (this.head) this.head.prev = node;
    this.head = node;
    if (!this.tail) this.tail = node;
  }

  private moveToHead(node: LRUNode<K, V>) {
    if (node === this.head) return;
    this.removeNode(node);
    this.addToHead(node);
  }

  private removeNode(node: LRUNode<K, V>) {
    if (node.prev) node.prev.next = node.next;
    if (node.next) node.next.prev = node.prev;
    if (node === this.head) this.head = node.next;
    if (node === this.tail) this.tail = node.prev;
    node.prev = node.next = null;
  }

  private evictTail() {
    if (!this.tail) return;
    const key = this.tail.key;
    this.removeNode(this.tail);
    this.map.delete(key);
  }
}

// -------------------- Auth Header Provider --------------------
const authHeaderProvider = (() => {
  let cachedHeaders: Record<string, string> | null = null;
  let lastComputed = 0;
  return (): Record<string, string> => {
    const now = Date.now();
    if (cachedHeaders && now - lastComputed < CONFIG.CACHE_TTL_MS) return cachedHeaders;
    const authHeaders: Record<string, string> = {};
    const { AUTH_USERNAME: username, AUTH_PASSWORD: password, API_TOKEN: token } = process.env;
    if (username && password)
      authHeaders.Authorization = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
    else if (token) authHeaders.Authorization = `Bearer ${token}`;
    cachedHeaders = authHeaders;
    lastComputed = now;
    return authHeaders;
  };
})();

// -------------------- Failure Tracker --------------------
class BoundedFailureTracker {
  private map = new Map<string, { count: number; lastFailure: number }>();
  private maxEntries = CONFIG.MAX_FAILURE_ENTRIES;

  record(url: string) {
    if (this.map.size >= this.maxEntries) this.cleanup();
    const now = Date.now();
    const existing = this.map.get(url);
    if (!existing) this.map.set(url, { count: 1, lastFailure: now });
    else {
      const decayFactor = Math.floor((now - existing.lastFailure) / CONFIG.FAILURE_DECAY_MS);
      existing.count = Math.max(1, existing.count - decayFactor + 1);
      existing.lastFailure = now;
    }
  }

  get(url: string) {
    return this.map.get(url) ?? { count: 0, lastFailure: 0 };
  }

  delete(url: string) {
    this.map.delete(url);
  }

  clear() {
    this.map.clear();
  }

  size() {
    return this.map.size;
  }

  private cleanup() {
    const entries = Array.from(this.map.entries()).sort(
      (a, b) => a[1].lastFailure - b[1].lastFailure,
    );
    const toRemove = entries.slice(0, Math.floor(entries.length / 2));
    for (const [url] of toRemove) this.map.delete(url);
  }
}

const failureTracker = new BoundedFailureTracker();

// -------------------- Worker Pool --------------------
type Task<T> = {
  id: string;
  run: () => Promise<T>;
  resolve: (v: T) => void;
  reject: (e: unknown) => void;
  timestamp: number;
};

class MemoryBoundedWorkerPool {
  private queues = {
    high: [] as Task<unknown>[],
    normal: [] as Task<unknown>[],
    low: [] as Task<unknown>[],
  };
  private workers: number;
  private running = true;
  private taskCounter = 0;

  constructor(workers = CONFIG.MAX_CONCURRENT_REQUESTS) {
    this.workers = Math.max(1, workers);
    for (let i = 0; i < this.workers; i++) this.workerLoop();
    setInterval(() => this.cleanupStaleTasks(), 30000);
  }

  enqueue<T>(fn: () => Promise<T>, priority: 'high' | 'normal' | 'low'): Promise<T> {
    const totalQueued =
      this.queues.high.length + this.queues.normal.length + this.queues.low.length;
    if (totalQueued >= CONFIG.MAX_QUEUE_ITEMS)
      return Promise.reject(new Error('Request queue limit exceeded'));
    const taskId = `task_${++this.taskCounter}`;
    return new Promise<T>((resolve, reject) => {
      this.queues[priority].push({
        id: taskId,
        run: fn,
        resolve: resolve as (v: unknown) => void,
        reject: reject as (e: unknown) => void,
        timestamp: Date.now(),
      });
    });
  }

  private async workerLoop() {
    while (this.running) {
      const task = this.dequeue();
      if (!task) {
        await new Promise((r) => setTimeout(r, 10));
        continue;
      }
      try {
        const result = await task.run();
        task.resolve(result);
      } catch (err) {
        task.reject(err);
      }
    }
  }

  private dequeue(): Task<unknown> | undefined {
    return this.queues.high.shift() || this.queues.normal.shift() || this.queues.low.shift();
  }

  private cleanupStaleTasks() {
    const now = Date.now();
    const maxAge = 300_000;
    for (const queue of Object.values(this.queues)) {
      for (let i = queue.length - 1; i >= 0; i--)
        if (now - queue[i].timestamp > maxAge)
          queue.splice(i, 1)[0].reject(new Error('Task timeout - removed from queue'));
    }
  }

  getStats() {
    return {
      high: this.queues.high.length,
      normal: this.queues.normal.length,
      low: this.queues.low.length,
      workers: this.workers,
    };
  }

  stop() {
    this.running = false;
  }
}

const pool = new MemoryBoundedWorkerPool(CONFIG.MAX_CONCURRENT_REQUESTS);

// -------------------- Caches --------------------
const responseCache = new MemoryEfficientLRUCache<string, ApiResponse<unknown>>(
  CONFIG.MAX_CACHE_SIZE,
);
const urlCache = new MemoryEfficientLRUCache<string, string>(CONFIG.MAX_URL_CACHE_SIZE);
const typeInferenceCache = new MemoryEfficientLRUCache<string, string>(CONFIG.MAX_TYPE_CACHE_SIZE);
const inFlightMap = new Map<string, Promise<ApiResponse<unknown>>>();

// -------------------- URL & Headers --------------------
const buildUrl = (endpoint: string, params?: QueryParams): string => {
  const paramsKey = stableSerializeParams(params);
  const cacheKey = `${endpoint}|${paramsKey}`;
  const cached = urlCache.get(cacheKey);
  if (cached) return cached;
  const isAbsolute = endpoint.startsWith('http');
  let url = isAbsolute ? endpoint : `${CONFIG.API_URL}/${endpoint.replace(/^\//, '')}`;
  if (paramsKey) url += `?${paramsKey}`;
  urlCache.set(cacheKey, url);
  return url;
};

const buildHeaders = (
  data?: RequestBody,
  custom?: Record<string, string>,
): Record<string, string> => {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (data && !(data instanceof FormData) && typeof data !== 'string')
    headers['Content-Type'] = 'application/json';
  return { ...headers, ...authHeaderProvider(), ...(custom || {}) };
};

// -------------------- Parse Response --------------------
const parseResponse = async <T>(response: Response): Promise<T> => {
  const text = await response.text();
  try {
    return JSON.parse(text) as T;
  } catch {
    return text as unknown as T;
  }
};

// -------------------- Execute Fetch --------------------
const executeFetch = async <TResponse>(
  url: string,
  method: HttpMethod,
  headers: Record<string, string>,
  body: BodyInit | undefined,
  cache: NextJSRequestCache,
  timeout: number,
  nextOptions: { next?: NextCacheOptions } = {},
): Promise<ApiResponse<TResponse>> => {
  const cacheKey = `${method}:${url}`;
  if (method === 'GET' && cache !== 'no-store') {
    const cached = responseCache.get(cacheKey);
    if (cached) return cached as ApiResponse<TResponse>;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      method,
      headers,
      body,
      cache,
      signal: controller.signal,
      ...nextOptions,
    });
    clearTimeout(timeoutId);
    const data = await parseResponse<TResponse>(response);

    if (response.ok) {
      const result = {
        success: true,
        status: response.status,
        data,
        headers: response.headers,
      } as const;
      if (method === 'GET' && cache !== 'no-store') responseCache.set(cacheKey, result);
      failureTracker.delete(url);
      return result;
    }

    const errorMessage =
      typeof data === 'string'
        ? data
        : data && typeof data === 'object' && 'message' in data
        ? String(data.message)
        : `HTTP ${response.status}`;
    failureTracker.record(url);
    return {
      success: false,
      status: response.status,
      error: createError(
        'HttpError',
        errorMessage,
        response.status,
        CONFIG.RETRY_CODES.has(response.status),
      ),
      data: null,
    };
  } catch (err) {
    clearTimeout(timeoutId);
    const isAbort =
      err instanceof Error && (err.name === 'AbortError' || /aborted|timeout/i.test(err.message));
    failureTracker.record(url);
    return {
      success: false,
      status: isAbort ? 408 : 0,
      error: createError(
        isAbort ? 'TimeoutError' : 'NetworkError',
        err instanceof Error ? err.message : 'Request failed',
        isAbort ? 408 : 0,
        true,
      ),
      data: null,
    };
  }
};

// -------------------- Main API Request --------------------
const shouldRetry = (
  error: ApiError,
  attempt: number,
  maxRetries: number,
  method: HttpMethod,
  url: string,
): boolean => {
  const f = failureTracker.get(url);
  if (f.count > 6 && Date.now() - f.lastFailure < 30_000) return false;
  return (
    attempt < maxRetries &&
    CONFIG.IDEMPOTENT_METHODS.has(method) &&
    (error.retryable || CONFIG.RETRY_CODES.has(error.status))
  );
};

const logTypes = <T>(endpoint: string, data: T): void => {
  if (!CONFIG.IS_DEV) return;
  const cacheKey = `${endpoint}_${typeof data}`;
  if (typeInferenceCache.get(cacheKey)) return;
  try {
    const inferType = (val: unknown, depth = 0, visited = new WeakSet()): string => {
      if (depth > 2) return 'unknown';
      if (val === null) return 'null';
      if (val === undefined) return 'undefined';
      if (typeof val === 'object' && val !== null) {
        if (visited.has(val)) return '[Circular]';
        visited.add(val);
      }
      if (Array.isArray(val))
        return val.length ? `${inferType(val[0], depth + 1, visited)}[]` : 'unknown[]';
      if (typeof val === 'object' && val !== null) {
        const entries = Object.entries(val).slice(0, 4);
        const props = entries
          .map(
            ([k, v]) =>
              `  ${k}: ${CONFIG.SENSITIVE_KEY_REGEX.test(k) ? '[REDACTED]' : inferType(v, depth + 1, visited)};`,
          )
          .join('\n');
        return `{\n${props}${entries.length > 4 ? '\n  // ...' : ''}\n}`;
      }
      return typeof val;
    };
    const typeString = `type ${endpoint.replace(/[^a-zA-Z0-9]/g, '_') || 'ApiResponse'}Response = ${inferType(data)};`;
    typeInferenceCache.set(cacheKey, typeString);
    console.log(`🔍 [SafeFetch] ${endpoint}\n${typeString}`);
  } catch {}
};

export default async function apiRequest<
  TResponse = unknown,
  TBody extends RequestBody = RequestBody,
>(
  method: HttpMethod,
  endpoint: string,
  options: RequestOptions<TBody, TResponse> = {},
): Promise<ApiResponse<TResponse>> {
  if (!HTTP_METHODS.includes(method))
    return {
      success: false,
      status: 400,
      error: createError('ValidationError', `Invalid HTTP method: ${method}`, 400),
      data: null,
    };

  const {
    data,
    params,
    retries = CONFIG.DEFAULT_RETRIES,
    timeout = CONFIG.DEFAULT_TIMEOUT,
    cache = 'default',
    next: nextCacheOptions,
    headers: customHeaders,
    logTypes: shouldLogTypes = false,
    transform,
    priority = 'normal',
  } = options;

  let url: string;
  try {
    url = buildUrl(endpoint, params);
  } catch (e) {
    return {
      success: false,
      status: 400,
      error: createError('ValidationError', `Request validation failed: ${String(e)}`, 400),
      data: null,
    };
  }

  const headers = buildHeaders(data, customHeaders);
  const body =
    data instanceof FormData || typeof data === 'string'
      ? (data as BodyInit)
      : data
      ? JSON.stringify(data)
      : undefined;

  // Deduplicate in-flight requests
  const inFlightKey = `${method}:${url}:${body ?? ''}`;
  if (inFlightMap.has(inFlightKey))
    return inFlightMap.get(inFlightKey)! as Promise<ApiResponse<TResponse>>;

  const fetchTask = pool.enqueue(
    () =>
      (async () => {
        let attempt = 0;
        while (true) {
          attempt++;
          const timeoutValue = typeof timeout === 'function' ? timeout(attempt) : timeout;
          const res = await executeFetch<TResponse>(url, method, headers, body, cache, timeoutValue, {
            next: nextCacheOptions,
          });
          if (res.success) {
            if (shouldLogTypes) logTypes(endpoint, res.data);
            return transform ? { ...res, data: transform(res.data) } : res;
          }
          if (!shouldRetry(res.error, attempt, retries, method, url)) return res;
          await new Promise((r) => setTimeout(r, 200 * attempt));
        }
      })(),
    priority,
  );

  inFlightMap.set(inFlightKey, fetchTask);
  try {
    const result = await fetchTask;
    return result;
  } finally {
    inFlightMap.delete(inFlightKey);
  }
}

// -------------------- Helpers & Utilities --------------------
apiRequest.isSuccess = <T>(
  response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: true }> => response.success;

apiRequest.isError = <T>(
  response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: false }> => !response.success;

apiRequest.utils = {
  getStats: () => ({
    queue: pool.getStats(),
    cache: {
      responses: responseCache.size,
      urls: urlCache.size,
      types: typeInferenceCache.size,
    },
    failures: failureTracker.size(),
    inFlight: inFlightMap.size,
  }),

  clearCaches: () => {
    responseCache.clear();
    urlCache.clear();
    typeInferenceCache.clear();
    failureTracker.clear();
    inFlightMap.clear();
  },

  warmup: async (endpoints: string[]) => {
    const promises = endpoints
      .slice(0, 10)
      .map((endpoint) =>
        apiRequest('GET', endpoint, { priority: 'low', timeout: 5000 }).catch(() => null),
      );
    return Promise.allSettled(promises);
  },

  getMemoryStats: () => {
    return typeof process !== 'undefined' ? (process?.memoryUsage?.() ?? null) : null;
  },
};

apiRequest.cacheHelpers = {
  revalidateTag,
  revalidatePath,
  cached: <TResponse = unknown, TBody extends RequestBody = RequestBody>(
    cacheKey: string,
    revalidateSeconds = 3600,
    tags: string[] = [],
  ) =>
    unstable_cache(
      (method: HttpMethod, endpoint: string, options: RequestOptions<TBody, TResponse> = {}) =>
        apiRequest<TResponse, TBody>(method, endpoint, options),
      [cacheKey],
      { revalidate: revalidateSeconds, tags },
    ),
};

// -------------------- HTTP Method Shortcuts --------------------
apiRequest.get = <TResponse = unknown>(
  endpoint: string,
  options: Omit<RequestOptions<null, TResponse>, 'data'> = {},
) => apiRequest<TResponse, null>('GET', endpoint, { ...options, data: null });

apiRequest.post = <TResponse = unknown, TBody extends RequestBody = RequestBody>(
  endpoint: string,
  data?: TBody,
  options: Omit<RequestOptions<TBody, TResponse>, 'data'> = {},
) => apiRequest<TResponse, TBody>('POST', endpoint, { ...options, data });

apiRequest.put = <TResponse = unknown, TBody extends RequestBody = RequestBody>(
  endpoint: string,
  data?: TBody,
  options: Omit<RequestOptions<TBody, TResponse>, 'data'> = {},
) => apiRequest<TResponse, TBody>('PUT', endpoint, { ...options, data });

apiRequest.patch = <TResponse = unknown, TBody extends RequestBody = RequestBody>(
  endpoint: string,
  data?: TBody,
  options: Omit<RequestOptions<TBody, TResponse>, 'data'> = {},
) => apiRequest<TResponse, TBody>('PATCH', endpoint, { ...options, data });

apiRequest.delete = <TResponse = unknown>(
  endpoint: string,
  options: Omit<RequestOptions<null, TResponse>, 'data'> = {},
) => apiRequest<TResponse, null>('DELETE', endpoint, { ...options, data: null });
