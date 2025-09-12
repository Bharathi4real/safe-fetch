/**
 * SafeFetch – Typed Fetch utility for Next.js
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * Supports Next.js 14.x.x & 15.x.x
 *
 * Features: O(1) LRU, request coalescing, worker-pool priority queue, full-jitter backoff,
 * incremental stream decoding, failure decay, stable param serialization.
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
  timeout?: number;
  cache?: NextJSRequestCache;
  next?: NextCacheOptions;
  headers?: Record<string, string>;
  logTypes?: boolean;
  transform?: <T = TResponse, R = TResponse>(data: T) => R;
  priority?: 'high' | 'normal' | 'low';
  onProgress?: (progress: { loaded: number; total?: number; percent?: number }) => void;
  preferStream?: boolean;
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

// Config tuned for memory & reliability
const CONFIG = {
  API_URL: process.env.NEXT_PUBLIC_API_URL ?? process.env.BASE_URL ?? '',
  IS_DEV: process.env.NODE_ENV === 'development',
  RETRY_CODES: new Set([408, 429, 500, 502, 503, 504]),
  IDEMPOTENT_METHODS: new Set<HttpMethod>(['GET', 'PUT', 'DELETE']),
  DEFAULT_TIMEOUT: 15000,
  DEFAULT_RETRIES: 2,
  SENSITIVE_KEY_REGEX: /password|token|secret|key|auth/i,
  MAX_CONCURRENT_REQUESTS: 15,
  STREAM_THRESHOLD: 1024 * 512, // 512KB
  MAX_CACHE_SIZE: 50,
  MAX_URL_CACHE_SIZE: 200,
  FAILURE_DECAY_MS: 60_000, // decay failures over time
  MAX_QUEUE_ITEMS: 1000, // protect memory if caller floods
} as const;

// Utilities

const encodeParamValue = (v: string | number | boolean) => String(v);
const stableSerializeParams = (params?: QueryParams): string => {
  if (!params) return '';
  const keys = Object.keys(params).sort();
  const parts: string[] = [];
  for (const k of keys) {
    const v = params[k];
    if (v === null || v === undefined) continue;
    parts.push(`${k}=${encodeURIComponent(encodeParamValue(v as string | number | boolean))}`);
  }
  return parts.join('&');
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

// O(1) LRU Cache (Map + doubly linked list)

class LRUNode<K, V> {
  key!: K;
  value!: V;
  prev: LRUNode<K, V> | null = null;
  next: LRUNode<K, V> | null = null;
}

class LRUCache<K, V> {
  private map = new Map<K, LRUNode<K, V>>();
  private head: LRUNode<K, V> | null = null; // most recent
  private tail: LRUNode<K, V> | null = null; // least recent
  private capacity: number;

  constructor(capacity: number) {
    this.capacity = Math.max(1, capacity);
  }

  get size() {
    return this.map.size;
  }

  get(key: K): V | undefined {
    const node = this.map.get(key);
    if (!node) return undefined;
    this.moveToHead(node);
    return node.value;
  }

  set(key: K, value: V): void {
    let node = this.map.get(key);
    if (node) {
      node.value = value;
      this.moveToHead(node);
      return;
    }

    node = new LRUNode<K, V>();
    node.key = key;
    node.value = value;
    this.map.set(key, node);
    this.addToHead(node);

    if (this.map.size > this.capacity) {
      this.evictTail();
    }
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

// Auth header provider

const authHeaderProvider = (() => {
  let cachedHeaders: Record<string, string> | null = null;
  let lastComputed = 0;
  const CACHE_TTL = 300000; // 5 minutes

  return (): Record<string, string> => {
    const now = Date.now();
    if (cachedHeaders && now - lastComputed < CACHE_TTL) return cachedHeaders;

    const authHeaders: Record<string, string> = {};
    const { AUTH_USERNAME: username, AUTH_PASSWORD: password, API_TOKEN: token } = process.env as {
      AUTH_USERNAME?: string;
      AUTH_PASSWORD?: string;
      API_TOKEN?: string;
    };

    if (username && password) {
      authHeaders.Authorization = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
    } else if (token) {
      authHeaders.Authorization = `Bearer ${token}`;
    }

    cachedHeaders = authHeaders;
    lastComputed = now;
    return authHeaders;
  };
})();

// Backoff: full jitter

const calculateBackoff = (attempt: number, base = 300, cap = 8000) => {
  // exponential: min(cap, base * 2**attempt)
  const exp = Math.min(cap, base * 2 ** attempt);
  // full jitter [0, exp)
  return Math.floor(Math.random() * exp);
};

// Failure tracker with decay (prevents permanent circuit-break)

type FailureEntry = { count: number; lastFailure: number };

class FailureTracker {
  private map = new Map<string, FailureEntry>();

  record(url: string) {
    const now = Date.now();
    const existing = this.map.get(url);
    if (!existing) {
      this.map.set(url, { count: 1, lastFailure: now });
      return;
    }
    // decay existing count proportional to time
    const elapsed = now - existing.lastFailure;
    const decayFactor = Math.floor(elapsed / CONFIG.FAILURE_DECAY_MS);
    existing.count = Math.max(1, existing.count - decayFactor + 1);
    existing.lastFailure = now;
    this.map.set(url, existing);
  }

  get(url: string) {
    const entry = this.map.get(url);
    if (!entry) return { count: 0, lastFailure: 0 };
    return entry;
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
}

const failureTracker = new FailureTracker();

// Request coalescing (in-flight dedupe for GET)
const inFlightMap = new Map<string, Promise<ApiResponse<unknown>>>();

// Priority worker pool
// 
// We maintain three queues and spawn N workers that pull highest-priority tasks first.
// This reduces recursion, keeps memory usage steady and gives deterministic concurrency.

type Task<T> = {
  run: () => Promise<T>;
  resolve: (v: T) => void;
  reject: (e: unknown) => void;
};

class PriorityWorkerPool {
  private queues: { high: Task<unknown>[]; normal: Task<unknown>[]; low: Task<unknown>[] } = {
    high: [],
    normal: [],
    low: [],
  };
  private workers: number;
  private running = true;

  constructor(workers = CONFIG.MAX_CONCURRENT_REQUESTS) {
    this.workers = Math.max(1, workers);
    for (let i = 0; i < this.workers; i++) this.workerLoop();
  }

  enqueue<T>(fn: () => Promise<T>, priority: 'high' | 'normal' | 'low'): Promise<T> {
    if (
      this.queues.high.length + this.queues.normal.length + this.queues.low.length >
      CONFIG.MAX_QUEUE_ITEMS
    ) {
      return Promise.reject(new Error('Request queue limit exceeded'));
    }

    return new Promise<T>((resolve, reject) => {
      this.queues[priority].push({ 
        run: fn, 
        resolve: resolve as (v: unknown) => void, 
        reject: reject as (e: unknown) => void 
      } as Task<unknown>);
    });
  }

  private async workerLoop() {
    while (this.running) {
      const task = this.dequeue();
      if (!task) {
        // small pause to avoid busy loop
        await new Promise((r) => setTimeout(r, 6));
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
    if (this.queues.high.length) return this.queues.high.shift();
    if (this.queues.normal.length) return this.queues.normal.shift();
    if (this.queues.low.length) return this.queues.low.shift();
    return undefined;
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

const pool = new PriorityWorkerPool(CONFIG.MAX_CONCURRENT_REQUESTS);

// Caches & type inference

const responseCache = new LRUCache<string, ApiResponse<unknown>>(CONFIG.MAX_CACHE_SIZE);
const urlCache = new LRUCache<string, string>(CONFIG.MAX_URL_CACHE_SIZE);
const typeInferenceCache = new LRUCache<string, string>(50);

// Stream parsing (incremental decode)

const sharedDecoder = new TextDecoder();

async function streamResponse<T>(
  response: Response,
  onProgress?: (progress: { loaded: number; total?: number; percent?: number }) => void,
): Promise<T> {
  if (!response.body) {
    throw new Error('Response body not available for streaming');
  }

  const reader = response.body.getReader();
  const contentLength = Number(response.headers.get('content-length') || '0') || undefined;
  let loaded = 0;
  const chunks: Uint8Array[] = [];

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        chunks.push(value);
        loaded += value.length;
        if (onProgress) {
          onProgress({
            loaded,
            ...(contentLength ? { total: contentLength, percent: Math.round((loaded / contentLength) * 100) } : {}),
          });
        }
      }
    }

    // combine
    const result = new Uint8Array(loaded);
    let offset = 0;
    for (const c of chunks) {
      result.set(c, offset);
      offset += c.length;
    }
    const text = sharedDecoder.decode(result, { stream: false });

    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('json') || text.trim().match(/^[[{]/)) {
      return JSON.parse(text) as T;
    }
    return text as unknown as T;
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // ignore
    }
  }
}

// Response parsing with preferStream flag

const parseResponse = async <T>(
  response: Response,
  options: {
    onProgress?: (progress: { loaded: number; total?: number; percent?: number }) => void;
    preferStream?: boolean;
  } = {},
): Promise<T> => {
  const contentLength = Number(response.headers.get('content-length') || '0') || undefined;
  const shouldStream = options.preferStream || (contentLength && contentLength > CONFIG.STREAM_THRESHOLD);

  if (shouldStream && response.body) {
    return streamResponse<T>(response, options.onProgress);
  }

  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('json')) {
    return response.json() as Promise<T>;
  }
  const text = await response.text();
  try {
    return JSON.parse(text) as T;
  } catch {
    return text as unknown as T;
  }
};

// Build url + caching

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

// Header builder

const buildHeaders = (data?: RequestBody, custom?: Record<string, string>): Record<string, string> => {
  const headers: Record<string, string> = { Accept: 'application/json' };

  if (data && !(data instanceof FormData) && typeof data !== 'string') {
    headers['Content-Type'] = 'application/json';
  }

  const auth = authHeaderProvider();
  return { ...headers, ...auth, ...(custom || {}) };
};

// executeFetch with timeout, caching, failure tracking

async function executeFetch<TResponse>(
  url: string,
  method: HttpMethod,
  headers: Record<string, string>,
  body: BodyInit | undefined,
  cache: NextJSRequestCache,
  timeout: number,
  nextOptions: { next?: NextCacheOptions },
  streamOptions: {
    onProgress?: (progress: { loaded: number; total?: number; percent?: number }) => void;
    preferStream?: boolean;
  } = {},
): Promise<ApiResponse<TResponse>> {
  // GET cache fast path
  const cacheKey = `${method}:${url}`;
  if (method === 'GET' && cache !== 'no-store' && !streamOptions.preferStream) {
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

    const data = await parseResponse<TResponse>(response, streamOptions);

    if (response.ok) {
      const result = {
        success: true,
        data,
        status: response.status,
        headers: response.headers,
      } as const;

      // Cache GETs
      if (method === 'GET' && cache !== 'no-store') {
        responseCache.set(cacheKey, result);
      }

      failureTracker.delete(url);
      return result;
    }

    // Build error message robustly
    const errorMessage = (() => {
      if (typeof data === 'string') return data;
      if (data && typeof data === 'object') {
        const obj = data as Record<string, unknown>;
        return String(obj.message || obj.error || `HTTP ${response.status}`);
      }
      return `HTTP ${response.status}`;
    })();

    failureTracker.record(url);

    return {
      success: false,
      status: response.status,
      error: createError('HttpError', errorMessage, response.status, CONFIG.RETRY_CODES.has(response.status)),
      data: null,
    };
  } catch (err) {
    clearTimeout(timeoutId);

    const isAbort = err instanceof Error && (err.name === 'AbortError' || /aborted|timeout/i.test(err.message));
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
}

// Should retry decision

const shouldRetry = (
  error: ApiError,
  attempt: number,
  maxRetries: number,
  method: HttpMethod,
  url: string,
): boolean => {
  const f = failureTracker.get(url);

  // Circuit breaker: if too many failures recently, avoid hammering
  if (f.count > 6 && Date.now() - f.lastFailure < 30_000) return false;

  return (
    attempt < maxRetries &&
    CONFIG.IDEMPOTENT_METHODS.has(method) &&
    (error.retryable || CONFIG.RETRY_CODES.has(error.status))
  );
};

// Type inference logging 

const logTypes = <T>(endpoint: string, data: T): void => {
  if (!CONFIG.IS_DEV) return;

  const cacheKey = `${endpoint}_${typeof data}`;
  const cached = typeInferenceCache.get(cacheKey);
  if (cached) {
    console.log(`🔍 [SafeFetch] ${endpoint} (cached)\n${cached}`);
    return;
  }

  const inferType = (val: unknown, depth = 0): string => {
    if (depth > 2) return 'unknown';
    if (val === null) return 'null';
    if (val === undefined) return 'undefined';
    if (Array.isArray(val)) {
      return val.length ? `${inferType(val[0], depth + 1)}[]` : 'unknown[]';
    }
    if (typeof val === 'object' && val !== null) {
      const entries = Object.entries(val).slice(0, 4);
      const props = entries
        .map(([key, value]) => {
          const type = CONFIG.SENSITIVE_KEY_REGEX.test(key) ? '[REDACTED]' : inferType(value, depth + 1);
          return `  ${key}: ${type};`;
        })
        .join('\n');
      return `{\n${props}${entries.length > 4 ? '\n  // ...' : ''}\n}`;
    }
    return typeof val;
  };

  try {
    const typeName = endpoint.replace(/[^a-zA-Z0-9]/g, '_').replace(/^_+|_+$/g, '') || 'ApiResponse';
    const typeString = `type ${typeName}Response = ${inferType(data)};`;
    typeInferenceCache.set(cacheKey, typeString);
    console.log(`🔍 [SafeFetch] ${endpoint}\n${typeString}`);
  } catch {
    // ignore
  }
};

// Public apiRequest function

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
      error: createError('ValidationError', `Invalid HTTP method: ${method}`, 400),
      data: null,
    };
  }

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
    onProgress,
    preferStream = false,
  } = options;

  // build url & headers early (may throw)
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

  // For GET dedupe: coalesce identical in-flight requests
  const dedupeKey = `${method}:${url}:${String(preferStream)}`;
  if (method === 'GET' && !body && inFlightMap.has(dedupeKey)) {
    // Type-cast is safe because we stored promise of ApiResponse<unknown>
    return (inFlightMap.get(dedupeKey) as Promise<ApiResponse<TResponse>>);
  }

  // Wrap core logic to submit to worker pool
  const taskPromise = pool.enqueue(
    async () => {
      // If GET, create dedupe promise placeholder
      if (method === 'GET' && !body) {
        // create placeholder promise and put into inFlightMap
        // but actual network work is done below
      }

      let lastError: ApiError | undefined;

      for (let attempt = 0; attempt <= retries; attempt++) {
        const result = await executeFetch<TResponse>(
          url,
          method,
          headers,
          body,
          cache,
          timeout,
          nextCacheOptions ? { next: nextCacheOptions } : {},
          { onProgress, preferStream },
        );

        if (result.success) {
          const finalData = transform ? transform(result.data) : result.data;
          if (shouldLogTypes) logTypes(endpoint, finalData);
          return { ...result, data: finalData } as ApiResponse<TResponse>;
        }

        lastError = result.error;
        if (!shouldRetry(lastError, attempt, retries, method, url) || attempt === retries) break;

        await new Promise((r) => setTimeout(r, calculateBackoff(attempt)));
      }

      return {
        success: false,
        status: lastError!.status,
        error: lastError!,
        data: null,
      } as ApiResponse<TResponse>;
    },
    priority,
  );

  // If GET dedupe: put into inFlightMap and ensure removal
  if (method === 'GET' && !body) {
    inFlightMap.set(dedupeKey, taskPromise as Promise<ApiResponse<unknown>>);
    // cleanup after settled
    taskPromise
      .finally(() => {
        inFlightMap.delete(dedupeKey);
      })
      .catch(() => {
        /* swallow: handled by returned result */
      });
  }

  return taskPromise as Promise<ApiResponse<TResponse>>;
}

// Type guards & helpers

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
    const promises = endpoints.map((endpoint) =>
      apiRequest('GET', endpoint, { priority: 'low', timeout: 5000 }).catch(() => null),
    );
    return Promise.allSettled(promises);
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
