/**
 * Optimized SafeFetch – High Performance HTTP Client for Next.js
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * Supports Next.js 14.x.x & 15.x.x
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

// Optimized configuration
const CONFIG = {
  API_URL: process.env.NEXT_PUBLIC_API_URL ?? process.env.BASE_URL ?? '',
  IS_DEV: process.env.NODE_ENV === 'development',
  RETRY_CODES: new Set([408, 429, 500, 502, 503, 504]),
  IDEMPOTENT_METHODS: new Set<HttpMethod>(['GET', 'PUT', 'DELETE']),
  DEFAULT_TIMEOUT: 15000,
  DEFAULT_RETRIES: 2,
  SENSITIVE_KEY_REGEX: /password|token|secret|key|auth/i,
  MAX_CONCURRENT_REQUESTS: 15,
  STREAM_THRESHOLD: 1024 * 512, // 512KB - reduced threshold for better streaming
  MAX_CACHE_SIZE: 50, // Reduced cache sizes for memory efficiency
  MAX_URL_CACHE_SIZE: 200,
} as const;

// Simplified priority queue using a more efficient heap structure
class PriorityQueue<T> {
  private heap: Array<{ item: T; priority: number; timestamp: number }> = [];

  enqueue(item: T, priority: number = 1): void {
    const node = { item, priority, timestamp: Date.now() };
    this.heap.push(node);
    this.heapifyUp(this.heap.length - 1);
  }

  dequeue(): T | undefined {
    if (this.heap.length === 0) return undefined;
    if (this.heap.length === 1) return this.heap.pop()!.item;

    const root = this.heap[0].item;
    this.heap[0] = this.heap.pop()!;
    this.heapifyDown(0);
    return root;
  }

  private heapifyUp(index: number): void {
    while (index > 0) {
      const parentIndex = Math.floor((index - 1) / 2);
      const parent = this.heap[parentIndex];
      const current = this.heap[index];

      if (
        current.priority <= parent.priority &&
        !(current.priority === parent.priority && current.timestamp < parent.timestamp)
      ) {
        break;
      }

      [this.heap[parentIndex], this.heap[index]] = [this.heap[index], this.heap[parentIndex]];
      index = parentIndex;
    }
  }

  private heapifyDown(index: number): void {
    const length = this.heap.length;
    while (true) {
      let maxIndex = index;
      const leftChild = 2 * index + 1;
      const rightChild = 2 * index + 2;

      if (leftChild < length && this.shouldSwap(leftChild, maxIndex)) {
        maxIndex = leftChild;
      }

      if (rightChild < length && this.shouldSwap(rightChild, maxIndex)) {
        maxIndex = rightChild;
      }

      if (maxIndex === index) break;

      [this.heap[index], this.heap[maxIndex]] = [this.heap[maxIndex], this.heap[index]];
      index = maxIndex;
    }
  }

  private shouldSwap(childIndex: number, parentIndex: number): boolean {
    const child = this.heap[childIndex];
    const parent = this.heap[parentIndex];
    return (
      child.priority > parent.priority ||
      (child.priority === parent.priority && child.timestamp < parent.timestamp)
    );
  }

  get size(): number {
    return this.heap.length;
  }
}

// Simplified request queue with better resource management
class RequestQueue {
  private queue = new PriorityQueue<() => Promise<unknown>>();
  private activeRequests = 0;
  private processing = false;

  async enqueue<T>(
    executeRequest: () => Promise<T>,
    priority: 'high' | 'normal' | 'low' = 'normal',
  ): Promise<T> {
    const priorityValue = priority === 'high' ? 3 : priority === 'normal' ? 2 : 1;

    return new Promise<T>((resolve, reject) => {
      this.queue.enqueue(async () => {
        try {
          const result = await executeRequest();
          resolve(result);
        } catch (error) {
          reject(error);
        }
      }, priorityValue);

      this.processQueue();
    });
  }

  private async processQueue(): Promise<void> {
    if (this.processing || this.activeRequests >= CONFIG.MAX_CONCURRENT_REQUESTS) {
      return;
    }

    this.processing = true;

    while (this.queue.size > 0 && this.activeRequests < CONFIG.MAX_CONCURRENT_REQUESTS) {
      const request = this.queue.dequeue();
      if (!request) break;

      this.activeRequests++;

      // Don't await - process concurrently
      request().finally(() => {
        this.activeRequests--;
        if (this.queue.size > 0) {
          this.processQueue();
        }
      });
    }

    this.processing = false;
  }

  getStats() {
    return {
      queueLength: this.queue.size,
      activeRequests: this.activeRequests,
      totalCapacity: CONFIG.MAX_CONCURRENT_REQUESTS,
    };
  }
}

const requestQueue = new RequestQueue();

// More efficient LRU Cache implementation
class OptimizedLRUCache<K, V> {
  private cache = new Map<K, V>();
  private readonly maxSize: number;

  constructor(maxSize: number) {
    this.maxSize = maxSize;
  }

  get(key: K): V | undefined {
    const value = this.cache.get(key);
    if (value !== undefined) {
      // Move to end (most recently used)
      this.cache.delete(key);
      this.cache.set(key, value);
      return value;
    }
    return undefined;
  }

  set(key: K, value: V): void {
    // If already exists, delete first
    if (this.cache.has(key)) {
      this.cache.delete(key);
    } else if (this.cache.size >= this.maxSize) {
      // Remove oldest entry
      const firstKey = this.cache.keys().next().value;
      if (firstKey !== undefined) {
        this.cache.delete(firstKey);
      }
    }
    this.cache.set(key, value);
  }

  clear(): void {
    this.cache.clear();
  }

  get size(): number {
    return this.cache.size;
  }
}

const responseCache = new OptimizedLRUCache<string, ApiResponse<unknown>>(CONFIG.MAX_CACHE_SIZE);
const urlCache = new OptimizedLRUCache<string, string>(CONFIG.MAX_URL_CACHE_SIZE);

// Optimized auth header with better caching strategy
const authHeaderProvider = (() => {
  let cachedHeaders: Record<string, string> | null = null;
  let lastComputed = 0;
  const CACHE_TTL = 300000; // 5 minutes

  return (): Record<string, string> => {
    const now = Date.now();
    if (cachedHeaders && now - lastComputed < CACHE_TTL) {
      return cachedHeaders;
    }

    const authHeaders: Record<string, string> = {};
    const { AUTH_USERNAME: username, AUTH_PASSWORD: password, API_TOKEN: token } = process.env;

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

// Streamlined URL building
const buildUrl = (endpoint: string, params?: QueryParams): string => {
  const cacheKey = `${endpoint}|${params ? JSON.stringify(params) : ''}`;
  const cached = urlCache.get(cacheKey);
  if (cached) return cached;

  const isAbsolute = endpoint.startsWith('http');
  let url = isAbsolute ? endpoint : `${CONFIG.API_URL}/${endpoint.replace(/^\//, '')}`;

  if (params) {
    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value != null) {
        searchParams.append(key, String(value));
      }
    });

    const query = searchParams.toString();
    if (query) url += `?${query}`;
  }

  urlCache.set(cacheKey, url);
  return url;
};

// Simplified header building
const buildHeaders = (
  data?: RequestBody,
  custom?: Record<string, string>,
): Record<string, string> => {
  const headers: Record<string, string> = { Accept: 'application/json' };

  if (data && !(data instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
  }

  return { ...headers, ...authHeaderProvider(), ...custom };
};

// Simplified exponential backoff
const calculateBackoff = (attempt: number): number => {
  const baseDelay = Math.min(1000 * 2 ** attempt, 8000);
  const jitter = Math.random() * 0.5 + 0.75; // 75-125% of base
  return Math.floor(baseDelay * jitter);
};

const delay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

// Optimized streaming with better memory management
async function streamResponse<T>(
  response: Response,
  onProgress?: (progress: { loaded: number; total?: number; percent?: number }) => void,
): Promise<T> {
  if (!response.body) {
    throw new Error('Response body not available for streaming');
  }

  const reader = response.body.getReader();
  const contentLength = parseInt(response.headers.get('content-length') || '0', 10);
  const chunks: Uint8Array[] = [];
  let loaded = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      chunks.push(value);
      loaded += value.length;

      onProgress?.({
        loaded,
        ...(contentLength > 0 && {
          total: contentLength,
          percent: Math.round((loaded / contentLength) * 100),
        }),
      });
    }

    // Efficiently combine chunks
    const result = new Uint8Array(loaded);
    let offset = 0;
    for (const chunk of chunks) {
      result.set(chunk, offset);
      offset += chunk.length;
    }

    const text = new TextDecoder().decode(result);
    const contentType = response.headers.get('content-type') || '';

    if (contentType.includes('json') || text.trim().match(/^[[{]/)) {
      return JSON.parse(text);
    }

    return text as T;
  } finally {
    reader.releaseLock();
  }
}

// Simplified response parsing
const parseResponse = async <T>(
  response: Response,
  options: {
    onProgress?: (progress: { loaded: number; total?: number; percent?: number }) => void;
    preferStream?: boolean;
  } = {},
): Promise<T> => {
  const contentLength = parseInt(response.headers.get('content-length') || '0', 10);
  const shouldStream = options.preferStream || contentLength > CONFIG.STREAM_THRESHOLD;

  if (shouldStream && response.body) {
    return streamResponse<T>(response, options.onProgress);
  }

  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('json')) {
    return response.json();
  }

  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    return text as T;
  }
};

// Simplified failure tracking
const failureTracker = new Map<string, { count: number; lastFailure: number }>();

const shouldRetry = (
  error: ApiError,
  attempt: number,
  maxRetries: number,
  method: HttpMethod,
  url: string,
): boolean => {
  const failure = failureTracker.get(url);
  const now = Date.now();

  // Circuit breaker: skip if too many recent failures
  if (failure && failure.count > 3 && now - failure.lastFailure < 30000) {
    return false;
  }

  return (
    attempt < maxRetries &&
    CONFIG.IDEMPOTENT_METHODS.has(method) &&
    (error.retryable || CONFIG.RETRY_CODES.has(error.status))
  );
};

// Optimized type inference with better caching
const typeInferenceCache = new OptimizedLRUCache<string, string>(50);

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
          const type = CONFIG.SENSITIVE_KEY_REGEX.test(key)
            ? '[REDACTED]'
            : inferType(value, depth + 1);
          return `  ${key}: ${type};`;
        })
        .join('\n');
      return `{\n${props}${entries.length > 4 ? '\n  // ...' : ''}\n}`;
    }
    return typeof val;
  };

  try {
    const typeName =
      endpoint.replace(/[^a-zA-Z0-9]/g, '_').replace(/^_+|_+$/g, '') || 'ApiResponse';
    const typeString = `type ${typeName}Response = ${inferType(data)};`;

    typeInferenceCache.set(cacheKey, typeString);
    console.log(`🔍 [SafeFetch] ${endpoint}\n${typeString}`);
  } catch {
    // Silently ignore errors
  }
};

// Core fetch execution with timeout handling
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
  // Check cache for GET requests
  if (method === 'GET' && cache !== 'no-store' && !streamOptions.preferStream) {
    const cacheKey = `${method}:${url}`;
    const cached = responseCache.get(cacheKey);
    if (cached) return cached as ApiResponse<TResponse>;
  }

  const abortController = new AbortController();
  const timeoutId = setTimeout(() => abortController.abort(), timeout);

  try {
    const response = await fetch(url, {
      method,
      headers,
      body,
      cache,
      signal: abortController.signal,
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

      // Cache successful GET requests
      if (method === 'GET' && cache !== 'no-store') {
        const cacheKey = `${method}:${url}`;
        responseCache.set(cacheKey, result);
      }

      // Reset failure tracking
      failureTracker.delete(url);
      return result;
    }

    // Handle HTTP errors
    const errorMessage = (() => {
      if (typeof data === 'string') return data;
      if (data && typeof data === 'object') {
        const errorObj = data as Record<string, unknown>;
        return String(errorObj.message || errorObj.error || `HTTP ${response.status}`);
      }
      return `HTTP ${response.status}`;
    })();

    // Track failure
    const failure = failureTracker.get(url) || { count: 0, lastFailure: 0 };
    failure.count++;
    failure.lastFailure = Date.now();
    failureTracker.set(url, failure);

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

    const isTimeout =
      err instanceof Error && (err.name === 'AbortError' || err.message.includes('timeout'));

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
}

/**
 * High-performance type-safe HTTP client with intelligent caching and streaming
 */
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

  return requestQueue.enqueue(async () => {
    let url: string, headers: Record<string, string>, body: BodyInit | undefined;

    try {
      url = buildUrl(endpoint, params);
      headers = buildHeaders(data, customHeaders);
      body =
        data instanceof FormData || typeof data === 'string'
          ? data
          : data
            ? JSON.stringify(data)
            : undefined;
    } catch (error) {
      return {
        success: false,
        status: 400,
        error: createError('ValidationError', `Request validation failed: ${error}`, 400),
        data: null,
      };
    }

    const nextOptions = nextCacheOptions ? { next: nextCacheOptions } : {};
    const streamOptions = { onProgress, preferStream };
    let lastError: ApiError | undefined;

    // Retry logic
    for (let attempt = 0; attempt <= retries; attempt++) {
      const result = await executeFetch<TResponse>(
        url,
        method,
        headers,
        body,
        cache,
        timeout,
        nextOptions,
        streamOptions,
      );

      if (result.success) {
        const finalData = transform ? transform(result.data) : result.data;

        if (shouldLogTypes) {
          logTypes(endpoint, finalData);
        }

        return { ...result, data: finalData };
      }

      lastError = result.error;

      if (!shouldRetry(lastError, attempt, retries, method, url) || attempt === retries) {
        break;
      }

      await delay(calculateBackoff(attempt));
    }

    return {
      success: false,
      status: lastError!.status,
      error: lastError!,
      data: null,
    };
  }, priority);
}

// Type guards
apiRequest.isSuccess = <T>(
  response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: true }> => response.success;

apiRequest.isError = <T>(
  response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: false }> => !response.success;

// Utilities
apiRequest.utils = {
  getStats: () => ({
    queue: requestQueue.getStats(),
    cache: {
      responses: responseCache.size,
      urls: urlCache.size,
      types: typeInferenceCache.size,
    },
    failures: failureTracker.size,
  }),

  clearCaches: () => {
    responseCache.clear();
    urlCache.clear();
    typeInferenceCache.clear();
    failureTracker.clear();
  },

  warmup: async (endpoints: string[]) => {
    const promises = endpoints.map((endpoint) =>
      apiRequest('GET', endpoint, { priority: 'low', timeout: 5000 }).catch(() => null),
    );
    return Promise.allSettled(promises);
  },
};

// Cache helpers
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

// HTTP method shortcuts
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
