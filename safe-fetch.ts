/**
 * SafeFetch – Optimized Typed Fetch utility for Next.js 15
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * Memory-optimized with unified retry, timeout & adaptive pooling
 */

'use server';

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] as const;

export type HttpMethod = (typeof HTTP_METHODS)[number];
export type RequestBody = Record<string, unknown> | FormData | string | null;
export type QueryParams = Record<string, string | number | boolean | null | undefined>;

export interface RequestOptions<TBody extends RequestBody = RequestBody, TResponse = unknown> {
  data?: TBody;
  params?: QueryParams;
  retries?: number;
  timeout?: number | ((attempt: number) => number);
  headers?: Record<string, string>;
  transform?<T = TResponse, R = TResponse>(data: T): R;
  priority?: 'high' | 'normal' | 'low';
  signal?: AbortSignal;
  batch?: boolean;
  logTypes?: boolean;
  cache?: RequestCache;
  next?: NextFetchRequestConfig;
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
const CONFIG = Object.freeze({
  API_URL: process.env.NEXT_PUBLIC_API_URL ?? process.env.BASE_URL ?? '',
  RETRY_CODES: new Set([408, 429, 500, 502, 503, 504]),
  IDEMPOTENT_METHODS: new Set<HttpMethod>(['GET', 'PUT', 'DELETE']),
  DEFAULT_TIMEOUT: 60000,
  DEFAULT_RETRIES: 2,
  MAX_CONCURRENT: IS_BUN ? 20 : 10,
  BATCH_SIZE: IS_BUN ? 20 : 10,
  BATCH_DELAY: IS_BUN ? 25 : 50,
  IS_DEV: process.env.NODE_ENV === 'development',
  LOG_SIZE_LIMIT: 50000,
});

// -------------------- Adaptive Pool --------------------
class RequestPool {
  private readonly queue: Array<{
    fn: () => Promise<unknown>;
    resolve: (value: unknown) => void;
    reject: (reason?: unknown) => void;
    priority: number;
  }> = [];
  private active = 0;
  private readonly maxConcurrent: number;

  constructor(maxConcurrent = CONFIG.MAX_CONCURRENT) {
    this.maxConcurrent = maxConcurrent;
  }

  private static getPriorityValue(priority: 'high' | 'normal' | 'low'): number {
    const priorityMap = { high: 3, normal: 2, low: 1 } as const;
    return priorityMap[priority];
  }

  async execute<T>(
    fn: () => Promise<T>,
    priority: 'high' | 'normal' | 'low' = 'normal',
  ): Promise<T> {
    if (this.active < this.maxConcurrent) {
      return this.run(fn);
    }

    const priorityNum = RequestPool.getPriorityValue(priority);
    return new Promise<T>((resolve, reject) => {
      this.queue.splice(this.findInsertIndex(priorityNum), 0, {
        fn: fn as () => Promise<unknown>,
        resolve: resolve as (value: unknown) => void,
        reject,
        priority: priorityNum,
      });
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
      const task = this.queue.shift();
      if (!task) break;
      
      this.run(task.fn)
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

const pool = new RequestPool();

// -------------------- Utilities --------------------
const buildUrl = (endpoint: string, params?: QueryParams): string => {
  const isAbsolute = endpoint.startsWith('http');
  
  let baseUrl = endpoint;
  if (!isAbsolute) {
    const cleanedEndpoint = endpoint.replace(/^\//, '');
    baseUrl = `${CONFIG.API_URL}/${cleanedEndpoint}`;
  }

  if (!params) return baseUrl;

  const searchParams = new URLSearchParams();
  
  for (const [key, value] of Object.entries(params)) {
    if (value != null) {
      searchParams.append(key, String(value));
    }
  }

  const queryString = searchParams.toString();
  return queryString ? `${baseUrl}?${queryString}` : baseUrl;
};

const getAuthHeaders = (() => {
  let cache: Record<string, string> | null = null;
  let lastCheck = 0;
  const CACHE_TTL = 300000; // 5 minutes

  return (): Record<string, string> => {
    const now = Date.now();
    if (cache && now - lastCheck < CACHE_TTL) {
      return cache;
    }

    const headers: Record<string, string> = {};
    const { AUTH_USERNAME: user, AUTH_PASSWORD: pass, API_TOKEN: token } = process.env;

    if (user && pass) {
      const credentials = `${user}:${pass}`;
      const encoded = IS_BUN ? btoa(credentials) : Buffer.from(credentials).toString('base64');
      headers.Authorization = `Basic ${encoded}`;
    } else if (token) {
      headers.Authorization = `Bearer ${token}`;
    }

    cache = headers;
    lastCheck = now;
    return headers;
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

// -------------------- Type Inference --------------------
class TypeInferrer {
  private static readonly MAX_DEPTH = 8;
  private static readonly MAX_SAMPLE_SIZE = 3;
  private static readonly MAX_PROPERTIES = 15;

  static infer(val: unknown, depth = 0): string {
    if (depth > this.MAX_DEPTH) return 'unknown';
    
    if (val === null) return 'null';
    if (val === undefined) return 'undefined';
    
    if (Array.isArray(val)) {
      if (val.length === 0) return 'unknown[]';
      
      const samples = val.slice(0, this.MAX_SAMPLE_SIZE);
      const types = [...new Set(samples.map(item => this.infer(item, depth + 1)))];
      return types.length === 1 ? `${types[0]}[]` : `(${types.join(' | ')})[]`;
    }
    
    if (typeof val === 'object') {
      const entries = Object.entries(val).slice(0, this.MAX_PROPERTIES);
      if (entries.length === 0) return 'Record<string, unknown>';
      
      const props = entries
        .map(([key, value]) => `  ${key}: ${this.infer(value, depth + 1)};`)
        .join('\n');
      return `{\n${props}\n}`;
    }
    
    return typeof val;
  }
}

// -------------------- Type Logging --------------------
const logTypes = <T>(
  endpoint: string,
  data: T,
  metadata?: { duration?: number; attempt?: number },
): void => {
  if (!CONFIG.IS_DEV) return;

  try {
    let payload: unknown = data;

    // Check if it's our API response wrapper
    if (
      payload &&
      typeof payload === 'object' &&
      'success' in payload &&
      (('headers' in payload && typeof payload.headers === 'object') ||
       ('status' in payload && typeof payload.status === 'number'))
    ) {
      payload = (payload as { data?: unknown }).data;
    }

    if (payload === null || payload === undefined) {
      const simpleType = payload === null ? 'null' : 'undefined';
      console.log(`🔍 [SafeFetch] "${endpoint}"`);
      console.log(`type ${endpoint.replace(/[^\w]/g, '_')}Response = ${simpleType};`);
      return;
    }

    if (typeof payload === 'string' || typeof payload === 'number' || typeof payload === 'boolean') {
      console.log(`🔍 [SafeFetch] "${endpoint}"`);
      console.log(`type ${endpoint.replace(/[^\w]/g, '_')}Response = ${typeof payload};`);
      return;
    }

    // Serialize for size check
    let serialized: string;
    try {
      serialized = JSON.stringify(payload);
    } catch {
      console.log(`🔍 [SafeFetch] "${endpoint}" - Response cannot be serialized`);
      return;
    }

    if (serialized.length > CONFIG.LOG_SIZE_LIMIT) {
      console.log(
        `🔍 [SafeFetch] "${endpoint}" - Response too large (${serialized.length} chars)`,
      );
      return;
    }

    const typeName = endpoint.replace(/[^\w]/g, '_') || 'ApiResponse';
    const typeDefinition = `type ${typeName}Response = ${TypeInferrer.infer(payload)};`;

    console.log(`[SafeFetch] "${endpoint}"\n${typeDefinition}`);
    
    if (metadata?.duration !== undefined) {
      console.log(
        `⏱️ ${metadata.duration}ms${metadata.attempt ? ` (attempt ${metadata.attempt})` : ''}`,
      );
    }
  } catch (error) {
    console.error('[SafeFetch] logTypes error:', error);
  }
};

// -------------------- Response Handler --------------------
const handleResponse = async <T>(response: Response): Promise<ApiResponse<T>> => {
  const headers: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    headers[key] = value;
  });

  const contentType = response.headers.get('content-type');
  const isJson = contentType?.includes('application/json') ?? false;
  
  let data: unknown;
  try {
    data = isJson ? await response.json() : await response.text();
  } catch {
    data = null;
  }

  if (response.ok) {
    return {
      success: true,
      status: response.status,
      data: data as T,
      headers,
    };
  }

  let message = `HTTP ${response.status}`;
  
  if (typeof data === 'string') {
    message = data;
  } else if (data && typeof data === 'object') {
    if ('message' in data && typeof data.message === 'string') {
      message = data.message;
    } else if ('error' in data && typeof data.error === 'string') {
      message = data.error;
    } else {
      try {
        message = JSON.stringify(data, null, 2);
      } catch {
        // Keep default message
      }
    }
  }

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
};

// -------------------- Core Request Logic --------------------
const executeRequest = async <T>(
  method: HttpMethod,
  url: string,
  options: {
    body?: BodyInit;
    headers: Record<string, string>;
    timeout: number;
    signal?: AbortSignal;
    cache?: RequestCache;
    next?: NextFetchRequestConfig;
  },
): Promise<ApiResponse<T>> => {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), options.timeout);

  // Combine signals if provided
  let signal = controller.signal;
  if (options.signal) {
    const combinedController = new AbortController();
    const abort = () => combinedController.abort();
    
    options.signal.addEventListener('abort', abort, { once: true });
    controller.signal.addEventListener('abort', abort, { once: true });
    
    signal = combinedController.signal;
  }

  try {
    const fetchOptions: RequestInit = {
      method,
      headers: options.headers,
      signal,
      cache: options.cache,
      next: options.next,
    };

    if (options.body !== undefined) {
      fetchOptions.body = options.body;
    }

    const response = await fetch(url, fetchOptions);
    clearTimeout(timeoutId);
    
    return await handleResponse<T>(response);
  } catch (error) {
    clearTimeout(timeoutId);
    
    if (error instanceof Error && error.name === 'AbortError') {
      return {
        success: false,
        status: 408,
        error: createError('TimeoutError', 'Request timed out', 408, true),
        data: null,
      };
    }

    return {
      success: false,
      status: 0,
      error: createError(
        'NetworkError',
        error instanceof Error ? error.message : 'Request failed',
        0,
        true,
      ),
      data: null,
    };
  }
};

// -------------------- Retry Logic --------------------
const calculateRetryDelay = (attempt: number): number => {
  const baseDelay = 100 * (2 ** (attempt - 1));
  const jitter = Math.random() * 100;
  return Math.min(1000, baseDelay + jitter);
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
  // Validate HTTP method
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
    headers: customHeaders = {},
    transform,
    priority = 'normal',
    signal,
    logTypes: shouldLogTypes = false,
    cache,
    next,
  } = options;

  const url = buildUrl(endpoint, params);
  
  // Prepare headers
  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...getAuthHeaders(),
    ...customHeaders,
  };

  // Prepare request body
  let body: BodyInit | undefined;
  if (data instanceof FormData) {
    body = data;
  } else if (typeof data === 'string') {
    body = data;
  } else if (data !== null && data !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(data);
  }

  const startTime = performance.now();

  return pool.execute(async (): Promise<ApiResponse<TResponse>> => {
    let attempt = 0;

    while (true) {
      attempt++;
      
      const timeoutValue = typeof timeout === 'function' ? timeout(attempt) : timeout;
      
      const result = await executeRequest<TResponse>(method, url, {
        body,
        headers,
        timeout: timeoutValue,
        signal,
        cache,
        next,
      });

      // Success case
      if (result.success) {
        const finalData = transform ? transform(result.data) : result.data;
        const finalResult = { ...result, data: finalData };

        if (shouldLogTypes) {
          logTypes(endpoint, finalResult.data, {
            duration: Math.round(performance.now() - startTime),
            attempt: attempt > 1 ? attempt : undefined,
          });
        }

        return finalResult;
      }

      // Check if we should retry
      const canRetry = (
        attempt <= retries &&
        CONFIG.IDEMPOTENT_METHODS.has(method) &&
        (result.error.retryable || CONFIG.RETRY_CODES.has(result.status))
      );

      if (!canRetry) {
        return result;
      }

      // Exponential backoff with jitter
      const delay = calculateRetryDelay(attempt);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }, priority);
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
    runtime: IS_BUN ? 'bun' : IS_NODE ? 'node' : 'unknown',
  }),
  timeout: (ms: number): AbortSignal => {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), ms);
    return controller.signal;
  },
} as const;
