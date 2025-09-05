/**
 * Ultimate SafeFetch – Maximum Performance + Comprehensive Features
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * for Next.js 14.x.x & 15.x.x
 *
 * The ultimate type-safe HTTP client combining blazing performance with
 * comprehensive features and robust error handling.
 */

'use server';

import { revalidatePath, revalidateTag, unstable_cache } from 'next/cache';

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] as const;

/** HTTP methods supported by SafeFetch. */
export type HttpMethod = (typeof HTTP_METHODS)[number];

/** Request body types: JSON object, FormData, string, or null. */
export type RequestBody = Record<string, unknown> | FormData | string | null;

/** Query parameters as key-value pairs. */
export type QueryParams = Record<string, string | number | boolean | null | undefined>;

/**
 * Next.js supported cache options only.
 * Excludes browser-specific options that aren't supported in server environments.
 */
export type NextJSRequestCache = 'default' | 'no-store' | 'reload' | 'no-cache' | 'force-cache';

/**
 * Cache configuration for Next.js caching.
 */
export interface NextCacheOptions {
  revalidate?: number | false;
  tags?: string[];
  key?: string;
}

/**
 * Request configuration options.
 */
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
  onError?: (error: ApiError, attempt: number) => void;
  performanceMode?: 'balanced' | 'speed' | 'safety';
}

/**
 * Enhanced error object with comprehensive context.
 */
export interface ApiError {
  readonly name: string;
  readonly message: string;
  readonly status: number;
  readonly attempt?: number;
  readonly context?: {
    url?: string;
    method?: HttpMethod;
    timestamp: number;
    duration?: number;
    stack?: string;
    retryable?: boolean;
  };
}

/**
 * Enhanced response object with performance metrics and cache info.
 */
export type ApiResponse<T = unknown> =
  | {
      success: true;
      status: number;
      data: T;
      headers: Headers;
      cache?: { hit: boolean; key?: string };
      performance?: { duration: number; attempt: number };
    }
  | {
      success: false;
      status: number;
      error: ApiError;
      data: null;
      performance?: { duration: number; attempt: number };
    };

// Ultra-optimized configuration with intelligent defaults
const CONFIG = {
  API_URL: process.env.NEXT_PUBLIC_API_URL ?? process.env.BASE_URL ?? '',
  IS_DEV: process.env.NODE_ENV === 'development',
  RETRY_CODES: new Set([429, 500, 502, 503, 504]),
  IDEMPOTENT_METHODS: new Set<HttpMethod>(['GET', 'PUT', 'DELETE']),
  MAX_CONCURRENT: parseInt(process.env.SAFEFETCH_MAX_CONCURRENT ?? '10', 10),
  DEFAULT_TIMEOUT: parseInt(process.env.SAFEFETCH_TIMEOUT ?? '15000', 10),
  DEFAULT_RETRIES: parseInt(process.env.SAFEFETCH_RETRIES ?? '2', 10),
  NON_ALPHANUMERIC_REGEX: /[^a-zA-Z0-9]/g,
  SENSITIVE_KEY_REGEX: /password|token|secret|key|auth/i,
  
  // Pre-calculated performance optimizations
  BASE_HEADERS: Object.freeze({ Accept: 'application/json' }),
  JSON_CONTENT_TYPE: Object.freeze({ 'Content-Type': 'application/json' }),
  
  // Pre-calculate auth header with fallback for runtime updates
  AUTH_HEADER: (() => {
    const username = process.env.AUTH_USERNAME;
    const password = process.env.AUTH_PASSWORD;
    const token = process.env.API_TOKEN;

    if (username && password) {
      return Object.freeze({
        Authorization: `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`,
      });
    }
    return token ? Object.freeze({ Authorization: `Bearer ${token}` }) : null;
  })(),
  
  // Pre-compiled delay calculations with jitter
  DELAY_MAP: new Map([
    [0, { base: 1000, jitter: 100 }],
    [1, { base: 2000, jitter: 200 }],
    [2, { base: 4000, jitter: 400 }],
    [3, { base: 8000, jitter: 800 }],
    [4, { base: 10000, jitter: 1000 }], // Cap at 10s
  ]),
} as const;

// Runtime auth header getter for dynamic credentials
const getRuntimeAuthHeader = (): Record<string, string> | null => {
  // Fast path: use pre-calculated if available
  if (CONFIG.AUTH_HEADER) return CONFIG.AUTH_HEADER;
  
  // Fallback: calculate at runtime (for dynamic credentials)
  const username = process.env.AUTH_USERNAME;
  const password = process.env.AUTH_PASSWORD;
  const token = process.env.API_TOKEN;

  if (username && password) {
    return { Authorization: `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}` };
  }
  return token ? { Authorization: `Bearer ${token}` } : null;
};

// Enhanced error creation with performance mode awareness
const createError = (
  name: string,
  message: string,
  status: number,
  attempt?: number,
  context?: Omit<ApiError['context'], 'timestamp'>,
  performanceMode: 'balanced' | 'speed' | 'safety' = 'balanced',
): ApiError => {
  const baseError: ApiError = { name, message, status, attempt };
  
  if (performanceMode === 'speed') {
    return baseError;
  }
  
  return {
    ...baseError,
    context: {
      timestamp: Date.now(),
      ...context,
      ...(performanceMode === 'safety' && CONFIG.IS_DEV && { stack: new Error().stack }),
    },
  };
};

// Hyper-optimized URL building with safety fallbacks
const buildUrl = (
  endpoint: string, 
  params?: QueryParams, 
  performanceMode: 'balanced' | 'speed' | 'safety' = 'balanced'
): string => {
  try {
    // Speed mode: minimal validation, maximum performance
    if (performanceMode === 'speed') {
      const isAbsolute = endpoint.startsWith('http');
      const url = isAbsolute ? endpoint : `${CONFIG.API_URL}/${endpoint.replace(/^\//, '')}`;
      
      if (!params) return url;
      
      const queryParts: string[] = [];
      for (const key in params) {
        const value = params[key];
        if (value != null) {
          queryParts.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`);
        }
      }
      return queryParts.length ? `${url}?${queryParts.join('&')}` : url;
    }
    
    // Safety mode: use URL constructor for validation
    if (performanceMode === 'safety') {
      let url: URL;
      
      if (endpoint.startsWith('http://') || endpoint.startsWith('https://')) {
        url = new URL(endpoint);
      } else {
        const baseUrl = CONFIG.API_URL.replace(/\/+$/, '') || 'http://localhost';
        const cleanEndpoint = endpoint.replace(/^\//, '');
        url = new URL(`${baseUrl}/${cleanEndpoint}`);
      }

      if (params) {
        Object.entries(params).forEach(([key, value]) => {
          if (value !== null && value !== undefined) {
            url.searchParams.append(key, String(value));
          }
        });
      }

      return url.toString();
    }
    
    // Balanced mode: performance with basic validation
    const isAbsolute = endpoint.startsWith('http');
    if (!isAbsolute && !CONFIG.API_URL) {
      throw new Error('Base URL required for relative endpoints');
    }
    
    const url = isAbsolute ? endpoint : `${CONFIG.API_URL}/${endpoint.replace(/^\//, '')}`;
    
    if (!params) return url;
    
    const queryParts: string[] = [];
    for (const key in params) {
      const value = params[key];
      if (value != null) {
        queryParts.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`);
      }
    }
    return queryParts.length ? `${url}?${queryParts.join('&')}` : url;
    
  } catch (error) {
    throw createError(
      'URLError',
      `URL construction failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      400,
      undefined,
      { url: '[REDACTED]' },
      performanceMode,
    );
  }
};

// Ultra-fast header building with intelligent optimization
const buildHeaders = (
  data?: RequestBody, 
  custom?: Record<string, string>,
  performanceMode: 'balanced' | 'speed' | 'safety' = 'balanced'
): HeadersInit => {
  // Speed mode: maximum performance
  if (performanceMode === 'speed') {
    let headers = CONFIG.BASE_HEADERS;

    if (CONFIG.AUTH_HEADER) {
      headers = { ...headers, ...CONFIG.AUTH_HEADER };
    }

    if (data && !(data instanceof FormData)) {
      headers = { ...headers, ...CONFIG.JSON_CONTENT_TYPE };
    }

    if (custom) {
      headers = { ...headers, ...custom };
    }

    return headers;
  }
  
  // Safety/Balanced mode: with runtime auth support
  const headers: Record<string, string> = { ...CONFIG.BASE_HEADERS };

  const authHeader = getRuntimeAuthHeader();
  if (authHeader) {
    Object.assign(headers, authHeader);
  }

  if (data && !(data instanceof FormData)) {
    Object.assign(headers, CONFIG.JSON_CONTENT_TYPE);
  }

  if (custom) {
    Object.assign(headers, custom);
  }

  return headers;
};

// Advanced timeout with AbortController and cleanup
const withTimeout = async <T>(
  promise: Promise<T>, 
  ms: number,
  performanceMode: 'balanced' | 'speed' | 'safety' = 'balanced'
): Promise<T> => {
  if (performanceMode === 'speed') {
    // Fast path: Promise.race approach
    let timeoutId: NodeJS.Timeout;
    let isResolved = false;

    const timeoutPromise = new Promise<never>((_, reject) => {
      timeoutId = setTimeout(() => {
        if (!isResolved) {
          reject(createError('TimeoutError', `Request timed out after ${ms}ms`, 408));
        }
      }, ms);
    });

    try {
      const result = await Promise.race([promise, timeoutPromise]);
      isResolved = true;
      clearTimeout(timeoutId!);
      return result;
    } catch (error) {
      isResolved = true;
      clearTimeout(timeoutId!);
      throw error;
    }
  }
  
  // Modern AbortController approach for safety/balanced
  const controller = new AbortController();
  const timeoutId = setTimeout(() => {
    controller.abort(new Error(`Request timed out after ${ms}ms`));
  }, ms);

  try {
    const result = await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        controller.signal.addEventListener('abort', () => {
          reject(createError('TimeoutError', `Request timed out after ${ms}ms`, 408, undefined, undefined, performanceMode));
        });
      }),
    ]);
    clearTimeout(timeoutId);
    return result;
  } catch (error) {
    clearTimeout(timeoutId);
    throw error;
  }
};

// Intelligent data sanitization with performance modes
const sanitizeData = (
  data: unknown, 
  performanceMode: 'balanced' | 'speed' | 'safety' = 'balanced'
): unknown => {
  // Speed mode: minimal sanitization
  if (performanceMode === 'speed' && (!data || typeof data !== 'object')) {
    return data;
  }
  
  if (!data || typeof data !== 'object') return data;

  if (Array.isArray(data)) {
    const result = new Array(data.length);
    for (let i = 0; i < data.length; i++) {
      result[i] = sanitizeData(data[i], performanceMode);
    }
    return result;
  }

  const result: Record<string, unknown> = {};
  for (const key in data) {
    if (Object.hasOwn ? Object.hasOwn(data, key) : key in data) {
      const value = (data as Record<string, unknown>)[key];
      if (CONFIG.SENSITIVE_KEY_REGEX.test(key)) {
        result[key] = '[REDACTED]';
      } else if (value !== null && typeof value === 'object') {
        result[key] = sanitizeData(value, performanceMode);
      } else {
        result[key] = value;
      }
    }
  }
  return result;
};

// Enhanced type inference with caching and performance modes
const TYPE_CACHE = new Map<string, { type: string; timestamp: number }>();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

interface LogMetadata {
  cached?: boolean;
  duration?: number;
  attempt?: number;
}

const logTypes = <T>(
  endpoint: string,
  data: T,
  metadata?: LogMetadata,
  performanceMode: 'balanced' | 'speed' | 'safety' = 'balanced',
): void => {
  if (!CONFIG.IS_DEV) return;

  const dataStr = JSON.stringify(data);
  if (dataStr.length > 50000) {
    console.log(`🔍 [SafeFetch] "${endpoint}" - Skipping type analysis (data too large)`);
    return;
  }

  // Check cache first (performance optimization)
  const cacheKey = `${endpoint}:${dataStr.slice(0, 100)}`;
  const cached = TYPE_CACHE.get(cacheKey);
  const now = Date.now();
  
  if (cached && (now - cached.timestamp) < CACHE_TTL) {
    console.log(`🔍 [SafeFetch] Type for "${endpoint}" (cached)`);
    console.log(cached.type);
    if (metadata?.duration) console.log(`⏱️ Duration: ${metadata.duration}ms`);
    if (metadata?.attempt) console.log(`🔄 Attempt: ${metadata.attempt + 1}`);
    return;
  }

  const maxDepth = performanceMode === 'speed' ? 5 : performanceMode === 'safety' ? 15 : 10;
  const maxProps = performanceMode === 'speed' ? 10 : performanceMode === 'safety' ? 25 : 20;

  const inferType = (val: unknown, depth = 0): string => {
    if (depth > maxDepth) return '[Max depth]';

    if (val === null) return 'null';
    if (val === undefined) return 'undefined';

    if (Array.isArray(val)) {
      if (!val.length) return 'unknown[]';
      const sampleSize = performanceMode === 'speed' ? 3 : 5;
      const sample = val.slice(0, sampleSize);
      const types = [...new Set(sample.map((item) => inferType(item, depth + 1)))];
      return types.length === 1 ? `${types[0]}[]` : `(${types.join(' | ')})[]`;
    }

    if (typeof val === 'object') {
      const obj = sanitizeData(val, performanceMode) as Record<string, unknown>;
      const entries = Object.entries(obj).slice(0, maxProps);
      const props = entries
        .map(([key, value]) => `  ${key}: ${inferType(value, depth + 1)};`)
        .join('\n');
      return `{\n${props}\n}`;
    }

    return typeof val;
  };

  try {
    const typeName = endpoint.replace(CONFIG.NON_ALPHANUMERIC_REGEX, '_') || 'ApiResponse';
    const typeDefinition = `type ${typeName}Response = ${inferType(data)};`;

    // Cache the result with TTL
    TYPE_CACHE.set(cacheKey, { type: typeDefinition, timestamp: now });

    // Limit cache size
    if (TYPE_CACHE.size > 100) {
      const oldestKey = [...TYPE_CACHE.entries()]
        .sort((a, b) => a[1].timestamp - b[1].timestamp)[0][0];
      TYPE_CACHE.delete(oldestKey);
    }

    console.log(`🔍 [SafeFetch] Type for "${endpoint}"`);
    console.log(typeDefinition);
    if (metadata?.cached) console.log(`💾 Cache hit: ${metadata.cached}`);
    if (metadata?.duration) console.log(`⏱️ Duration: ${metadata.duration}ms`);
    if (metadata?.attempt) console.log(`🔄 Attempt: ${metadata.attempt + 1}`);
  } catch (err) {
    console.warn('[SafeFetch logTypes] Failed:', err);
  }
};

// Enhanced delay with jitter and performance modes
const delay = (attempt: number, performanceMode: 'balanced' | 'speed' | 'safety' = 'balanced'): Promise<void> => {
  const config = CONFIG.DELAY_MAP.get(attempt) ?? { base: 10000, jitter: 1000 };
  
  let ms: number;
  if (performanceMode === 'speed') {
    // Faster retries in speed mode
    ms = Math.min(config.base * 0.5, 5000);
  } else if (performanceMode === 'safety') {
    // More conservative delays in safety mode
    ms = config.base + Math.random() * config.jitter;
  } else {
    // Balanced mode
    ms = config.base + Math.random() * config.jitter * 0.5;
  }
  
  return new Promise((resolve) => setTimeout(resolve, ms));
};

// Intelligent concurrency control with performance awareness
const requestQueue = new Set<Promise<unknown>>();
const limitConcurrentRequests = async <T>(
  request: () => Promise<T>,
  performanceMode: 'balanced' | 'speed' | 'safety' = 'balanced'
): Promise<T> => {
  // Skip concurrency control in speed mode for maximum performance
  if (performanceMode === 'speed') {
    return request();
  }
  
  const maxConcurrent = performanceMode === 'safety' ? CONFIG.MAX_CONCURRENT / 2 : CONFIG.MAX_CONCURRENT;
  
  while (requestQueue.size >= maxConcurrent) {
    await Promise.race(requestQueue);
  }

  const promise = request().finally(() => {
    requestQueue.delete(promise);
  });

  requestQueue.add(promise);
  return promise;
};

// Enhanced response parsing
const parseResponse = async <T>(response: Response): Promise<T> => {
  const contentType = response.headers.get('content-type')?.toLowerCase() || '';

  if (contentType.includes('json')) {
    return (await response.json()) as T;
  }
  if (contentType.includes('text') || contentType.includes('html')) {
    return (await response.text()) as T;
  }
  
  // Try JSON first, fallback to text
  try {
    return (await response.json()) as T;
  } catch {
    return (await response.text()) as T;
  }
};

// Enhanced retry logic
const shouldRetryRequest = (
  error: ApiError,
  attempt: number,
  maxRetries: number,
  method: HttpMethod,
): boolean => {
  if (attempt >= maxRetries) return false;
  if (!CONFIG.IDEMPOTENT_METHODS.has(method)) return false;
  
  return (
    error.name === 'TimeoutError' ||
    error.name === 'NetworkError' ||
    CONFIG.RETRY_CODES.has(error.status)
  );
};

// Ultimate fetch execution combining best practices
async function executeFetch<TResponse>(
  url: string,
  method: HttpMethod,
  headers: HeadersInit,
  body: BodyInit | undefined,
  cache: NextJSRequestCache,
  timeout: number,
  nextOptions: { next?: NextCacheOptions },
  attempt: number,
  performanceMode: 'balanced' | 'speed' | 'safety',
): Promise<ApiResponse<TResponse>> {
  return limitConcurrentRequests(async () => {
    const startTime = performance.now();

    try {
      const fetchPromise = fetch(url, {
        method,
        headers,
        body,
        cache,
        ...nextOptions,
      });

      const response = await withTimeout(fetchPromise, timeout, performanceMode);
      const data = await parseResponse<TResponse>(response);
      const duration = performance.now() - startTime;

      if (response.ok) {
        // Detect cache status
        const cacheStatus = 
          response.headers.get('x-cache-status') || 
          response.headers.get('cf-cache-status') ||
          response.headers.get('x-cache');
        const cacheHit = /hit/i.test(cacheStatus || '');

        return {
          success: true,
          data,
          status: response.status,
          headers: response.headers,
          cache: { hit: cacheHit, key: nextOptions.next?.key },
          performance: { duration, attempt },
        };
      }

      // Extract meaningful error message
      const errorMessage = (() => {
        if (typeof data === 'string') return data;
        if (data && typeof data === 'object') {
          const obj = data as Record<string, unknown>;
          return String(obj.message || obj.error || `HTTP ${response.status} ${response.statusText}`);
        }
        return `HTTP ${response.status} ${response.statusText}`;
      })();

      return {
        success: false,
        status: response.status,
        error: createError(
          'HttpError',
          errorMessage,
          response.status,
          attempt,
          {
            url: performanceMode === 'safety' ? url : '[REDACTED]',
            method,
            duration,
            retryable: CONFIG.RETRY_CODES.has(response.status),
          },
          performanceMode,
        ),
        data: null,
        performance: { duration, attempt },
      };
    } catch (err) {
      const duration = performance.now() - startTime;
      const isTimeout = err instanceof Error && (
        err.message.includes('timed out') || 
        err.message.includes('timeout') ||
        err.name === 'AbortError'
      );

      const errorName = isTimeout ? 'TimeoutError' : 'NetworkError';
      const errorMessage = err instanceof Error ? err.message : 'Network error occurred';

      return {
        success: false,
        status: isTimeout ? 408 : 0,
        error: createError(
          errorName,
          errorMessage,
          isTimeout ? 408 : 0,
          attempt,
          {
            url: performanceMode === 'safety' ? url : '[REDACTED]',
            method,
            duration,
            retryable: true,
          },
          performanceMode,
        ),
        data: null,
        performance: { duration, attempt },
      };
    }
  }, performanceMode);
}

/**
 * Ultimate type-safe HTTP request function combining maximum performance with comprehensive features.
 * 
 * @param method - HTTP method to use (GET, POST, PUT, DELETE, PATCH).
 * @param endpoint - API endpoint (relative or absolute URL).
 * @param options - Configuration options for the request.
 * @typeParam TResponse - Expected response data type.
 * @typeParam TBody - Request body type.
 * @returns A promise resolving to the API response.
 * 
 * @example
 * ```ts
 * // Speed mode - maximum performance
 * const fastResponse = await apiRequest<UserResponse>('GET', '/api/users', {
 *   performanceMode: 'speed',
 *   cache: 'force-cache',
 *   timeout: 5000,
 * });
 * 
 * // Safety mode - comprehensive error handling
 * const safeResponse = await apiRequest<User, CreateUserData>('POST', '/api/users', {
 *   data: { name: 'John', email: 'john@example.com' },
 *   performanceMode: 'safety',
 *   retries: 3,
 *   logTypes: true,
 *   onError: (error, attempt) => {
 *     console.error(`Attempt ${attempt + 1} failed:`, error.message);
 *   },
 *   transform: (user) => ({ ...user, processed: true }),
 * });
 * 
 * // Balanced mode (default) - best of both worlds
 * const response = await apiRequest<ApiData>('GET', '/api/data', {
 *   params: { page: 1, limit: 20 },
 *   next: { revalidate: 3600, tags: ['data'] },
 *   headers: { 'X-Custom': 'value' },
 * });
 * 
 * if (apiRequest.isSuccess(response)) {
 *   console.log('Success:', response.data);
 *   console.log('Performance:', response.performance);
 * } else {
 *   console.error('Error:', response.error.message);
 *   console.error('Context:', response.error.context);
 * }
 * ```
 */
export default async function apiRequest<
  TResponse = unknown,
  TBody extends RequestBody = RequestBody,
>(
  method: HttpMethod,
  endpoint: string,
  options: RequestOptions<TBody, TResponse> = {},
): Promise<ApiResponse<TResponse>> {
  // Validate method
  if (!HTTP_METHODS.includes(method)) {
    const error = createError(
      'ValidationError',
      `Invalid HTTP method: ${method}`,
      400,
      undefined,
      { method },
      options.performanceMode,
    );
    return { success: false, status: 400, error, data: null };
  }

  // Extract options with intelligent defaults
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
    onError,
    performanceMode = 'balanced',
  } = options;

  const requestStart = performance.now();
  let url: string, headers: HeadersInit, body: BodyInit | undefined;

  // Pre-flight validation and preparation
  try {
    url = buildUrl(endpoint, params, performanceMode);
    headers = buildHeaders(data, customHeaders, performanceMode);

    if (data) {
      if (data instanceof FormData) {
        body = data;
      } else if (typeof data === 'string') {
        body = data;
      } else {
        body = JSON.stringify(data);
      }
    }
  } catch (error) {
    const apiError = createError(
      'ValidationError',
      `Request validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      400,
      undefined,
      { url: '[REDACTED]', method },
      performanceMode,
    );
    return { 
      success: false, 
      status: 400, 
      error: apiError, 
      data: null,
      performance: { duration: performance.now() - requestStart, attempt: 0 },
    };
  }

  const nextOptions = nextCacheOptions ? { next: nextCacheOptions } : {};
  let lastError: ApiError | undefined;

  // Enhanced retry loop with performance tracking
  for (let attempt = 0; attempt <= retries; attempt++) {
    const result = await executeFetch<TResponse>(
      url,
      method,
      headers,
      body,
      cache,
      timeout,
      nextOptions,
      attempt,
      performanceMode,
    );

    if (result.success) {
      const finalData = transform ? transform(result.data) : result.data;
      const totalDuration = performance.now() - requestStart;

      if (shouldLogTypes) {
        logTypes(
          endpoint, 
          finalData, 
          {
            cached: result.cache?.hit,
            duration: totalDuration,
            attempt,
          },
          performanceMode,
        );
      }

      return { 
        ...result, 
        data: finalData,
        performance: { 
          duration: totalDuration, 
          attempt: attempt + 1,
        },
      };
    }

    lastError = result.error;
    onError?.(lastError, attempt);

    // Intelligent retry decision
    if (!shouldRetryRequest(lastError, attempt, retries, method)) {
      break;
    }

    if (attempt < retries) {
      await delay(attempt, performanceMode);
    }
  }

  const totalDuration = performance.now() - requestStart;
  return { 
    success: false, 
    status: lastError!.status, 
    error: lastError!, 
    data: null,
    performance: { duration: totalDuration, attempt: retries + 1 },
  };
}

/**
 * Ultra-fast type guard to check if the response is successful.
 */
apiRequest.isSuccess = <T>(
  response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: true }> => response.success;

/**
 * Ultra-fast type guard to check if the response is an error.
 */
apiRequest.isError = <T>(
  response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: false }> => !response.success;

/**
 * Enhanced cache helper utilities with performance modes.
 */
apiRequest.cacheHelpers = {
  revalidateTag,
  revalidatePath,
  cached: <TResponse = unknown, TBody extends RequestBody = RequestBody>(
    cacheKey: string,
    revalidateSeconds = 3600,
    tags: string[] = [],
  ) =>
    unstable_cache(
      (
        method: HttpMethod, 
        endpoint: string, 
        options: RequestOptions<TBody, TResponse> = {}
      ) =>
        apiRequest<TResponse, TBody>(method, endpoint, options),
      [cacheKey],
      { revalidate: revalidateSeconds, tags },
    ),

  /**
   * Performance-aware cached request with intelligent defaults
   */
  fastCached: <TResponse = unknown, TBody extends RequestBody = RequestBody>(
    cacheKey: string,
    revalidateSeconds = 3600,
    tags: string[] = [],
  ) =>
    unstable_cache(
      (
        method: HttpMethod, 
        endpoint: string, 
        options: RequestOptions<TBody, TResponse> = {}
      ) =>
        apiRequest<TResponse, TBody>(method, endpoint, { 
          ...options, 
          performanceMode: 'speed',
          cache: 'force-cache',
        }),
      [cacheKey],
      { revalidate: revalidateSeconds, tags },
    ),

  /**
   * Safety-focused cached request with comprehensive error handling
   */
  safeCached: <TResponse = unknown, TBody extends RequestBody = RequestBody>(
    cacheKey: string,
    revalidateSeconds = 3600,
    tags: string[] = [],
  ) =>
    unstable_cache(
      (
        method: HttpMethod, 
        endpoint: string, 
        options: RequestOptions<TBody, TResponse> = {}
      ) =>
        apiRequest<TResponse, TBody>(method, endpoint, { 
          ...options, 
          performanceMode: 'safety',
          retries: Math.max(options.retries ?? 0, 3),
          timeout: Math.max(options.timeout ?? 0, 30000),
        }),
      [cacheKey],
      { revalidate: revalidateSeconds, tags },
    ),
};

/**
 * Performance mode presets for common use cases
 */
apiRequest.presets = {
  /**
   * Maximum speed preset - optimized for high-performance scenarios
   */
  speed: <TResponse = unknown, TBody extends RequestBody = RequestBody>(
    method: HttpMethod,
    endpoint: string,
    options: Omit<RequestOptions<TBody, TResponse>, 'performanceMode'> = {},
  ) =>
    apiRequest<TResponse, TBody>(method, endpoint, {
      ...options,
      performanceMode: 'speed',
      timeout: Math.min(options.timeout ?? CONFIG.DEFAULT_TIMEOUT, 5000),
      retries: Math.min(options.retries ?? CONFIG.DEFAULT_RETRIES, 1),
      cache: options.cache ?? 'force-cache',
    }),

  /**
   * Maximum safety preset - comprehensive error handling and validation
   */
  safety: <TResponse = unknown, TBody extends RequestBody = RequestBody>(
    method: HttpMethod,
    endpoint: string,
    options: Omit<RequestOptions<TBody, TResponse>, 'performanceMode'> = {},
  ) =>
    apiRequest<TResponse, TBody>(method, endpoint, {
      ...options,
      performanceMode: 'safety',
      timeout: Math.max(options.timeout ?? CONFIG.DEFAULT_TIMEOUT, 15000),
      retries: Math.max(options.retries ?? CONFIG.DEFAULT_RETRIES, 3),
      logTypes: options.logTypes ?? CONFIG.IS_DEV,
    }),

  /**
   * Balanced preset - optimal mix of performance and safety
   */
  balanced: <TResponse = unknown, TBody extends RequestBody = RequestBody>(
    method: HttpMethod,
    endpoint: string,
    options: Omit<RequestOptions<TBody, TResponse>, 'performanceMode'> = {},
  ) =>
    apiRequest<TResponse, TBody>(method, endpoint, {
      ...options,
      performanceMode: 'balanced',
    }),
};

/**
 * HTTP method shortcuts with intelligent defaults
 */
apiRequest.get = <TResponse = unknown>(
  endpoint: string,
  options: Omit<RequestOptions<null, TResponse>, 'data'> = {},
) =>
  apiRequest<TResponse, null>('GET', endpoint, { ...options, data: null });

apiRequest.post = <TResponse = unknown, TBody extends RequestBody = RequestBody>(
  endpoint: string,
  data?: TBody,
  options: Omit<RequestOptions<TBody, TResponse>, 'data'> = {},
) =>
  apiRequest<TResponse, TBody>('POST', endpoint, { ...options, data });

apiRequest.put = <TResponse = unknown, TBody extends RequestBody = RequestBody>(
  endpoint: string,
  data?: TBody,
  options: Omit<RequestOptions<TBody, TResponse>, 'data'> = {},
) =>
  apiRequest<TResponse, TBody>('PUT', endpoint, { ...options, data });

apiRequest.patch = <TResponse = unknown, TBody extends RequestBody = RequestBody>(
  endpoint: string,
  data?: TBody,
  options: Omit<RequestOptions<TBody, TResponse>, 'data'> = {},
) =>
  apiRequest<TResponse, TBody>('PATCH', endpoint, { ...options, data });

apiRequest.delete = <TResponse = unknown>(
  endpoint: string,
  options: Omit<RequestOptions<null, TResponse>, 'data'> = {},
) =>
  apiRequest<TResponse, null>('DELETE', endpoint, { ...options, data: null });

/**
 * Batch request configuration interface
 */
interface BatchRequestItem {
  method: HttpMethod;
  endpoint: string;
  options?: RequestOptions;
}

/**
 * Batch request options
 */
interface BatchOptions {
  concurrency?: number;
  failFast?: boolean;
  performanceMode?: 'balanced' | 'speed' | 'safety';
}

/**
 * Poll request options
 */
interface PollOptions<TResponse = unknown> extends RequestOptions<RequestBody, TResponse> {
  interval?: number;
  maxAttempts?: number;
  exponentialBackoff?: boolean;
}

/**
 * Circuit breaker options
 */
interface CircuitBreakerOptions<TResponse = unknown, TBody extends RequestBody = RequestBody> extends RequestOptions<TBody, TResponse> {
  failureThreshold?: number;
  resetTimeout?: number;
}

/**
 * Utility functions for common patterns
 */
apiRequest.utils = {
  /**
   * Create a batch request handler
   */
  batch: async <TResponse = unknown>(
    requests: BatchRequestItem[],
    options: BatchOptions = {},
  ): Promise<ApiResponse<TResponse>[]> => {
    const { concurrency = 5, failFast = false, performanceMode = 'balanced' } = options;
    
    const executeRequest = async (request: BatchRequestItem): Promise<ApiResponse<TResponse>> => {
      try {
        return await apiRequest<TResponse>(
          request.method, 
          request.endpoint, 
          { ...request.options, performanceMode }
        );
      } catch (error) {
        return {
          success: false,
          status: 500,
          error: createError(
            'BatchError',
            error instanceof Error ? error.message : 'Batch request failed',
            500,
            undefined,
            undefined,
            performanceMode,
          ),
          data: null,
        } as ApiResponse<TResponse>;
      }
    };

    if (failFast) {
      // Execute all requests, fail on first error
      const results: ApiResponse<TResponse>[] = [];
      for (let i = 0; i < requests.length; i += concurrency) {
        const batch = requests.slice(i, i + concurrency);
        const batchResults = await Promise.all(batch.map(executeRequest));
        
        results.push(...batchResults);
        
        // Check for failures in this batch
        if (batchResults.some(result => !result.success)) {
          break;
        }
      }
      return results;
    } else {
      // Execute all requests, collect all results
      const results: ApiResponse<TResponse>[] = [];
      for (let i = 0; i < requests.length; i += concurrency) {
        const batch = requests.slice(i, i + concurrency);
        const batchResults = await Promise.all(batch.map(executeRequest));
        results.push(...batchResults);
      }
      return results;
    }
  },

  /**
   * Create a polling request that continues until a condition is met
   */
  poll: async <TResponse = unknown>(
    method: HttpMethod,
    endpoint: string,
    condition: (response: ApiResponse<TResponse>) => boolean,
    options: PollOptions<TResponse> = {},
  ): Promise<ApiResponse<TResponse>> => {
    const {
      interval = 1000,
      maxAttempts = 10,
      exponentialBackoff = false,
      ...requestOptions
    } = options;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const response = await apiRequest<TResponse>(method, endpoint, requestOptions);
      
      if (condition(response)) {
        return response;
      }

      if (attempt < maxAttempts - 1) {
        const delayTime = exponentialBackoff ? interval * (2 ** attempt) : interval;
        await new Promise(resolve => setTimeout(resolve, delayTime));
      }
    }

    return {
      success: false,
      status: 408,
      error: createError(
        'PollTimeoutError',
        `Polling condition not met after ${maxAttempts} attempts`,
        408,
        maxAttempts,
        undefined,
        requestOptions.performanceMode,
      ),
      data: null,
    };
  },

  /**
   * Create a request with circuit breaker pattern
   */
  circuitBreaker: (() => {
    interface CircuitState {
      failures: number;
      lastFailure: number;
      state: 'closed' | 'open' | 'half-open';
    }

    const circuits = new Map<string, CircuitState>();

    return async <TResponse = unknown, TBody extends RequestBody = RequestBody>(
      key: string,
      method: HttpMethod,
      endpoint: string,
      options: CircuitBreakerOptions<TResponse, TBody> = {},
    ): Promise<ApiResponse<TResponse>> => {
      const {
        failureThreshold = 5,
        resetTimeout = 60000,
        ...requestOptions
      } = options;

      const circuit = circuits.get(key) ?? {
        failures: 0,
        lastFailure: 0,
        state: 'closed' as const,
      };

      const now = Date.now();

      // Check if circuit should be reset
      if (circuit.state === 'open' && now - circuit.lastFailure > resetTimeout) {
        circuit.state = 'half-open';
        circuit.failures = 0;
      }

      // Circuit is open, reject immediately
      if (circuit.state === 'open') {
        return {
          success: false,
          status: 503,
          error: createError(
            'CircuitBreakerError',
            'Circuit breaker is open',
            503,
            undefined,
            { circuitKey: key },
            requestOptions.performanceMode,
          ),
          data: null,
        };
      }

      try {
        const response = await apiRequest<TResponse, TBody>(method, endpoint, requestOptions);

        if (response.success) {
          // Success - reset circuit
          circuit.failures = 0;
          circuit.state = 'closed';
        } else {
          // Failure - increment counter
          circuit.failures++;
          circuit.lastFailure = now;

          if (circuit.failures >= failureThreshold) {
            circuit.state = 'open';
          }
        }

        circuits.set(key, circuit);
        return response;
      } catch (error) {
        circuit.failures++;
        circuit.lastFailure = now;

        if (circuit.failures >= failureThreshold) {
          circuit.state = 'open';
        }

        circuits.set(key, circuit);
        throw error;
      }
    };
  })(),

  /**
   * Performance monitoring and metrics collection
   */
  metrics: {
    requests: 0,
    successes: 0,
    failures: 0,
    totalDuration: 0,
    averageLatency: 0,
    
    record(response: ApiResponse<unknown>): void {
      this.requests++;
      if (response.success) {
        this.successes++;
      } else {
        this.failures++;
      }
      
      if (response.performance?.duration) {
        this.totalDuration += response.performance.duration;
        this.averageLatency = this.totalDuration / this.requests;
      }
    },

    reset(): void {
      this.requests = 0;
      this.successes = 0;
      this.failures = 0;
      this.totalDuration = 0;
      this.averageLatency = 0;
    },

    getStats() {
      return {
        requests: this.requests,
        successes: this.successes,
        failures: this.failures,
        successRate: this.requests > 0 ? (this.successes / this.requests) * 100 : 0,
        averageLatency: Math.round(this.averageLatency * 100) / 100,
        totalDuration: Math.round(this.totalDuration * 100) / 100,
      };
    },
  },
};

// Auto-record metrics in development mode
if (CONFIG.IS_DEV) {
  const originalApiRequest = apiRequest;
  
  // Create wrapper that records metrics
  const wrappedApiRequest = async <TResponse = unknown, TBody extends RequestBody = RequestBody>(
    method: HttpMethod,
    endpoint: string,
    options: RequestOptions<TBody, TResponse> = {},
  ): Promise<ApiResponse<TResponse>> => {
    const response = await originalApiRequest<TResponse, TBody>(method, endpoint, options);
    apiRequest.utils.metrics.record(response);
    return response;
  };

  // Copy all properties to maintain API compatibility
  Object.setPrototypeOf(wrappedApiRequest, originalApiRequest);
  Object.assign(wrappedApiRequest, originalApiRequest);
}
