/**
 * SafeFetch – High-Performance Typed Fetch Utility for Next.js
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * for Next.js 14.x.x & 15.x.x
 *
 * A robust, type-safe HTTP client for Next.js with advanced caching, retry logic,
 * error handling, and type inference logging.
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
 * Excludes browser-specific options like 'only-if-cached' that aren't supported in server environments.
 */
export type NextJSRequestCache = 'default' | 'no-store' | 'reload' | 'no-cache' | 'force-cache';

/**
 * Cache configuration for Next.js caching.
 */
export interface NextCacheOptions {
  revalidate?: number | false;
  tags?: string[];
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
  transform?: (data: TResponse) => TResponse;
}

/**
 * Error object for failed requests.
 */
export interface ApiError {
  readonly name: string;
  readonly message: string;
  readonly status: number;
}

/**
 * Response object for API requests.
 */
export type ApiResponse<T = unknown> =
  | { success: true; status: number; data: T }
  | { success: false; status: number; error: ApiError; data: null };

// Ultra-optimized configuration with pre-compiled patterns and cached computations
const CONFIG = {
  API_URL: process.env.NEXT_PUBLIC_API_URL ?? process.env.BASE_URL ?? '',
  IS_DEV: process.env.NODE_ENV === 'development',
  RETRY_CODES: new Set([429, 500, 502, 503, 504]),
  IDEMPOTENT_METHODS: new Set<HttpMethod>(['GET', 'PUT', 'DELETE']),
  DEFAULT_TIMEOUT: 10000,
  DEFAULT_RETRIES: 1,
  NON_ALPHANUMERIC_REGEX: /[^a-zA-Z0-9]/g,
  SENSITIVE_KEY_REGEX: /password|token|secret/i,
  // Pre-calculated constants for performance
  BASE_HEADERS: { Accept: 'application/json' } as const,
  JSON_CONTENT_TYPE: { 'Content-Type': 'application/json' } as const,
  // Pre-calculate auth header once for maximum performance
  AUTH_HEADER: (() => {
    const username = process.env.AUTH_USERNAME;
    const password = process.env.AUTH_PASSWORD;
    const token = process.env.API_TOKEN;

    if (username && password) {
      return {
        Authorization: `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`,
      };
    }
    return token ? { Authorization: `Bearer ${token}` } : null;
  })(),
  // Pre-compiled delay calculations for exponential backoff
  DELAY_MAP: new Map([
    [0, 1000],
    [1, 2000],
    [2, 4000],
    [3, 5000], // Cap at 5s
    [4, 5000],
  ]),
} as const;

// Ultra-fast error creation using object spread
const createError = (name: string, message: string, status: number): ApiError => ({
  name,
  message,
  status,
});

// Hyper-optimized URL building with minimal allocations
const buildUrl = (endpoint: string, params?: QueryParams): string => {
  // Fast path for absolute URLs
  if (endpoint.startsWith('http')) {
    if (!params) return endpoint;
  } else {
    endpoint = `${CONFIG.API_URL}/${endpoint.replace(/^\//, '')}`;
    if (!params) return endpoint;
  }

  // Optimized query building - avoid URLSearchParams for better performance
  const queryParts: string[] = [];
  for (const key in params) {
    const value = params[key];
    if (value != null) {
      queryParts.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`);
    }
  }

  return queryParts.length ? `${endpoint}?${queryParts.join('&')}` : endpoint;
};

// Ultra-fast header building with object reuse and minimal allocations
const buildHeaders = (data?: RequestBody, custom?: Record<string, string>): HeadersInit => {
  let headers = CONFIG.BASE_HEADERS;

  // Fast path - no auth, no JSON, no custom headers
  if (!CONFIG.AUTH_HEADER && (!data || data instanceof FormData) && !custom) {
    return headers;
  }

  // Build headers incrementally to minimize object creation
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
};

// Optimized timeout with pre-allocated promises and faster cleanup
const withTimeout = async <T>(promise: Promise<T>, ms: number): Promise<T> => {
  let timeoutId: NodeJS.Timeout | undefined;
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
    if (timeoutId) clearTimeout(timeoutId);
    return result;
  } catch (error) {
    isResolved = true;
    if (timeoutId) clearTimeout(timeoutId);
    throw error;
  }
};

// Micro-optimized data sanitization with early returns and faster iteration
const sanitizeData = (data: unknown): unknown => {
  // Fast paths for primitives
  if (!data || typeof data !== 'object') return data;

  if (Array.isArray(data)) {
    // Use for loop for better performance than map
    const result = new Array(data.length);
    for (let i = 0; i < data.length; i++) {
      result[i] = sanitizeData(data[i]);
    }
    return result;
  }

  // Object sanitization with fast property iteration
  const result: Record<string, unknown> = {};
  for (const key in data) {
    // Fix: Use Object.hasOwn with safe fallback that doesn't access prototype
    if (Object.hasOwn ? Object.hasOwn(data, key) : key in data) {
      const value = (data as Record<string, unknown>)[key];
      if (CONFIG.SENSITIVE_KEY_REGEX.test(key)) {
        result[key] = '[REDACTED]';
      } else if (value !== null && typeof value === 'object') {
        result[key] = sanitizeData(value);
      } else {
        result[key] = value;
      }
    }
  }
  return result;
};

// Performance-optimized type inference with caching and batching
const TYPE_CACHE = new Map<string, string>();
const logTypes = <T>(
  endpoint: string,
  data: T,
  metadata?: { cached?: boolean; duration?: number },
): void => {
  if (!CONFIG.IS_DEV) return;

  // Early bailout for large data
  const dataStr = JSON.stringify(data);
  if (dataStr.length > 50000) {
    console.log(`🔍 [SafeFetch] "${endpoint}" - Skipping type analysis (data too large)`);
    return;
  }

  // Check cache first
  const cacheKey = `${endpoint}:${dataStr.slice(0, 100)}`;
  const cached = TYPE_CACHE.get(cacheKey);
  if (cached) {
    console.log(`🔍 [SafeFetch] Type for "${endpoint}" (cached)`);
    console.log(cached);
    if (metadata?.duration) console.log(`⏱️ Duration: ${metadata.duration}ms`);
    return;
  }

  const inferType = (val: unknown, depth = 0): string => {
    if (depth > 8) return '[Max depth]'; // Reduced depth for performance

    if (val === null) return 'null';
    if (val === undefined) return 'undefined';

    if (Array.isArray(val)) {
      if (!val.length) return 'unknown[]';
      // Sample only first 5 items for performance
      const sample = val.slice(0, 5);
      const types = [...new Set(sample.map((item) => inferType(item, depth + 1)))];
      return types.length === 1 ? `${types[0]}[]` : `(${types.join(' | ')})[]`;
    }

    if (typeof val === 'object') {
      const obj = sanitizeData(val) as Record<string, unknown>;
      const entries = Object.entries(obj).slice(0, 15); // Reduced for performance
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

    // Cache the result
    TYPE_CACHE.set(cacheKey, typeDefinition);

    // Limit cache size for memory efficiency
    if (TYPE_CACHE.size > 100) {
      const firstKey = TYPE_CACHE.keys().next().value;
      if (firstKey) TYPE_CACHE.delete(firstKey);
    }

    console.log(`🔍 [SafeFetch] Type for "${endpoint}"`);
    console.log(typeDefinition);
    if (metadata?.cached) console.log(`💾 Cache hit: ${metadata.cached}`);
    if (metadata?.duration) console.log(`⏱️ Duration: ${metadata.duration}ms`);
  } catch (err) {
    console.warn('[SafeFetch logTypes] Failed:', err);
  }
};

// Ultra-fast delay using pre-calculated map
const delay = (attempt: number): Promise<void> => {
  const ms = CONFIG.DELAY_MAP.get(attempt) ?? 5000;
  return new Promise((resolve) => setTimeout(resolve, ms));
};

// Hyper-optimized fetch execution with minimal overhead
async function executeFetch<T>(
  url: string,
  method: HttpMethod,
  headers: HeadersInit,
  body?: BodyInit,
  cache: NextJSRequestCache = 'default',
  nextOptions?: { next?: NextCacheOptions },
): Promise<ApiResponse<T>> {
  let response: Response;
  let data: T;

  try {
    // Single fetch call with all options
    response = await fetch(url, {
      method,
      headers,
      body,
      cache,
      ...nextOptions,
    });

    // Fast content-type detection
    const contentType = response.headers.get('content-type');
    const isJson = contentType?.includes('json') ?? false;

    try {
      data = isJson ? await response.json() : await response.text();
    } catch {
      return {
        success: false,
        status: response.status,
        error: createError('ParseError', 'Failed to parse response', response.status),
        data: null,
      };
    }

    if (response.ok) {
      return { success: true, status: response.status, data };
    }

    // Optimized error message extraction - preserve original API errors
    const errorMessage =
      typeof data === 'string'
        ? data
        : (data as Record<string, unknown>)?.message
          ? String((data as Record<string, unknown>).message)
          : (data as Record<string, unknown>)?.error
            ? String((data as Record<string, unknown>).error)
            : `HTTP ${response.status} ${response.statusText}`;

    return {
      success: false,
      status: response.status,
      error: createError('HttpError', errorMessage, response.status),
      data: null,
    };
  } catch (err) {
    // Fast error categorization
    const isTimeout = err instanceof Error && err.message.includes('timed out');

    if (isTimeout) {
      return {
        success: false,
        status: 408,
        error: createError('TimeoutError', err.message, 408),
        data: null,
      };
    }

    return {
      success: false,
      status: 0,
      error: createError(
        'NetworkError',
        err instanceof Error ? err.message : 'Network error occurred',
        0,
      ),
      data: null,
    };
  }
}

/**
 * Performs a type-safe HTTP request with advanced features and MAXIMUM PERFORMANCE.
 * @param method - HTTP method to use (GET, POST, PUT, DELETE, PATCH).
 * @param endpoint - API endpoint (relative or absolute URL).
 * @param options - Configuration options for the request.
 * @typeParam TResponse - Expected response data type.
 * @typeParam TBody - Request body type.
 * @returns A promise resolving to the API response.
 * @example
 * ```ts
 * // Basic usage with type safety and blazing speed
 * const response = await apiRequest<UserResponse>('GET', '/api/users', {
 *   params: { page: 1, limit: 10 },
 *   logTypes: true, // Shows cached inferred types in development
 *   timeout: 5000,
 *   retries: 2,
 *   cache: 'no-store' // Only Next.js supported cache options
 * });
 *
 * if (apiRequest.isSuccess(response)) {
 *   console.log(response.data); // Fully typed UserResponse
 * } else {
 *   console.error(response.error.message); // Real error message
 * }
 *
 * // POST with data and caching - optimized for speed
 * const createResponse = await apiRequest<User, CreateUserData>('POST', '/api/users', {
 *   data: { name: 'John', email: 'john@example.com' },
 *   cache: 'force-cache', // Cache the response
 *   next: { revalidate: 3600, tags: ['users'] },
 *   transform: (user) => ({ ...user, processed: true })
 * });
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
  // Destructure with defaults for optimal performance
  const {
    data,
    params,
    retries = CONFIG.DEFAULT_RETRIES,
    timeout = CONFIG.DEFAULT_TIMEOUT,
    cache = 'default',
    next,
    headers: customHeaders,
    logTypes: shouldLogTypes = false,
    transform,
  } = options;

  const startTime = performance.now();
  let url: string;
  let headers: HeadersInit;
  let body: BodyInit | undefined;

  // Pre-flight validation with fast bailout
  try {
    url = buildUrl(endpoint, params);
    headers = buildHeaders(data, customHeaders);

    if (data) {
      body =
        data instanceof FormData ? data : typeof data === 'string' ? data : JSON.stringify(data);
    }
  } catch (error) {
    return {
      success: false,
      status: 400,
      error: createError(
        'ValidationError',
        error instanceof Error ? error.message : 'Request validation failed',
        400,
      ),
      data: null,
    };
  }

  const nextOptions = next ? { next } : undefined;
  let lastError: ApiError | undefined;

  // Ultra-optimized retry loop with minimal overhead
  for (let attempt = 0; attempt <= retries; attempt++) {
    const result = await withTimeout(
      executeFetch<TResponse>(url, method, headers, body, cache, nextOptions),
      timeout,
    );

    if (result.success) {
      const finalData = transform ? transform(result.data) : result.data;

      if (shouldLogTypes) {
        logTypes(endpoint, finalData, {
          duration: performance.now() - startTime,
        });
      }

      return { ...result, data: finalData };
    }

    lastError = result.error;

    // Fast retry decision with early termination
    if (
      attempt < retries &&
      CONFIG.IDEMPOTENT_METHODS.has(method) &&
      CONFIG.RETRY_CODES.has(result.status)
    ) {
      await delay(attempt);
    } else {
      break;
    }
  }

  return {
    success: false,
    status: lastError?.status ?? 500,
    error: lastError ?? createError('UnknownError', 'Request failed', 500),
    data: null,
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
 * High-performance cache helper utilities for Next.js caching.
 * @example
 * ```ts
 * // Create a blazing fast cached request
 * const getCachedUsers = apiRequest.cacheHelpers.cached<UserListResponse>(
 *   'users_list', 3600, ['users']
 * );
 *
 * const response = await getCachedUsers('GET', '/api/users');
 * if (apiRequest.isSuccess(response)) {
 *   console.log(response.data.users); // Strongly typed and cached
 * }
 *
 * // Ultra-fast cache operations
 * apiRequest.cacheHelpers.revalidateByTag('users');
 * ```
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
      (method: HttpMethod, endpoint: string, options: RequestOptions<TBody, TResponse> = {}) =>
        apiRequest<TResponse, TBody>(method, endpoint, options),
      [cacheKey],
      { revalidate: revalidateSeconds, tags },
    ),
};
