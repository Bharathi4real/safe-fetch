 * SafeFetch – High-Performance Typed Fetch Utility for Next.js
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * for Next.js 14.x.x & 15.x.x
 *
 * A robust, type-safe HTTP client for Next.js with advanced caching, retry logic,
 * error handling, and type inference logging. Optimized for maximum performance.
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

// Optimized configuration with pre-calculated values
const CONFIG = {
  API_URL: process.env.NEXT_PUBLIC_API_URL ?? process.env.BASE_URL ?? '',
  IS_DEV: process.env.NODE_ENV === 'development',
  RETRY_CODES: new Set([429, 500, 502, 503, 504]),
  IDEMPOTENT_METHODS: new Set<HttpMethod>(['GET', 'PUT', 'DELETE']),
  DEFAULT_TIMEOUT: 10000,
  DEFAULT_RETRIES: 1,
  NON_ALPHANUMERIC_REGEX: /[^a-zA-Z0-9]/g,
  SENSITIVE_KEY_REGEX: /password|token|secret/i,
  // Pre-calculate auth header once for performance
  AUTH_HEADER: (() => {
    const username = process.env.AUTH_USERNAME;
    const password = process.env.AUTH_PASSWORD;
    const token = process.env.API_TOKEN;

    if (username && password) {
      return `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
    }
    return token ? `Bearer ${token}` : undefined;
  })(),
} as const;

// Simplified error creation
const createError = (name: string, message: string, status: number): ApiError => ({
  name,
  message,
  status,
});

// Fast URL building
const buildUrl = (endpoint: string, params?: QueryParams): string => {
  let url = endpoint.startsWith('http')
    ? endpoint
    : `${CONFIG.API_URL}/${endpoint.replace(/^\//, '')}`;

  if (params) {
    const searchParams = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (value != null) searchParams.append(key, String(value));
    }
    const query = searchParams.toString();
    if (query) url += `?${query}`;
  }

  return url;
};

// Optimized header building
const buildHeaders = (data?: RequestBody, custom?: Record<string, string>): HeadersInit => {
  const headers: Record<string, string> = { Accept: 'application/json' };

  if (CONFIG.AUTH_HEADER) headers.Authorization = CONFIG.AUTH_HEADER;
  if (data && !(data instanceof FormData)) headers['Content-Type'] = 'application/json';
  if (custom) Object.assign(headers, custom);

  return headers;
};

// Simple timeout with proper error handling
const withTimeout = async <T>(promise: Promise<T>, ms: number): Promise<T> => {
  let timeoutId: NodeJS.Timeout | undefined;

  const timeoutPromise = new Promise<never>((_, reject) => {
    timeoutId = setTimeout(() => {
      reject(createError('TimeoutError', `Request timed out after ${ms}ms`, 408));
    }, ms);
  });

  try {
    const result = await Promise.race([promise, timeoutPromise]);
    if (timeoutId) clearTimeout(timeoutId);
    return result;
  } catch (error) {
    if (timeoutId) clearTimeout(timeoutId);
    throw error;
  }
};

// Data sanitization for logTypes
const sanitizeData = (data: unknown): unknown => {
  if (!data || typeof data !== 'object') return data;
  if (Array.isArray(data)) return data.map(sanitizeData);

  const result = { ...data } as Record<string, unknown>;
  for (const [key, value] of Object.entries(result)) {
    if (CONFIG.SENSITIVE_KEY_REGEX.test(key)) {
      result[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      result[key] = sanitizeData(value);
    }
  }
  return result;
};

// Type inference logging - exactly as before
const logTypes = <T>(
  endpoint: string,
  data: T,
  metadata?: { cached?: boolean; duration?: number },
): void => {
  if (!CONFIG.IS_DEV) return;

  const dataStr = JSON.stringify(data);
  if (dataStr.length > 50000) {
    console.log(`🔍 [SafeFetch] "${endpoint}" - Skipping type analysis (data too large)`);
    return;
  }

  const inferType = (val: unknown, depth = 0): string => {
    if (depth > 10) return '[Max depth reached]';

    if (val === null) return 'null';
    if (val === undefined) return 'undefined';

    if (Array.isArray(val)) {
      if (!val.length) return 'unknown[]';
      const types = [...new Set(val.slice(0, 10).map((item) => inferType(item, depth + 1)))];
      return types.length === 1 ? `${types[0]}[]` : `(${types.join(' | ')})[]`;
    }

    if (typeof val === 'object') {
      const obj = sanitizeData(val) as Record<string, unknown>;
      const entries = Object.entries(obj).slice(0, 20);
      const props = entries
        .map(([key, value]) => `  ${key}: ${inferType(value, depth + 1)};`)
        .join('\n');
      return `{\n${props}\n}`;
    }

    return typeof val;
  };

  try {
    const typeName = endpoint.replace(CONFIG.NON_ALPHANUMERIC_REGEX, '_') || 'ApiResponse';
    console.log(`🔍 [SafeFetch] Type for "${endpoint}"`);
    console.log(`type ${typeName}Response = ${inferType(data)};`);
    if (metadata?.cached) console.log(`💾 Cache hit: ${metadata.cached}`);
    if (metadata?.duration) console.log(`⏱️ Duration: ${metadata.duration}ms`);
  } catch (err) {
    console.warn('[SafeFetch logTypes] Failed:', err);
  }
};

// Exponential backoff delay
const delay = (attempt: number) =>
  new Promise((resolve) => setTimeout(resolve, Math.min(1000 * 2 ** attempt, 5000)));

// Core fetch function with proper error details
async function executeFetch<T>(
  url: string,
  method: HttpMethod,
  headers: HeadersInit,
  body?: BodyInit,
  cache: NextJSRequestCache = 'default',
  nextOptions?: { next?: NextCacheOptions },
): Promise<ApiResponse<T>> {
  try {
    const response = await fetch(url, {
      method,
      headers,
      body,
      cache,
      ...nextOptions,
    });

    const contentType = response.headers.get('content-type') || '';
    let data: T;

    try {
      data = contentType.includes('json') ? await response.json() : await response.text();
    } catch (_parseError) {
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

    // Return actual HTTP error with response data if available
    const errorMessage =
      typeof data === 'string'
        ? data
        : data && typeof data === 'object' && 'message' in data
          ? String(data.message)
          : `HTTP ${response.status} ${response.statusText}`;

    return {
      success: false,
      status: response.status,
      error: createError('HttpError', errorMessage, response.status),
      data: null,
    };
  } catch (err) {
    // Network errors, timeouts, etc.
    if (err instanceof Error && err.message.includes('timed out')) {
      return {
        success: false,
        status: 408,
        error: createError('TimeoutError', err.message, 408),
        data: null,
      };
    }

    const errorMessage = err instanceof Error ? err.message : 'Network error occurred';
    return {
      success: false,
      status: 0, // Network error
      error: createError('NetworkError', errorMessage, 0),
      data: null,
    };
  }
}

/**
 * Performs a type-safe HTTP request with advanced features.
 * @param method - HTTP method to use (GET, POST, PUT, DELETE, PATCH).
 * @param endpoint - API endpoint (relative or absolute URL).
 * @param options - Configuration options for the request.
 * @typeParam TResponse - Expected response data type.
 * @typeParam TBody - Request body type.
 * @returns A promise resolving to the API response.
 * @example
 * ```ts
 * // Basic usage with type safety
 * const response = await apiRequest<UserResponse>('GET', '/api/users', {
 *   params: { page: 1, limit: 10 },
 *   logTypes: true, // Shows inferred types in development
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
 * // POST with data and caching
 * const createResponse = await apiRequest<User, CreateUserData>('POST', '/api/users', {
 *   data: { name: 'John', email: 'john@example.com' },
 *   cache: 'force-cache', // Cache the response
 *   next: { revalidate: 3600, tags: ['users'] },
 *   transform: (user) => ({ ...user, processed: true })
 * });
 *
 * // Different cache strategies
 * const freshData = await apiRequest('GET', '/api/real-time-data', {
 *   cache: 'no-store' // Always fetch fresh data
 * });
 *
 * const cachedData = await apiRequest('GET', '/api/static-data', {
 *   cache: 'force-cache', // Use cache if available
 *   next: { revalidate: 86400 } // Revalidate daily
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

  try {
    url = buildUrl(endpoint, params);
    headers = buildHeaders(data, customHeaders);

    if (data) {
      body =
        data instanceof FormData ? data : typeof data === 'string' ? data : JSON.stringify(data);
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Request validation failed';
    return {
      success: false,
      status: 400,
      error: createError('ValidationError', errorMessage, 400),
      data: null,
    };
  }

  const nextOptions = next ? { next } : undefined;
  let lastError: ApiError | undefined;

  // Retry loop
  for (let attempt = 0; attempt <= retries; attempt++) {
    const fetchPromise = executeFetch<TResponse>(url, method, headers, body, cache, nextOptions);
    const result = await withTimeout(fetchPromise, timeout);

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

    // Should retry?
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
 * Type guard to check if the response is successful.
 */
apiRequest.isSuccess = <T>(
  response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: true }> => response.success;

/**
 * Type guard to check if the response is an error.
 */
apiRequest.isError = <T>(
  response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: false }> => !response.success;

/**
 * Cache helper utilities for Next.js caching.
 * @example
 * ```ts
 * // Create a cached request
 * const getCachedUsers = apiRequest.cacheHelpers.cached<UserListResponse>(
 *   'users_list', 3600, ['users']
 * );
 *
 * const response = await getCachedUsers('GET', '/api/users');
 * if (apiRequest.isSuccess(response)) {
 *   console.log(response.data.users); // Strongly typed
 * }
 *
 * // Revalidate cache
 * apiRequest.cacheHelpers.revalidateByTag('users');
 *
 * // Different cache strategies with helpers
 * const getStaticData = apiRequest.cacheHelpers.cached<StaticData>(
 *   'static_data', 86400, ['static'] // Cache for 24 hours
 * );
 *
 * const getRealTimeData = apiRequest.cacheHelpers.cached<RealTimeData>(
 *   'realtime_data', 60, ['realtime'] // Cache for 1 minute
 * );
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

