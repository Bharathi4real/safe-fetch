/**
 * SafeFetch – Typed Fetch Utility for Next.js
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * Optimized for Next.js 14.x.x & 15.x.x
 *
 * A robust, type-safe HTTP client for Next.js with advanced caching, retry logic,
 * and error handling. Provides excellent IntelliSense and autocomplete support.
 */

'use server';

import { revalidatePath, revalidateTag, unstable_cache } from 'next/cache';
import { fetch as nextFetch } from 'next/dist/compiled/@edge-runtime/primitives/fetch';

// Define HTTP methods with stricter type safety
const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] as const;

/** HTTP methods supported by SafeFetch. */
export type HttpMethod = typeof HTTP_METHODS[number];

/** Request body types: JSON object, FormData, string, or null. */
export type RequestBody = Record<string, unknown> | FormData | string | null;

/** Query parameters as key-value pairs施

/** Query parameters as key-value pairs. */
export type QueryParams = Record<string, string | number | boolean | null | undefined>;

/**
 * Cache configuration for Next.js caching.
 * @property revalidate - Cache revalidation time in seconds or false to disable.
 * @property tags - Cache tags for targeted revalidation.
 * @property key - Unique cache key for the request.
 */
export interface NextCacheOptions {
  revalidate?: number | false;
  tags?: string[];
  key?: string;
}

/**
 * Request configuration options.
 * @typeParam TBody - Type of the request body.
 * @typeParam TResponse - Type of the response data.
 * @property data - Request body data (JSON, FormData, or string).
 * @property params - Query parameters to append to the URL.
 * @property retries - Number of retry attempts for failed requests.
 * @property timeout - Request timeout in milliseconds.
 * @property cache - Cache mode for the request.
 * @property next - Next.js cache configuration.
 * @property headers - Custom HTTP headers.
 * @property logTypes - Log inferred TypeScript types in development mode.
 * @property transform - Transform response data before returning.
 * @property onError - Callback for handling errors during retries.
 */
export interface RequestOptions<TBody extends RequestBody = RequestBody, TResponse = unknown> {
  data?: TBody;
  params?: QueryParams;
  retries?: number;
  timeout?: number;
  cache?: RequestCache;
  next?: NextCacheOptions;
  headers?: Record<string, string>;
  logTypes?: boolean;
  transform?: <T = TResponse, R = TResponse>(data: T) => R;
  onError?: (error: ApiError, attempt: number) => void;
}

/**
 * Error object for failed requests.
 * @property name - Error type (e.g., HttpError, NetworkError).
 * @property message - Descriptive error message.
 * @property status - HTTP status code.
 * @property attempt - Current retry attempt number.
 * @property context - Additional error context.
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
    stack?: string;
  };
}

/**
 * Response object for API requests.
 * @typeParam T - Type of the response data.
 */
export type ApiResponse<T = unknown> =
  | {
      success: true;
      status: number;
      data: T;
      headers: Headers;
      cache?: { hit: boolean; key?: string };
    }
  | {
      success: false;
      status: number;
      error: ApiError;
      data: null;
    };

// Configuration with secure defaults
const CONFIG = {
  API_URL: process.env.NEXT_PUBLIC_API_URL ?? process.env.BASE_URL ?? '',
  IS_DEV: process.env.NODE_ENV === 'development',
  RETRY_CODES: new Set<number>([429, 500, 502, 503, 504]),
  IDEMPOTENT_METHODS: new Set<HttpMethod>(['GET', 'PUT', 'DELETE']),
  MAX_CONCURRENT: 10,
  DEFAULT_TIMEOUT: 30000,
  DEFAULT_RETRIES: 1,
};

// Secure auth header generation
const getAuthHeader = (): string | undefined => {
  const { AUTH_USERNAME, AUTH_PASSWORD, API_TOKEN } = process.env;
  if (!AUTH_USERNAME && !AUTH_PASSWORD && !API_TOKEN) {
    if (CONFIG.IS_DEV) console.warn('[SafeFetch] No authentication credentials provided');
    return undefined;
  }
  if (AUTH_USERNAME && AUTH_PASSWORD) {
    return `Basic ${Buffer.from(`${AUTH_USERNAME}:${AUTH_PASSWORD}`, 'utf8').toString('base64')}`;
  }
  return API_TOKEN ? `Bearer ${API_TOKEN}` : undefined;
};

// Utility to create ApiError with stack trace in dev mode
const createApiError = (
  name: string,
  message: string,
  status: number,
  attempt?: number,
  context?: Omit<ApiError['context'], 'timestamp'>,
): ApiError => ({
  name,
  message,
  status,
  attempt,
  context: {
    timestamp: Date.now(),
    ...context,
    ...(CONFIG.IS_DEV && { stack: new Error().stack }),
  },
});

// Build URL with sanitization
const buildUrl = (endpoint: string, params?: QueryParams): string => {
  try {
    const base = endpoint.startsWith('http://') || endpoint.startsWith('https://')
      ? endpoint
      : `${CONFIG.API_URL.replace(/\/+$/, '')}/${endpoint.replace(/^\//, '')}`;

    const url = new URL(base);
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== null && value !== undefined) {
          url.searchParams.append(key, String(value));
        }
      });
    }
    return url.toString();
  } catch (error) {
    throw createApiError(
      'URLError',
      `URL construction failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      400,
      undefined,
      { url: '[REDACTED]' },
    );
  }
};

// Build headers with secure handling
const buildHeaders = (data?: RequestBody, custom?: Record<string, string>): HeadersInit => {
  const authHeader = getAuthHeader();
  return {
    Accept: 'application/json',
    ...(authHeader && { Authorization: authHeader }),
    ...(data && !(data instanceof FormData) && { 'Content-Type': 'application/json' }),
    ...custom,
  };
};

// Parse response with type safety
const parseResponse = async <T>(response: Response): Promise<T> => {
  const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
  if (contentType.includes('application/json')) {
    return (await response.json()) as T;
  }
  return (await response.text()) as T;
};

// Create timeout with AbortController
const createTimeout = (ms: number): { controller: AbortController; cleanup: () => void } => {
  const controller = new AbortController();
  let cleaned = false;
  const timeoutId = setTimeout(() => {
    if (!cleaned) controller.abort(new Error('Request timeout'));
  }, ms);
  return {
    controller,
    cleanup: () => {
      cleaned = true;
      clearTimeout(timeoutId);
    },
  };
};

// Exponential backoff with jitter
const delay = (attempt: number): Promise<void> => {
  const ms = Math.min(1000 * 2 ** attempt, 10000) + Math.random() * 100;
  return new Promise((resolve) => setTimeout(resolve, ms));
};

// Retry logic
const shouldRetryRequest = (
  error: ApiError,
  attempt: number,
  maxRetries: number,
  method: HttpMethod,
): boolean =>
  attempt < maxRetries &&
  CONFIG.IDEMPOTENT_METHODS.has(method) &&
  (error.name === 'AbortError' || CONFIG.RETRY_CODES.has(error.status));

// Sanitize sensitive data in logs
const sanitizeData = (data: unknown): unknown => {
  if (!data || typeof data !== 'object') return data;
  if (Array.isArray(data)) return data.map(sanitizeData);
  const result = { ...data } as Record<string, unknown>;
  for (const [key, value] of Object.entries(result)) {
    if (/password|token|secret/i.test(key)) {
      result[key] = '[REDACTED]';
    } else if (typeof value === 'object') {
      result[key] = sanitizeData(value);
    }
  }
  return result;
};

// Log types in development mode
const logTypes = <T>(
  endpoint: string,
  data: T,
  metadata?: { cached?: boolean; duration?: number },
): void => {
  if (!CONFIG.IS_DEV) return;

  if (JSON.stringify(data).length > 50000) {
    console.log(`🔍 [SafeFetch] "${endpoint}" - Skipping type analysis (data too large)`);
    return;
  }

  const inferType = (val: unknown, depth = 0, indent = ''): string => {
    if (depth > 20) return '[Max depth reached]';
    if (val === null) return 'null';
    if (val === undefined) return 'undefined';
    if (Array.isArray(val)) {
      if (!val.length) return 'unknown[]';
      const types = [
        ...new Set(
          val.map((item) => inferType(item, depth + 1, `${indent}  `))
        ),
      ];
      return types.length === 1 ? `${types[0]}[]` : `(${types.join(' | ')})[]`;
    }
    if (typeof val === 'object' && val !== null) {
      const obj = sanitizeData(val) as Record<string, unknown>;
      const entries = Object.entries(obj);
      const props = entries
        .map(
          ([key, value]) =>
            `${indent}  ${key}: ${inferType(value, depth + 1, `${indent}  `)};`,
        )
        .join('\n');
      return `{\n${props}\n${indent}}`;
    }
    return typeof val;
  };
  try {
    const typeName = endpoint.replace(/[^a-zA-Z0-9]/g, '_') || 'ApiResponse';
    console.log(`🔍 [SafeFetch] Type for "${endpoint}"`);
    console.log(`type ${typeName}Response = ${inferType(data)};`);
    if (metadata?.cached) console.log(`💾 Cache hit: ${metadata.cached}`);
    if (metadata?.duration) console.log(`⏱️ Duration: ${metadata.duration}ms`);
  } catch (err) {
    console.warn('[SafeFetch logTypes] Failed:', err);
  }
};

// Concurrent request limiter
const requestQueue = new Set<Promise<unknown>>();
const limitConcurrentRequests = async <T>(request: () => Promise<T>): Promise<T> => {
  if (requestQueue.size >= CONFIG.MAX_CONCURRENT) {
    await Promise.race(requestQueue);
  }
  const promise = request();
  requestQueue.add(promise);
  try {
    return await promise;
  } finally {
    requestQueue.delete(promise);
  }
};

// Execute fetch with strict typing
async function executeFetch<TResponse>(
  url: string,
  method: HttpMethod,
  headers: HeadersInit,
  body: BodyInit | undefined,
  cache: RequestCache,
  timeout: number,
  nextOptions: { next?: NextCacheOptions },
  attempt: number,
): Promise<ApiResponse<TResponse>> {
  return limitConcurrentRequests(async () => {
    const timeoutController = createTimeout(timeout);
    try {
      const response = await nextFetch(url, {
        method,
        headers,
        body,
        cache,
        signal: timeoutController.controller.signal,
        ...nextOptions,
      });

      timeoutController.cleanup();
      const data = await parseResponse<TResponse>(response);

      if (response.ok) {
        return {
          success: true,
          data,
          status: response.status,
          headers: response.headers,
          cache: {
            hit:
              response.headers.get('x-cache-status') === 'hit' ||
              response.headers.get('cf-cache-status') === 'HIT',
          },
        };
      }

      return {
        success: false,
        error: createApiError('HttpError', `HTTP ${response.status}`, response.status, attempt, {
          url: '[REDACTED]',
          method,
        }),
        status: response.status,
        data: null,
      };
    } catch (err) {
      timeoutController.cleanup();
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      return {
        success: false,
        error: createApiError('NetworkError', errorMessage, 500, attempt, {
          url: '[REDACTED]',
          method,
        }),
        status: 500,
        data: null,
      };
    }
  });
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
 * // Comprehensive example using all available options
 * const response = await apiRequest<
 *   { id: number; name: string; email: string }, // Response type
 *   { name: string; email: string } // Body type
 * >(
 *   'POST',
 *   '/api/users',
 *   {
 *     data: { name: 'John Doe', email: 'john@example.com' }, // Request body
 *     params: { role: 'admin', active: true }, // Query parameters
 *     retries: 3, // Retry up to 3 times
 *     timeout: 10000, // 10-second timeout
 *     cache: 'no-store', // Cache mode
 *     next: { revalidate: 3600, tags: ['users'], key: 'user-create' }, // Next.js cache options
 *     headers: { 'X-Custom-Header': 'value' }, // Custom headers
 *     logTypes: true, // Log inferred types in development
 *     transform: (data) => ({ // Transform response data
 *       ...data,
 *       name: data.name.toUpperCase(),
 *     }),
 *     onError: (error, attempt) => { // Error handling callback
 *       console.error(`Attempt ${attempt + 1} failed: ${error.message}`);
 *     },
 *   }
 * );
 *
 * if (apiRequest.isSuccess(response)) {
 *   console.log(response.data); // Strongly typed: { id: number; name: string; email: string }
 * } else {
 *   console.error(response.error.message); // Access error details
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
  if (!HTTP_METHODS.includes(method)) {
    const error = createApiError('ValidationError', `Invalid HTTP method: ${method}`, 400, undefined, {
      url: '[REDACTED]',
    });
    return { success: false, status: 400, error, data: null };
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
    onError,
  } = options;

  const startTime = Date.now();
  let url: string, headers: HeadersInit, body: BodyInit | undefined;

  try {
    url = buildUrl(endpoint, params);
    headers = buildHeaders(data, customHeaders);
    body = data
      ? data instanceof FormData
        ? data
        : typeof data === 'string'
        ? data
        : JSON.stringify(data)
      : undefined;
  } catch (error) {
    const apiError = createApiError(
      'ValidationError',
      `Request validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      400,
      undefined,
      { url: '[REDACTED]', method },
    );
    return { success: false, status: 400, error: apiError, data: null };
  }

  const nextOptions = nextCacheOptions ? { next: nextCacheOptions } : {};

  let lastError: ApiError | undefined;
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
    );

    if (result.success) {
      const finalData = transform ? transform(result.data) : result.data;
      if (shouldLogTypes) {
        logTypes(endpoint, finalData, {
          cached: result.cache?.hit,
          duration: Date.now() - startTime,
        });
      }
      return { ...result, data: finalData };
    }

    lastError = result.error;
    onError?.(lastError, attempt);
    if (!shouldRetryRequest(lastError, attempt, retries, method)) break;
    if (attempt < retries) await delay(attempt);
  }

  return { success: false, status: lastError!.status, error: lastError!, data: null };
}

/**
 * Type guard to check if the response is successful.
 * @param response - The API response to check.
 * @returns True if the response is successful.
 */
apiRequest.isSuccess = <T>(
  response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: true }> => response.success;

/**
 * Type guard to check if the response is an error.
 * @param response - The API response to check.
 * @returns True if the response is an error.
 */
apiRequest.isError = <T>(
  response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: false }> => !response.success;

/**
 * Cache helper utilities for Next.js caching.
 * @property revalidateByTag - Revalidate cache by tag.
 * @property revalidateByPath - Revalidate cache by path.
 * @property cached - Wrap apiRequest with Next.js unstable_cache.
 * @example
 * ```ts
 * // Create a cached request
 * const getCachedUsers = apiRequest.cacheHelpers.cached<
 *   { users: { id: number; name: string }[] }
 * >('users_cache_key', 3600, ['users']);
 *
 * const response = await getCachedUsers('GET', '/api/users');
 * if (apiRequest.isSuccess(response)) {
 *   console.log(response.data.users); // Strongly typed
 * }
 *
 * // Revalidate cache
 * apiRequest.cacheHelpers.revalidateByTag('users');
 * ```
 */
apiRequest.cacheHelpers = {
  revalidateByTag: revalidateTag,
  revalidateByPath: revalidatePath,
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
