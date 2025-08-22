/**
 * SafeFetch – Typed Fetch Utility for Next.js
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * for Next.js 14.x.x & 15.x.x
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
export type HttpMethod = (typeof HTTP_METHODS)[number];

/** Request body types: JSON object, FormData, string, or null. */
export type RequestBody = Record<string, unknown> | FormData | string | null;

/** Query parameters as key-value pairs. */
export type QueryParams = Record<string, string | number | boolean | null | undefined>;

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
  cache?: RequestCache;
  next?: NextCacheOptions;
  headers?: Record<string, string>;
  logTypes?: boolean;
  transform?: <T = TResponse, R = TResponse>(data: T) => R;
  onError?: (error: ApiError, attempt: number) => void;
}

/**
 * Error object for failed requests.
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

// Configuration
const CONFIG = {
  API_URL: process.env.NEXT_PUBLIC_API_URL ?? process.env.BASE_URL ?? '',
  IS_DEV: process.env.NODE_ENV === 'development',
  RETRY_CODES: new Set<number>([429, 500, 502, 503, 504]),
  IDEMPOTENT_METHODS: new Set<HttpMethod>(['GET', 'PUT', 'DELETE']),
  MAX_CONCURRENT: 10,
  DEFAULT_TIMEOUT: 30000,
  DEFAULT_RETRIES: 1,
  SENSITIVE_KEY_REGEX: /password|token|secret/i,
  NON_ALPHANUMERIC_REGEX: /[^a-zA-Z0-9]/g,
  AUTH_CREDENTIALS: {
    username: process.env.AUTH_USERNAME,
    password: process.env.AUTH_PASSWORD,
    token: process.env.API_TOKEN,
  },
} as const;

// Auth header generation
const getAuthHeader = (): string | undefined => {
  const { username, password, token } = CONFIG.AUTH_CREDENTIALS;

  if (!username && !password && !token) {
    if (CONFIG.IS_DEV) console.warn('[SafeFetch] No authentication credentials provided');
    return undefined;
  }

  if (username && password) {
    const encoded = Buffer.from(`${username}:${password}`, 'utf8').toString('base64');
    return `Basic ${encoded}`;
  }

  return token ? `Bearer ${token}` : undefined;
};

// Error creation
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

// URL building
const buildUrl = (endpoint: string, params?: QueryParams): string => {
  try {
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

// Header building
const buildHeaders = (data?: RequestBody, custom?: Record<string, string>): HeadersInit => {
  const headers: Record<string, string> = {
    Accept: 'application/json',
  };

  const authHeader = getAuthHeader();
  if (authHeader) {
    headers.Authorization = authHeader;
  }

  if (data && !(data instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
  }

  if (custom) {
    Object.assign(headers, custom);
  }

  return headers;
};

// Response parsing
const parseResponse = async <T>(response: Response): Promise<T> => {
  const contentType = response.headers.get('content-type')?.toLowerCase() || '';

  if (contentType.includes('json')) {
    return (await response.json()) as T;
  }
  return (await response.text()) as T;
};

// Timeout handling
const createTimeout = (ms: number): { controller: AbortController; cleanup: () => void } => {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => {
    controller.abort(new Error('Request timeout'));
  }, ms);

  return {
    controller,
    cleanup: () => clearTimeout(timeoutId),
  };
};

// Delay with exponential backoff
const delay = (attempt: number): Promise<void> => {
  const baseDelay = Math.min(1000 * 2 ** attempt, 10000);
  const jitteredDelay = baseDelay + Math.random() * 100;
  return new Promise((resolve) => setTimeout(resolve, jitteredDelay));
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

// Data sanitization
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

// Type inference logging
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

// Concurrent request limiting
const requestQueue = new Set<Promise<unknown>>();
const limitConcurrentRequests = async <T>(request: () => Promise<T>): Promise<T> => {
  while (requestQueue.size >= CONFIG.MAX_CONCURRENT) {
    await Promise.race(requestQueue);
  }

  const promise = request().finally(() => {
    requestQueue.delete(promise);
  });

  requestQueue.add(promise);
  return promise;
};

// Fetch execution
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

      const data = await parseResponse<TResponse>(response);

      if (response.ok) {
        const cacheStatus =
          response.headers.get('x-cache-status') || response.headers.get('cf-cache-status');
        const cacheHit = cacheStatus === 'hit' || cacheStatus === 'HIT';

        return {
          success: true,
          data,
          status: response.status,
          headers: response.headers,
          cache: { hit: cacheHit },
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
    } finally {
      timeoutController.cleanup();
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
  // Validate HTTP method
  if (!HTTP_METHODS.includes(method)) {
    const error = createApiError(
      'ValidationError',
      `Invalid HTTP method: ${method}`,
      400,
      undefined,
      {
        url: '[REDACTED]',
      },
    );
    return { success: false, status: 400, error, data: null };
  }

  // Extract options with defaults
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

    // Prepare request body
    if (data) {
      if (data instanceof FormData) {
        body = data;
      } else if (typeof data === 'string') {
        body = data;
      } else {
        body = JSON.stringify(data);
      }
    } else {
      body = undefined;
    }
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

  // Retry loop
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

    // Check if we should retry
    if (!shouldRetryRequest(lastError, attempt, retries, method)) {
      break;
    }

    if (attempt < retries) {
      await delay(attempt);
    }
  }

  return { success: false, status: lastError!.status, error: lastError!, data: null };
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
