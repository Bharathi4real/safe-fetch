/**
 * SafeFetch – Next.js 15 Optimized Typed Fetch Utility
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * Optimized for Next.js 15 with backward compatibility
 */

'use server';

import { revalidatePath, revalidateTag, unstable_cache } from 'next/cache';
import { fetch as nextFetch } from 'next/dist/compiled/@edge-runtime/primitives/fetch';

// Define HTTP methods as a const array for better type safety
const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] as const;
export type HttpMethod = typeof HTTP_METHODS[number];

export type RequestBody = Record<string, unknown> | FormData | string | null;
export type QueryParams = Record<string, string | number | boolean | null | undefined>;

// Extend Next.js cache options with stricter typing
export interface NextCacheOptions {
  revalidate?: number | false;
  tags?: string[];
  key?: string;
}

// Define RequestOptions with strict generic constraints, removed baseUrl
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

// Define ApiError with immutable properties and context
export interface ApiError {
  readonly name: string;
  readonly message: string;
  readonly status: number;
  readonly attempt?: number;
  readonly context?: {
    url?: string;
    method?: HttpMethod;
    timestamp: number;
  };
}

// Define ApiResponse with discriminated union for better type narrowing
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
const BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? process.env.BASE_URL ?? '';
const IS_DEV = process.env.NODE_ENV === 'development';
const RETRY_CODES = new Set<number>([429, 500, 502, 503, 504]);
const IDEMPOTENT_METHODS = new Set<HttpMethod>(['GET', 'PUT', 'DELETE']);
const AUTH_HEADER = (() => {
  const { AUTH_USERNAME, AUTH_PASSWORD, API_TOKEN } = process.env;
  if (AUTH_USERNAME && AUTH_PASSWORD) {
    const credentials = Buffer.from(`${AUTH_USERNAME}:${AUTH_PASSWORD}`, 'utf8').toString('base64');
    return `Basic ${credentials}`;
  }
  return API_TOKEN ? `Bearer ${API_TOKEN}` : undefined;
})();

// Utility to create ApiError with strict typing
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
  context: { timestamp: Date.now(), ...context },
});

// Build URL with strict error handling, supporting absolute URLs
const buildUrl = (endpoint: string, params?: QueryParams): string => {
  try {
    // If endpoint is an absolute URL, use it directly; otherwise, combine with DEFAULT_BASE_URL
    const base = endpoint.startsWith('http://') || endpoint.startsWith('https://')
      ? endpoint
      : `${BASE_URL.replace(/\/+$/, '')}/${endpoint.replace(/^\//, '')}`;
    
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
      { url: endpoint },
    );
  }
};

// Build headers with type-safe handling of FormData
const buildHeaders = (data?: RequestBody, custom?: Record<string, string>): HeadersInit => {
  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...(AUTH_HEADER && { Authorization: AUTH_HEADER }),
    ...(data && !(data instanceof FormData) && { 'Content-Type': 'application/json' }),
    ...custom,
  };
  return headers;
};

// Parse response with generic type
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

// Exponential backoff delay
const delay = (attempt: number): Promise<void> => {
  const ms = Math.min(1000 * 2 ** attempt, 10000) + Math.random() * 100;
  return new Promise((resolve) => setTimeout(resolve, ms));
};

// Determine if retry is needed
const shouldRetryRequest = (
  error: ApiError,
  attempt: number,
  maxRetries: number,
  method: HttpMethod,
): boolean =>
  attempt < maxRetries &&
  IDEMPOTENT_METHODS.has(method) &&
  (error.name === 'AbortError' || RETRY_CODES.has(error.status));

// Log type inference in development mode
const logTypes = <T>(
  endpoint: string,
  data: T,
  metadata?: { cached?: boolean; duration?: number },
): void => {
  if (!IS_DEV) return;

  const inferType = (val: unknown, depth = 0, indent = ''): string => {
    if (val === null) return 'null';
    if (val === undefined) return 'undefined';

    if (Array.isArray(val)) {
      if (!val.length) return 'unknown[]';
      const types = [...new Set(val.slice(0, 10).map((item) => inferType(item, depth + 1, indent + '  ')))];
      return types.length === 1 ? `${types[0]}[]` : `(${types.join(' | ')})[]`;
    }

    if (typeof val === 'object' && val !== null) {
      const obj = val as Record<string, unknown>;
      const entries = Object.entries(obj).slice(0, 30);
      const props = entries
        .map(([key, value]) =>
          `${indent}  ${key}: ${/password|token|secret/i.test(key) ? 'string /* redacted */' : inferType(value, depth + 1, indent + '  ')};`,
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
        url,
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
      error: createApiError('NetworkError', errorMessage, 500, attempt, { url, method }),
      status: 500,
      data: null,
    };
  }
}

// Main apiRequest function with strict generics
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
    retries = 1,
    timeout = 30000,
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
      { url: endpoint, method },
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

// Type guard for successful responses
apiRequest.isSuccess = <T>(
  response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: true }> => response.success;

// Type guard for error responses
apiRequest.isError = <T>(
  response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: false }> => !response.success;

// Cache helpers with strict typing
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

