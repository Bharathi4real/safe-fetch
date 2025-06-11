'use server'; // Nextjs

/** Allowed HTTP methods for API calls */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';

/**
 * Request options for the API client.
 * @template T - Request body type
 */
export interface RequestOptions<T = unknown> {
  /** Request body (JSON or FormData) */
  data?: T;

  /** Query parameters (will be appended to the URL) */
  params?: Record<string, string | number | boolean>;

  /** Max retry attempts for safe methods (default: 1) */
  retries?: number;

  /** Request timeout in ms (default: 30000) */
  timeout?: number;

  /** Fetch API cache mode (default: 'default') */
  cache?: RequestCache;

  /** Next.js ISR revalidation time in seconds (false disables ISR) */
  revalidate?: number | false;

  /** Optional ISR cache tags (Next.js App Router only) */
  tags?: string[];

  /** Custom headers (merged with auth/content-type defaults) */
  headers?: Record<string, string>;
}

/**
 * API response format returned from apiRequest
 * @template T - Response body type
 */
export type ApiResponse<T = unknown> =
  | { success: true; status: number; data: T }
  | { success: false; status: number; error: string; data: null };

// Base URL from environment
const BASE = process.env.BASE_URL || '';

// Optional Basic Auth header (if env credentials are set)
const AUTH =
  process.env.AUTH_USERNAME && process.env.AUTH_PASSWORD
    ? `Basic ${btoa(`${process.env.AUTH_USERNAME}:${process.env.AUTH_PASSWORD}`)}`
    : null;

// Status codes eligible for retry
const RETRY_CODES = new Set([408, 429, 500, 502, 503, 504]);

/**
 * Builds full request URL with optional query parameters.
 */
const buildUrl = (
  endpoint: string,
  params?: Record<string, string | number | boolean>,
): string => {
  const url = new URL(endpoint, BASE);
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      url.searchParams.append(key, String(value));
    }
  }
  return url.toString();
};

/**
 * Constructs final headers for the request.
 */
const buildHeaders = (
  data?: unknown,
  headers?: Record<string, string>,
): HeadersInit => {
  const result: HeadersInit = { ...headers };
  if (AUTH) result.Authorization = AUTH;
  if (data && !(data instanceof FormData)) {
    result['Content-Type'] = 'application/json';
  }
  return result;
};

/**
 * Parses the response body into JSON or plain text fallback.
 */
const parse = async <T>(res: Response): Promise<T> => {
  const contentType = res.headers.get('content-type');
  if (contentType?.includes('application/json')) {
    try {
      return await res.json();
    } catch {
      return (await res.text()) as T;
    }
  }
  return (await res.text()) as T;
};

/**
 * Returns an AbortController and a cleanup function for timeout handling.
 */
const createController = (timeout: number) => {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);
  return { c: controller, clean: () => clearTimeout(timeoutId) };
};

/**
 * Determines whether the request should be retried.
 */
const retryable = (
  err: { name: string; status?: number; message: string },
  attempt: number,
  maxRetries: number,
  method: HttpMethod,
): boolean => {
  return (
    attempt < maxRetries &&
    ['GET', 'PUT'].includes(method) &&
    (err.name === 'AbortError' ||
      (typeof err.status === 'number' && RETRY_CODES.has(err.status)) ||
      /fetch|network|ECONNRESET/i.test(err.message))
  );
};

/**
 * Delays execution using exponential backoff strategy.
 */
const delay = (attempt: number) =>
  new Promise((res) => setTimeout(res, Math.min(1000 * 2 ** attempt, 10000)));

/**
 * Makes a typed API request with retry, timeout, and ISR support.
 *
 * @template T - Response type
 * @template D - Request body type
 * @param method - HTTP method ('GET', 'POST', etc.)
 * @param endpoint - API route relative to BASE_URL
 * @param opts - Optional settings: headers, retries, params, timeout, etc.
 *
 * @returns Promise resolving to an ApiResponse<T>
 *
 * @example
 * const result = await apiRequest<User[]>('GET', '/users');
 * if (result.success) console.log(result.data);
 */
export default async function apiRequest<T = unknown, D = unknown>(
  method: HttpMethod,
  endpoint: string,
  opts: RequestOptions<D> = {},
): Promise<ApiResponse<T>> {
  const {
    data,
    params,
    retries = 1,
    timeout = 30000,
    cache = 'default',
    revalidate,
    tags = [],
    headers,
  } = opts;

  const url = buildUrl(endpoint, params);
  const requestHeaders = buildHeaders(data, headers);

  let fallbackError: { name: string; message: string; status: number } = {
    name: 'UnknownError',
    message: 'An unexpected error occurred',
    status: 500,
  };

  for (let attempt = 0; attempt <= retries; attempt++) {
    const { c: controller, clean } = createController(timeout);
    try {
      const init: RequestInit = {
        method,
        headers: requestHeaders,
        cache,
        signal: controller.signal,
        ...(data && {
          body: data instanceof FormData ? data : JSON.stringify(data),
        }),
        ...(revalidate !== undefined || tags.length
          ? {
              next: {
                ...(revalidate !== undefined && { revalidate }),
                ...(tags.length && { tags }),
              },
            }
          : {}),
      };

      const res = await fetch(url, init);
      clean();
      const responseData = await parse<T>(res);

      if (res.ok) {
        return { success: true, status: res.status, data: responseData };
      }

      const err = {
        name: 'HttpError',
        message: `HTTP ${res.status}: ${res.statusText}`,
        status: res.status,
      };

      if (retryable(err, attempt, retries, method)) {
        await delay(attempt);
        continue;
      }

      return {
        success: false,
        status: err.status,
        error: err.message,
        data: null,
      };
    } catch (error: unknown) {
      clean();
      const err =
        error instanceof Error
          ? {
              name: error.name,
              message:
                error.name === 'AbortError'
                  ? 'Request timeout'
                  : error.message || 'Unknown error',
              status: error.name === 'AbortError' ? 408 : 500,
            }
          : {
              name: 'UnknownError',
              message: 'An unexpected error occurred',
              status: 500,
            };

      fallbackError = err;

      if (retryable(err, attempt, retries, method)) {
        await delay(attempt);
      }
    }
  }

  return {
    success: false,
    status: fallbackError.status,
    error: fallbackError.message,
    data: null,
  };
}
