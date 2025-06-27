/**
 * SafeFetch – Typed fetch utility with retry, timeout & Next.js support
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * https://github.com/Bharathi4real/safe-fetch
 */

'use server'; // Next.js server action

/** HTTP methods */
export type HttpMethod =
  | 'GET'
  | 'POST'
  | 'PUT'
  | 'DELETE'
  | 'PATCH'
  | 'HEAD'
  | 'OPTIONS';

/** Request body types */
export type RequestBody =
  | Record<string, unknown>
  | FormData
  | string
  | ArrayBuffer
  | Blob
  | null;

/** Query parameter types */
export type QueryParams = Record<
  string,
  string | number | boolean | null | undefined
>;

/**
 * Request options with comprehensive JSDoc for perfect IntelliSense
 * @template TBody - Request body type
 */
export interface RequestOptions<TBody extends RequestBody = RequestBody> {
  /** Request body - auto-serialized to JSON unless FormData/Blob/ArrayBuffer */
  data?: TBody;

  /** Query parameters appended to URL */
  params?: QueryParams;

  /** Max retry attempts for idempotent methods (default: 1) */
  retries?: number;

  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;

  /** Fetch cache strategy (default: 'default') */
  cache?: RequestCache;

  /** Next.js ISR revalidation time in seconds */
  revalidate?: number | false;

  /** Next.js cache tags for on-demand revalidation */
  tags?: string[];

  /** Custom headers merged with defaults */
  headers?: Record<string, string>;

  /** Log inferred TypeScript types (dev only) */
  logTypes?: boolean;

  /** Transform response data before returning */
  transform?<T>(data: T): T;

  /** Custom error handler */
  onError?: (error: ApiError, attempt: number) => void;

  /** Custom retry condition */
  shouldRetry?: (error: ApiError, attempt: number) => boolean;
}

/** Structured error information */
export interface ApiError {
  readonly name: string;
  readonly message: string;
  readonly status: number;
  readonly attempt?: number;
}

/** Type-safe API response with success/error discrimination */
export type ApiResponse<T = unknown> =
  | { success: true; status: number; data: T; headers: Headers }
  | { success: false; status: number; error: ApiError; data: null };

// Environment configuration
const BASE_URL = process.env.BASE_URL || process.env.NEXT_PUBLIC_API_URL || '';
const IS_DEV = process.env.NODE_ENV === 'development';

// Authentication setup
const AUTH_HEADER = (() => {
  if (process.env.AUTH_USERNAME && process.env.AUTH_PASSWORD) {
    return `Basic ${btoa(`${process.env.AUTH_USERNAME}:${process.env.AUTH_PASSWORD}`)}`;
  }
  if (process.env.AUTH_TOKEN || process.env.API_TOKEN) {
    return `Bearer ${process.env.AUTH_TOKEN || process.env.API_TOKEN}`;
  }
  return null;
})();

// Retry configuration
const RETRY_CODES = new Set([408, 429, 500, 502, 503, 504]);
const IDEMPOTENT_METHODS = new Set<HttpMethod>([
  'GET',
  'PUT',
  'DELETE',
  'HEAD',
  'OPTIONS',
]);

/** Build request URL with query parameters */
const buildUrl = (endpoint: string, params?: QueryParams): string => {
  const url = new URL(
    endpoint.startsWith('/') ? endpoint : `/${endpoint}`,
    BASE_URL,
  );
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (value != null) url.searchParams.append(key, String(value));
    });
  }
  return url.toString();
};

/** Build request headers with content-type detection */
const buildHeaders = (
  data?: RequestBody,
  custom?: Record<string, string>,
): HeadersInit => {
  const headers: Record<string, string> = { ...custom };

  if (AUTH_HEADER) headers.Authorization = AUTH_HEADER;
  if (
    data &&
    !(data instanceof FormData) &&
    !(data instanceof Blob) &&
    !(data instanceof ArrayBuffer)
  ) {
    headers['Content-Type'] = 'application/json';
  }
  if (!headers.Accept) headers.Accept = 'application/json, text/plain, */*';

  return headers;
};

/** Parse response with intelligent content-type handling */
const parseResponse = async <T>(response: Response): Promise<T> => {
  const contentType = response.headers.get('content-type') || '';

  if (contentType.includes('application/json')) {
    return await response.json();
  }

  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    return text as T;
  }
};

/** Create timeout controller with cleanup */
const createTimeout = (ms: number) => {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), ms);
  return { controller, cleanup: () => clearTimeout(id) };
};

/** Check if request should be retried */
const shouldRetry = (
  error: ApiError,
  attempt: number,
  maxRetries: number,
  method: HttpMethod,
  customRetry?: (error: ApiError, attempt: number) => boolean,
): boolean => {
  if (customRetry) return attempt < maxRetries && customRetry(error, attempt);

  return (
    attempt < maxRetries &&
    IDEMPOTENT_METHODS.has(method) &&
    (error.name === 'AbortError' ||
      RETRY_CODES.has(error.status) ||
      /network|fetch|connection/i.test(error.message))
  );
};

/** Exponential backoff with jitter */
const delay = (attempt: number) => {
  const ms = Math.min(1000 * Math.pow(2, attempt), 10000);
  const jitter = ms * 0.25 * (Math.random() - 0.5);
  return new Promise((resolve) => setTimeout(resolve, ms + jitter));
};

/** Log inferred TypeScript types (dev only) */
const logTypes = (endpoint: string, data: unknown): void => {
  if (!IS_DEV) return;

  const inferType = (val: unknown): string => {
    if (val === null) return 'null';
    if (Array.isArray(val))
      return val.length ? `${inferType(val[0])}[]` : 'unknown[]';
    if (typeof val === 'object') {
      const obj = val as Record<string, unknown>;
      const props = Object.entries(obj)
        .map(([k, v]) => `  ${k}: ${inferType(v)};`)
        .join('\n');
      return `{\n${props}\n}`;
    }
    return typeof val;
  };

  const typeName =
    endpoint
      .split(/[\/\-]/)
      .filter(Boolean)
      .map((s) => s.charAt(0).toUpperCase() + s.slice(1))
      .join('') + 'Response';

  console.log(
    `\n// Generated type for "${endpoint}":\nexport type ${typeName} = ${inferType(data)};\n`,
  );
};

/**
 * Enhanced API request function with comprehensive TypeScript support
 *
 * @template TResponse - Expected response data type
 * @template TBody - Request body type
 * @param method - HTTP method
 * @param endpoint - API endpoint path
 * @param options - Request configuration
 * @returns Promise resolving to typed ApiResponse
 *
 * @example
 * ```typescript
 * // Simple GET
 * const users = await apiRequest<User[]>('GET', '/users');
 *
 * // POST with full configuration
 * const result = await apiRequest<CreateResponse, CreateUserData>('POST', '/users', {
 *   data: { name: 'John', email: 'john@example.com' },
 *   retries: 3,
 *   shouldRetry: (error, attempt) => error.status === 503 && attempt < 2,
 *   onError: (error, attempt) => console.warn(`Retry ${attempt}:`, error),
 *   transform: (data) => ({ ...data, timestamp: Date.now() })
 * });
 * ```
 */
export default async function apiRequest<
  TResponse = unknown,
  TBody extends RequestBody = RequestBody,
>(
  method: HttpMethod,
  endpoint: string,
  options: RequestOptions<TBody> = {},
): Promise<ApiResponse<TResponse>> {
  const {
    data,
    params,
    retries = 1,
    timeout = 30000,
    cache = 'default',
    revalidate,
    tags = [],
    headers: customHeaders,
    logTypes: shouldLogTypes = false,
    transform,
    onError,
    shouldRetry: customShouldRetry,
  } = options;

  const url = buildUrl(endpoint, params);
  const headers = buildHeaders(data, customHeaders);

  let lastError: ApiError = {
    name: 'UnknownError',
    message: 'Request failed',
    status: 500,
  };

  for (let attempt = 0; attempt <= retries; attempt++) {
    const { controller, cleanup } = createTimeout(timeout);

    try {
      // Prepare request body
      let body: BodyInit | undefined;
      if (data) {
        body =
          data instanceof FormData ||
          data instanceof Blob ||
          data instanceof ArrayBuffer ||
          typeof data === 'string'
            ? data
            : JSON.stringify(data);
      }

      // Next.js options
      const nextOptions =
        revalidate !== undefined || tags.length
          ? {
              next: {
                ...(revalidate !== undefined && { revalidate }),
                ...(tags.length && { tags }),
              },
            }
          : {};

      const response = await fetch(url, {
        method,
        headers,
        body,
        cache,
        signal: controller.signal,
        ...nextOptions,
      });

      cleanup();

      const responseData = await parseResponse<TResponse>(response);

      if (response.ok) {
        const finalData = transform ? transform(responseData) : responseData;

        if (shouldLogTypes) logTypes(endpoint, finalData);

        return {
          success: true,
          status: response.status,
          data: finalData,
          headers: response.headers,
        };
      }

      const error: ApiError = {
        name: 'HttpError',
        message: `HTTP ${response.status}: ${response.statusText}`,
        status: response.status,
        attempt,
      };

      lastError = error;
      if (onError) onError(error, attempt);

      if (shouldRetry(error, attempt, retries, method, customShouldRetry)) {
        await delay(attempt);
        continue;
      }

      return { success: false, status: response.status, error, data: null };
    } catch (err) {
      cleanup();

      const error: ApiError =
        err instanceof Error
          ? {
              name: err.name === 'AbortError' ? 'TimeoutError' : 'NetworkError',
              message:
                err.name === 'AbortError'
                  ? `Timeout after ${timeout}ms`
                  : err.message,
              status: err.name === 'AbortError' ? 408 : 500,
              attempt,
            }
          : {
              name: 'UnknownError',
              message: 'Unexpected error',
              status: 500,
              attempt,
            };

      lastError = error;
      if (onError) onError(error, attempt);

      if (shouldRetry(error, attempt, retries, method, customShouldRetry)) {
        await delay(attempt);
        continue;
      }
    }
  }

  return {
    success: false,
    status: lastError.status,
    error: lastError,
    data: null,
  };
}

/** Type guard for successful responses */
export const isSuccess = <T>(
  response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: true }> => response.success;

/** Type guard for error responses */
export const isError = <T>(
  response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: false }> => !response.success;
