/**
 * SafeFetch – Typed fetch utility with retry, timeout & Next.js support
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * https://github.com/Bharathi4real/safe-fetch
 */
'use server';

import { revalidatePath, revalidateTag } from 'next/cache';

// Environment configuration
const env = {
  AUTH_USERNAME: process.env.AUTH_USERNAME?.trim(),
  AUTH_PASSWORD: process.env.AUTH_PASSWORD?.trim(),
  AUTH_TOKEN: process.env.AUTH_TOKEN?.trim(),
  BASE_URL: process.env.BASE_URL?.trim() || '',
  ALLOW_BASIC_AUTH_IN_PROD: process.env.ALLOW_BASIC_AUTH_IN_PROD === 'true',
};

if (!env.BASE_URL?.startsWith('https://')) {
  throw new Error('BASE_URL must start with https://');
}

const PROD_ALLOWED_DOMAINS = ['api.example.com', 'another.example.com'] satisfies string[];

if (
  process.env.NODE_ENV === 'production' &&
  !PROD_ALLOWED_DOMAINS.includes(new URL(env.BASE_URL).hostname)
) {
  throw new Error('BASE_URL must be one of the allowed production domains');
}

const MAX = {
  TAGS: 10,
  TAG_LEN: 64,
  PATHS: 10,
  RES_SIZE: 1_000_000,
  PAYLOAD: 100_000,
  TIMEOUT: 30_000,
  RATE_WINDOW: 60_000,
  RATE_MAX: 500,
  CIRCUIT_TTL: 30_000,
  CIRCUIT_MAX: 100,
} as const;

/**
 * HTTP methods with perfect autocomplete
 */
const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as const;
export type HttpMethod = (typeof HTTP_METHODS)[number];

/**
 * HTTP status codes
 */
const STATUS = {
  OK: 200,
  CREATED: 201,
  NO_CONTENT: 204,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  METHOD_NOT_ALLOWED: 405,
  REQUEST_TIMEOUT: 408,
  PAYLOAD_TOO_LARGE: 413,
  RATE_LIMITED: 429,
  INTERNAL_ERROR: 500,
  SERVICE_UNAVAILABLE: 503,
} as const;

export type StatusCode = (typeof STATUS)[keyof typeof STATUS];

/**
 * Error categories for better error handling
 */
export type ErrorType =
  | 'VALIDATION_ERROR'
  | 'AUTH_ERROR'
  | 'RATE_LIMIT_ERROR'
  | 'NETWORK_ERROR'
  | 'TIMEOUT_ERROR'
  | 'SERVER_ERROR';

/**
 * Structured error information
 */
export interface ApiError {
  status: StatusCode;
  type: ErrorType;
  message: string;
  timestamp: string;
  requestId: string;
  details?: Record<string, unknown>;
}

/**
 * Cache options with clear descriptions
 */
export type CacheOption =
  | 'no-store' // Never cache (default)
  | 'force-cache' // Always use cache
  | 'default' // Browser default
  | 'no-cache' // Revalidate before use
  | 'reload' // Always fetch fresh
  | 'only-if-cached'; // Use cache only

/**
 * Query parameter types
 */
export type QueryValue = string | number | boolean | null | undefined;
export type QueryParams = Record<string, QueryValue>;

// Rate limiting and circuit breaker
const rateTimestamps: number[] = [];
const circuitMap = new Map<string, number>();

const isRateLimited = (): boolean => {
  const now = Date.now();
  while (rateTimestamps.length && rateTimestamps[0] < now - MAX.RATE_WINDOW) rateTimestamps.shift();
  if (rateTimestamps.length >= MAX.RATE_MAX) return true;
  rateTimestamps.push(now);
  return false;
};

const getAuthHeader = (): string | undefined => {
  if (typeof window !== 'undefined') throw new Error('apiRequest must run server-side');

  if (env.AUTH_TOKEN) {
    const isValidJwt = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/.test(env.AUTH_TOKEN);
    if (!isValidJwt || env.AUTH_TOKEN.length > 512) {
      throw new Error('Invalid AUTH_TOKEN format');
    }
    return `Bearer ${env.AUTH_TOKEN}`;
  }

  if (process.env.NODE_ENV === 'production' && !env.ALLOW_BASIC_AUTH_IN_PROD) {
    throw new Error('Basic Auth not allowed in production without ALLOW_BASIC_AUTH_IN_PROD=true');
  }

  if (env.AUTH_USERNAME && env.AUTH_PASSWORD) {
    return `Basic ${Buffer.from(`${env.AUTH_USERNAME}:${env.AUTH_PASSWORD}`).toString('base64')}`;
  }

  throw new Error('No authentication credentials provided');
};

const sanitizeTags = (tags: string[]): string[] =>
  tags
    .filter((tag) => /^[\w:-]+$/.test(tag))
    .map((tag) => (tag.startsWith('api:') ? tag : `api:${tag}`))
    .slice(0, MAX.TAGS)
    .map((t) => t.slice(0, MAX.TAG_LEN));

const sanitizePaths = (paths: string[]): string[] =>
  paths.filter((p) => p.startsWith('/') && !p.includes('..')).slice(0, MAX.PATHS);

const invalidateCache = async (
  paths: string[],
  tags: string[],
  type?: 'page' | 'layout',
): Promise<void> => {
  if (typeof window !== 'undefined') return;
  const safePaths = sanitizePaths(paths);
  const safeTags = sanitizeTags(tags);

  try {
    await Promise.all([
      ...safePaths.map((p) => revalidatePath(p, type)),
      ...safeTags.map((t) => revalidateTag(t)),
    ]);
  } catch (err) {
    console.error('[CACHE] Revalidation failed:', err);
  }
};

/**
 * Configuration options you can pass to `apiRequest` for API requests
 */
export interface RequestOptions<TData = unknown> {
  /**
   * Data to send in the request body.
   * Only used with POST, PUT, PATCH, DELETE.
   */
  data?: TData;

  /**
   * Query parameters to append to the URL.
   * Will be converted to URLSearchParams.
   */
  query?: QueryParams;

  /**
   * How you want to cache this request (Next.js cache behavior).
   * Most people should leave this as `'no-store'` (default).
   */
  cache?: CacheOption;

  /**
   * How long (in seconds) this response should be considered fresh.
   * Only used with Next.js cache integration.
   */
  revalidate?: number | false;

  /**
   * Cache tags to revalidate after successful mutation.
   * These should match tags you use with `fetch(..., { next: { tags: [...] } })`.
   */
  revalidateTags?: string[];

  /**
   * Paths (pages) to revalidate after success.
   * Only works on the server.
   */
  revalidatePaths?: string[];

  /**
   * Whether the revalidation targets a page or layout.
   * Only needed if using `revalidatePath()`.
   */
  revalidateType?: 'page' | 'layout';

  /**
   * Request timeout in milliseconds.
   * Default: 30_000 (30 seconds)
   */
  timeout?: number;

  /**
   * Retry count if the request fails.
   * Only for network/server errors. Max 5.
   * Default: 3
   */
  retryAttempts?: 0 | 1 | 2 | 3 | 4 | 5;

  /**
   * Delay (in ms) between retries.
   * Used with exponential backoff.
   * Default: 1000
   */
  retryDelay?: number;

  /**
   * CSRF token. Optional for mutation requests (POST, PUT, etc).
   * When provided, must be at least 32 chars and contain only safe characters.
   * If not provided, no CSRF validation will be performed.
   */
  csrfToken?: string;

  /**
   * Development helper: log the TypeScript shape of the response in the console.
   * Useful when building types from API responses.
   */
  logTypes?: boolean;

  /**
   * Any additional headers to send with the request.
   * Example: { "X-Client-Version": "1.0.0" }
   */
  customHeaders?: Record<string, string>;
}

/**
 * Method-specific options with proper typing
 */
export type GetOptions = Omit<RequestOptions<never>, 'data' | 'csrfToken'>;
export type PostOptions<T> = RequestOptions<T>;
export type PutOptions<T> = RequestOptions<T>;
export type PatchOptions<T> = RequestOptions<T>;
export type DeleteOptions = RequestOptions<never>;

/**
 * API response with success/error states
 */
export type ApiResponse<T> =
  | {
      success: true;
      data: T;
      status: StatusCode;
      headers: Record<string, string>;
      requestId: string;
    }
  | {
      success: false;
      error: ApiError & { type: ErrorType };
      data: null;
    };

/**
 * Type inference helper for development
 */
function inferType(val: unknown, depth = 0): string {
  const indent = '  '.repeat(depth);
  if (val === null) return 'null';
  if (val === undefined) return 'undefined';
  if (Array.isArray(val)) {
    const itemType = val.length > 0 ? inferType(val[0], depth) : 'unknown';
    return `${itemType}[]`;
  }
  if (typeof val === 'object' && val !== null) {
    if (depth > 2) return 'object';
    const entries = Object.entries(val)
      .slice(0, 8)
      .map(([k, v]) => `${indent}  ${k}: ${inferType(v, depth + 1)};`)
      .join('\n');
    return `{\n${entries}\n${indent}}`;
  }
  return typeof val;
}

/**
 * Create structured error
 */
function createError(
  status: StatusCode,
  type: ErrorType,
  message: string,
  requestId: string,
  details?: Record<string, unknown>,
): ApiError {
  return {
    status,
    type,
    message,
    timestamp: new Date().toISOString(),
    requestId,
    details,
  };
}

/**
 * Map status codes to error types
 */
function getErrorType(status: number): ErrorType {
  if (status === 400 || status === 422) return 'VALIDATION_ERROR';
  if (status === 401 || status === 403) return 'AUTH_ERROR';
  if (status === 408) return 'TIMEOUT_ERROR';
  if (status === 429) return 'RATE_LIMIT_ERROR';
  if (status >= 500) return 'SERVER_ERROR';
  return 'NETWORK_ERROR';
}

function isValidMethod(method: string): method is HttpMethod {
  return HTTP_METHODS.includes(method as HttpMethod);
}

// Overloaded function signatures for perfect IntelliSense
export async function apiRequest<T>(
  method: 'GET',
  url: string,
  options?: GetOptions,
): Promise<ApiResponse<T>>;
export async function apiRequest<T>(
  method: 'POST',
  url: string,
  options?: PostOptions<T>,
): Promise<ApiResponse<T>>;
export async function apiRequest<T>(
  method: 'PUT',
  url: string,
  options?: PutOptions<T>,
): Promise<ApiResponse<T>>;
export async function apiRequest<T>(
  method: 'PATCH',
  url: string,
  options?: PatchOptions<T>,
): Promise<ApiResponse<T>>;
export async function apiRequest<T>(
  method: 'DELETE',
  url: string,
  options?: DeleteOptions,
): Promise<ApiResponse<T>>;

/**
 * Makes a safe, typed HTTP request to your backend or any HTTPS API.
 *
 * This function:
 * - Automatically attaches credentials (JWT or Basic Auth)
 * - Optionally validates mutations with CSRF checks
 * - Handles common HTTP errors and maps them to helpful messages
 * - Automatically retries on failures (with backoff)
 * - Validates inputs like URLs, methods, payload size
 * - Optionally revalidates Next.js cache after mutation
 * - Logs inferred TypeScript types in development to help with typing
 *
 * ## Basic Usage:
 *
 * GET request:
 * ```ts
 * const res = await apiRequest<User[]>('GET', '/api/users', {
 *   query: { page: 1, limit: 10 }
 * });
 *
 * if (res.success) {
 *   console.log(res.data); // Fully typed User[]
 * } else {
 *   console.error(res.error.message);
 * }
 * ```
 *
 * POST request with optional CSRF and cache revalidation:
 * ```ts
 * const res = await apiRequest<User>('POST', '/api/users', {
 *   data: { name: 'Jane' },
 *   csrfToken: csrf, // Optional - provide if your API requires it
 *   revalidateTags: ['users']
 * });
 * ```
 *
 * POST request without CSRF (for APIs that don't require it):
 * ```ts
 * const res = await apiRequest<User>('POST', '/api/users', {
 *   data: { name: 'Jane' },
 *   revalidateTags: ['users']
 * });
 * ```
 *
 * Advanced config (PUT with retry, timeout, revalidate):
 * ```ts
 * const res = await apiRequest<User>('PUT', '/api/users/123', {
 *   data: { name: 'John' },
 *   csrfToken: csrf, // Optional
 *   timeout: 15000,
 *   retryAttempts: 2,
 *   revalidatePaths: ['/users']
 * });
 * ```
 */
export async function apiRequest<T>(
  method: HttpMethod,
  url: string,
  options: RequestOptions = {},
): Promise<ApiResponse<T>> {
  const requestId = `req_${crypto.randomUUID()}`;
  const {
    data,
    query,
    cache = 'no-store',
    revalidate,
    revalidateTags = [],
    revalidatePaths = [],
    revalidateType,
    timeout = MAX.TIMEOUT,
    retryAttempts = 3,
    retryDelay = 1000,
    csrfToken,
    logTypes = false,
    customHeaders = {},
  } = options;

  if (!isValidMethod(method)) {
    return {
      success: false,
      error: createError(
        STATUS.METHOD_NOT_ALLOWED,
        'VALIDATION_ERROR',
        `Invalid HTTP method: ${method}`,
        requestId,
      ),
      data: null,
    };
  }

  let fullUrl: URL;
  try {
    fullUrl = new URL(url, env.BASE_URL);
  } catch {
    return {
      success: false,
      error: createError(STATUS.BAD_REQUEST, 'VALIDATION_ERROR', 'Invalid URL', requestId),
      data: null,
    };
  }

  if (fullUrl.protocol !== 'https:') {
    return {
      success: false,
      error: createError(STATUS.BAD_REQUEST, 'VALIDATION_ERROR', 'HTTPS required', requestId),
      data: null,
    };
  }

  if (isRateLimited()) {
    return {
      success: false,
      error: createError(STATUS.RATE_LIMITED, 'RATE_LIMIT_ERROR', 'Rate limit exceeded', requestId),
      data: null,
    };
  }

  const circuitKey = `${fullUrl.origin}${fullUrl.pathname}`;
  const now = Date.now();
  if ((circuitMap.get(circuitKey) ?? 0) > now) {
    return {
      success: false,
      error: createError(
        STATUS.SERVICE_UNAVAILABLE,
        'SERVER_ERROR',
        'Service unavailable (circuit breaker)',
        requestId,
      ),
      data: null,
    };
  }

  if (query) {
    Object.entries(query).forEach(([key, val]) => {
      if (val != null) fullUrl.searchParams.append(key, String(val));
    });
  }

  if (['GET', 'HEAD'].includes(method) && data !== undefined) {
    return {
      success: false,
      error: createError(
        STATUS.BAD_REQUEST,
        'VALIDATION_ERROR',
        'GET/HEAD methods cannot send body payload',
        requestId,
      ),
      data: null,
    };
  }

  // Optional CSRF validation - only check if token is provided
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && csrfToken !== undefined) {
    if (!/^[a-zA-Z0-9-_]{32,}$/.test(csrfToken)) {
      return {
        success: false,
        error: createError(
          STATUS.BAD_REQUEST,
          'VALIDATION_ERROR',
          'Invalid CSRF token format',
          requestId,
        ),
        data: null,
      };
    }
  }

  let authHeader: string | undefined;
  try {
    authHeader = getAuthHeader();
  } catch {
    return {
      success: false,
      error: createError(STATUS.UNAUTHORIZED, 'AUTH_ERROR', 'Authentication failed', requestId),
      data: null,
    };
  }

  const isFormData = typeof FormData !== 'undefined' && data instanceof FormData;
  const headers: Record<string, string> = {
    Accept: 'application/json',
    'X-Requested-With': 'XMLHttpRequest',
    'X-Request-ID': requestId,
    ...customHeaders,
  };
  if (authHeader) headers.Authorization = authHeader;
  if (!isFormData && !['GET', 'HEAD'].includes(method))
    headers['Content-Type'] = 'application/json';
  if (csrfToken) headers['X-CSRF-Token'] = csrfToken;

  const makeRequest = async (attempt = 1): Promise<ApiResponse<T>> => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      let body: string | FormData | undefined;
      if (!['GET', 'HEAD'].includes(method)) {
        if (isFormData) {
          body = data as FormData;
        } else if (data !== undefined) {
          body = JSON.stringify(data);
          if (body.length > MAX.PAYLOAD) {
            return {
              success: false,
              error: createError(
                STATUS.PAYLOAD_TOO_LARGE,
                'VALIDATION_ERROR',
                'Payload too large',
                requestId,
              ),
              data: null,
            };
          }
        }
      }

      interface NextFetchOptions extends RequestInit {
        next?: {
          revalidate?: number | false;
          tags?: string[];
        };
      }

      const fetchOptions: NextFetchOptions = {
        method,
        headers,
        cache,
        signal: controller.signal,
        body,
      };

      if (revalidate !== undefined || revalidateTags.length) {
        fetchOptions.next = {
          revalidate,
          tags: sanitizeTags(revalidateTags),
        };
      }

      if (revalidate !== undefined || revalidateTags.length) {
        fetchOptions.next = {
          revalidate,
          tags: sanitizeTags(revalidateTags),
        };
      }

      const response = await fetch(fullUrl.toString(), fetchOptions);

      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        responseHeaders[key] = value;
      });

      const contentLength = Number(response.headers.get('Content-Length') || '0');
      if (contentLength > MAX.RES_SIZE) {
        return {
          success: false,
          error: createError(
            STATUS.PAYLOAD_TOO_LARGE,
            'VALIDATION_ERROR',
            'Response too large',
            requestId,
          ),
          data: null,
        };
      }

      let parsedData: T;
      try {
        const contentType = response.headers.get('Content-Type') || '';
        if (contentType.includes('application/json')) {
          parsedData = await response.json();
        } else if (contentType.startsWith('text/')) {
          parsedData = (await response.text()) as unknown as T;
        } else if (
          contentType.includes('application/octet-stream') ||
          contentType.startsWith('image/')
        ) {
          parsedData = (await response.blob()) as unknown as T; // 🔧 basic binary support
        } else {
          throw new Error(`Unsupported content type: ${contentType}`);
        }
      } catch (error: unknown) {
        console.error('Failed to parse response:', error);
        return {
          success: false,
          error: createError(
            response.status as StatusCode,
            'NETWORK_ERROR',
            'Failed to parse response',
            requestId,
          ),
          data: null,
        };
      }

      if (!response.ok) {
        if (response.status >= 500 && attempt < retryAttempts) {
          const retryAfter = response.headers.get('Retry-After');
          const delay = retryAfter
            ? Number(retryAfter) * 1000
            : retryDelay * 2 ** (attempt - 1) * (0.5 + Math.random());
          await new Promise((r) => setTimeout(r, delay));
          return makeRequest(attempt + 1);
        }

        circuitMap.set(circuitKey, now + MAX.CIRCUIT_TTL);
        return {
          success: false,
          error: createError(
            response.status as StatusCode,
            getErrorType(response.status),
            response.statusText || 'Request failed',
            requestId,
            { url, method, attempt },
          ),
          data: null,
        };
      }

      await invalidateCache(revalidatePaths, revalidateTags, revalidateType);

      if (process.env.NODE_ENV === 'development' && logTypes) {
        console.group(`🔍 ${method} ${url} - Inferred Type`);
        console.log(inferType(parsedData));
        console.groupEnd();
      }

      return {
        success: true,
        data: parsedData,
        status: response.status as StatusCode,
        headers: responseHeaders,
        requestId,
      };
    } catch (err) {
      const isTimeout = err instanceof Error && err.name === 'AbortError';
      const isNetwork = err instanceof TypeError;

      if ((isTimeout || isNetwork) && attempt < retryAttempts && ['GET', 'HEAD'].includes(method)) {
        const delay = retryDelay * 2 ** (attempt - 1) * (0.5 + Math.random());
        await new Promise((r) => setTimeout(r, delay));
        return makeRequest(attempt + 1);
      }

      circuitMap.set(circuitKey, now + MAX.CIRCUIT_TTL);
      return {
        success: false,
        error: createError(
          isTimeout ? 408 : 500,
          isTimeout ? 'TIMEOUT_ERROR' : 'NETWORK_ERROR',
          isTimeout ? 'Request timeout' : 'Network error',
          requestId,
        ),
        data: null,
      };
    } finally {
      clearTimeout(timeoutId);
    }
  };

  return makeRequest();
}

export default apiRequest;
