/**
 * SafeFetch – Next.js typed fetch utility with retry, timeout & caching
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * https://github.com/Bharathi4real/safe-fetch
 */

'use server';

import { revalidatePath, revalidateTag } from 'next/cache';
import { headers } from 'next/headers';

/**
 * Environment configuration for authentication and base URL setup
 */
export interface EnvConfig {
  /** Environment variable name for basic auth username */
  authUsername?: string;
  /** Environment variable name for basic auth password */
  authPassword?: string;
  /** Environment variable name for JWT/Bearer token */
  authToken?: string;
  /** Environment variable name for API base URL */
  baseUrl?: string;
  /** Environment variable name to allow basic auth in production */
  allowBasicAuthInProd?: string;
  /** Environment variable name to enable detailed error headers in production */
  exposeErrorHeaders?: string;
}

/**
 * Default environment variable names used by SafeFetch
 */
const DEFAULT_ENV_CONFIG: Required<EnvConfig> = {
  authUsername: 'AUTH_USERNAME',
  authPassword: 'AUTH_PASSWORD',
  authToken: 'AUTH_TOKEN',
  baseUrl: 'BASE_URL',
  allowBasicAuthInProd: 'ALLOW_BASIC_AUTH_IN_PROD',
  exposeErrorHeaders: 'EXPOSE_ERROR_HEADERS',
};

/**
 * Creates environment configuration object from process.env
 */
const createEnv = (envConfig: EnvConfig = {}) => {
  if (typeof window !== 'undefined') return {};

  const config = { ...DEFAULT_ENV_CONFIG, ...envConfig };

  return {
    AUTH_USERNAME: process.env[config.authUsername]?.trim(),
    AUTH_PASSWORD: process.env[config.authPassword]?.trim(),
    AUTH_TOKEN: process.env[config.authToken]?.trim(),
    BASE_URL: process.env[config.baseUrl]?.trim() || '',
    ALLOW_BASIC_AUTH_IN_PROD: process.env[config.allowBasicAuthInProd] === 'true',
    ENABLE_DETAILED_ERRORS_IN_PROD: process.env[config.exposeErrorHeaders] === 'true',
  };
};

/**
 * Maximum limits and timeouts for various operations
 */
const MAX = {
  /** Maximum number of cache tags allowed per request */
  TAGS: 10,
  /** Maximum length of individual cache tag in characters */
  TAG_LEN: 64,
  /** Maximum number of paths to revalidate per request */
  PATHS: 10,
  /** Maximum response size in bytes (1MB) - prevents memory exhaustion */
  RES_SIZE: 1_000_000,
  /** Maximum request payload size in bytes (100KB) - prevents large uploads */
  PAYLOAD: 100_000,
  /** Default request timeout in milliseconds (30 seconds) */
  TIMEOUT: 30_000,
  /** Rate limiting time window in milliseconds (60 seconds) */
  RATE_WINDOW: 60_000,
  /** Maximum requests allowed per rate limit window */
  RATE_MAX: 500,
  /** Circuit breaker timeout in milliseconds (30 seconds) - how long to keep circuit open */
  CIRCUIT_TTL: 30_000,
  /** Circuit breaker failure threshold - unused but reserved for future implementation */
  CIRCUIT_MAX: 100,
} as const;

/**
 * Supported HTTP methods
 */
const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as const;

/**
 * HTTP method type union
 */
export type HttpMethod = (typeof HTTP_METHODS)[number];

/**
 * HTTP status codes used throughout the library
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
 * Error types for categorizing different failure modes
 */
export type ErrorType =
  | 'VALIDATION_ERROR' // Invalid input data or parameters
  | 'AUTH_ERROR' // Authentication/authorization failures
  | 'RATE_LIMIT_ERROR' // Rate limiting triggered
  | 'NETWORK_ERROR' // Network connectivity issues
  | 'TIMEOUT_ERROR' // Request timeout
  | 'SERVER_ERROR'; // Server-side errors (5xx)

/**
 * Standardized error object returned by SafeFetch
 */
export interface ApiError {
  status: StatusCode;
  type: ErrorType;
  message: string;
  timestamp: string;
  requestId: string;
  details?: Record<string, unknown>;
  apiError?: unknown;
  rawResponse?: {
    statusText: string;
    url: string;
    safeHeaders?: Record<string, string>;
  };
}

/**
 * Next.js cache strategies
 */
export type NextCacheStrategy =
  /** Cache indefinitely until manually invalidated */
  | 'force-cache'
  /** Never cache, always fetch fresh data */
  | 'no-store'
  /** Cache but revalidate on every request (stale-while-revalidate) */
  | 'no-cache'
  /** Use Next.js default caching behavior */
  | 'default';

/**
 * Valid query parameter value types
 */
export type QueryValue = string | number | boolean | null | undefined;

/**
 * URL query parameters object
 */
export type QueryParams = Record<string, QueryValue>;

// Shared rate limiting and circuit breaker state
const rateTimestamps: number[] = [];
const circuitMap = new Map<string, number>();

/**
 * Checks if current request would exceed rate limits
 */
const isRateLimited = (): boolean => {
  const now = Date.now();
  while (rateTimestamps.length && rateTimestamps[0] < now - MAX.RATE_WINDOW) rateTimestamps.shift();
  if (rateTimestamps.length >= MAX.RATE_MAX) return true;
  rateTimestamps.push(now);
  return false;
};

/**
 * Client configuration for making requests
 */
export interface ClientConfig {
  baseUrl: string;
  authHeader?: string;
  forwardedHeaders?: Record<string, string>;
  /** Whether to include detailed error information (headers, raw response) */
  includeDetailedErrors?: boolean;
}

/**
 * Configuration for SafeFetch instance
 */
export interface SafeFetchConfig {
  envConfig?: EnvConfig;
  allowedDomains?: string[];
  /** Whether to include detailed error information in responses */
  includeDetailedErrors?: boolean;
  defaults?: {
    timeout?: number;
    retryAttempts?: number | 0;
    retryDelay?: number;
    cache?: NextCacheStrategy;
  };
}

/**
 * Generates authorization header from environment variables
 */
const getAuthHeader = (env: ReturnType<typeof createEnv>): string | undefined => {
  if (typeof window !== 'undefined') throw new Error('getAuthHeader must run server-side');

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

/**
 * Determines whether to include detailed error information based on environment and configuration
 */
const shouldIncludeDetailedErrors = (
  config: SafeFetchConfig = {},
  env: ReturnType<typeof createEnv>,
): boolean => {
  // If explicitly configured in SafeFetchConfig, use that
  if (config.includeDetailedErrors !== undefined) {
    return config.includeDetailedErrors;
  }

  // In development, always include detailed errors
  if (process.env.NODE_ENV === 'development') {
    return true;
  }

  // In production, only include if explicitly enabled via environment variable
  return env.ENABLE_DETAILED_ERRORS_IN_PROD || false;
};

/**
 * Creates client configuration for API requests (server-side only)
 */
export async function createClientConfig(config: SafeFetchConfig = {}): Promise<ClientConfig> {
  if (typeof window !== 'undefined') {
    throw new Error('createClientConfig must run server-side');
  }

  const env = createEnv(config.envConfig);

  if (!env.BASE_URL?.startsWith('https://')) {
    throw new Error('BASE_URL must start with https://');
  }

  const DEFAULT_ALLOWED_DOMAINS = [`${env.BASE_URL}`, `anotherdomain.com`];
  const allowedDomains = config.allowedDomains || DEFAULT_ALLOWED_DOMAINS;

  if (
    process.env.NODE_ENV === 'production' &&
    !allowedDomains.includes(new URL(env.BASE_URL).hostname)
  ) {
    throw new Error(
      `BASE_URL must be one of the allowed production domains: ${allowedDomains.join(', ')}`,
    );
  }

  const forwardedHeaders: Record<string, string> = {};

  try {
    const headersList = await headers();
    const userAgent = headersList.get('user-agent');
    const xForwardedFor = headersList.get('x-forwarded-for');
    const xRealIp = headersList.get('x-real-ip');

    if (userAgent) forwardedHeaders['User-Agent'] = userAgent;
    if (xForwardedFor) forwardedHeaders['X-Forwarded-For'] = xForwardedFor;
    if (xRealIp) forwardedHeaders['X-Real-IP'] = xRealIp;
  } catch {
    // Headers not available in some contexts
  }

  const includeDetailedErrors = shouldIncludeDetailedErrors(config, env);

  return {
    baseUrl: env.BASE_URL!,
    authHeader: getAuthHeader(env),
    forwardedHeaders,
    includeDetailedErrors,
  };
}

/**
 * Sanitizes cache tags to ensure they meet Next.js requirements
 */
const sanitizeTags = (tags: string[]): string[] =>
  tags
    .filter((tag) => /^[\w:-]+$/.test(tag))
    .map((tag) => (tag.startsWith('api:') ? tag : `api:${tag}`))
    .slice(0, MAX.TAGS)
    .map((t) => t.slice(0, MAX.TAG_LEN));

/**
 * Sanitizes revalidation paths to prevent directory traversal
 */
const sanitizePaths = (paths: string[]): string[] =>
  paths.filter((p) => p.startsWith('/') && !p.includes('..')).slice(0, MAX.PATHS);

/**
 * Invalidates Next.js cache for specified paths and tags
 */
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
 * Base request options interface with comprehensive JSDoc for IntelliSense
 */
export interface RequestOptions<TData = unknown> {
  /** Request body data (for POST, PUT, PATCH methods) */
  data?: TData;

  /** URL query parameters to append to the request URL */
  query?: QueryParams;

  /**
   * Next.js caching strategy
   * - 'force-cache': Cache indefinitely until manually invalidated
   * - 'no-store': Never cache, always fetch fresh (default)
   * - 'no-cache': Cache but revalidate on every request
   * - 'default': Use Next.js default caching behavior
   */
  cache?: NextCacheStrategy;

  /** Cache revalidation interval in seconds (false to never auto-revalidate) */
  revalidate?: number | false;

  /** Cache tags for targeted cache invalidation */
  revalidateTags?: string[];

  /** Paths to revalidate after successful request */
  revalidatePaths?: string[];

  /** Type of path revalidation ('page' | 'layout') */
  revalidateType?: 'page' | 'layout';

  /** Request timeout in milliseconds @default 30000 */
  timeout?: number;

  /** Number of retry attempts for failed requests @default 3 */
  retryAttempts?: number;

  /** Base delay between retries in milliseconds @default 1000 */
  retryDelay?: number;

  /** CSRF token for state-changing requests */
  csrfToken?: string;

  /** Log inferred TypeScript types in development console */
  logTypes?: boolean;

  /** Additional headers to include in the request */
  customHeaders?: Record<string, string>;

  /** Client configuration (required for client-side requests) */
  clientConfig?: ClientConfig;

  /**
   * Whether to include detailed error information (headers, raw response) in error responses
   * Overrides the global configuration for this specific request
   */
  includeDetailedErrors?: boolean;
}

/**
 * Options for GET requests (excludes body data and CSRF token)
 */
export type GetOptions = Omit<RequestOptions<never>, 'data' | 'csrfToken'>;

/**
 * Options for POST requests with typed body data
 */
export type PostOptions<T> = RequestOptions<T>;

/**
 * Options for PUT requests with typed body data
 */
export type PutOptions<T> = RequestOptions<T>;

/**
 * Options for PATCH requests with typed body data
 */
export type PatchOptions<T> = RequestOptions<T>;

/**
 * Options for DELETE requests (excludes body data)
 */
export type DeleteOptions = RequestOptions<never>;

/**
 * Standardized API response wrapper with discriminated union for type safety
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
 * Infers TypeScript type from runtime value for development logging
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
 * Creates standardized error object
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
 * Maps HTTP status codes to error categories
 */
function getErrorType(status: number): ErrorType {
  if (status === 400 || status === 422) return 'VALIDATION_ERROR';
  if (status === 401 || status === 403) return 'AUTH_ERROR';
  if (status === 408) return 'TIMEOUT_ERROR';
  if (status === 429) return 'RATE_LIMIT_ERROR';
  if (status >= 500) return 'SERVER_ERROR';
  return 'NETWORK_ERROR';
}

/**
 * Type guard to validate HTTP methods
 */
function isValidMethod(method: string): method is HttpMethod {
  return HTTP_METHODS.includes(method as HttpMethod);
}

/**
 * Makes a GET request to retrieve data from the server
 */
export async function apiRequest<T>(
  method: 'GET',
  url: string,
  options?: GetOptions,
): Promise<ApiResponse<T>>;

/**
 * Makes a DELETE request to remove a resource from the server
 */
export async function apiRequest<T>(
  method: 'DELETE',
  url: string,
  options?: DeleteOptions,
): Promise<ApiResponse<T>>;

/**
 * Makes a POST request to create new resources or submit data
 */
export async function apiRequest<T, TData = unknown>(
  method: 'POST',
  url: string,
  options?: PostOptions<TData>,
): Promise<ApiResponse<T>>;

/**
 * Makes a PUT request to replace or fully update a resource
 */
export async function apiRequest<T, TData = unknown>(
  method: 'PUT',
  url: string,
  options?: PutOptions<TData>,
): Promise<ApiResponse<T>>;

/**
 * Makes a PATCH request to partially update a resource
 */
export async function apiRequest<T, TData = unknown>(
  method: 'PATCH',
  url: string,
  options?: PatchOptions<TData>,
): Promise<ApiResponse<T>>;

/**
 * Makes an HTTP request with the specified method (generic overload)
 */
export async function apiRequest<T>(
  method: HttpMethod,
  url: string,
  options?: RequestOptions,
): Promise<ApiResponse<T>>;

/**
 * Core HTTP request function with comprehensive features for Next.js applications
 *
 * @param method - HTTP method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
 * @param url - Relative or absolute URL path
 * @param options - Request configuration options
 * @returns Promise resolving to typed API response
 *
 * @example Basic GET request
 * ```typescript
 * const { success, data, error } = await apiRequest('GET', '/api/users');
 * if (success) console.log(data);
 * ```
 *
 * @example POST with data
 * ```typescript
 * const response = await apiRequest('POST', '/api/users', {
 *   data: { name: 'John', email: 'john@example.com' }
 * });
 * ```
 *
 * @example With caching and revalidation
 * ```typescript
 * const response = await apiRequest('GET', '/api/posts', {
 *   cache: 'force-cache',
 *   revalidate: 3600,
 *   revalidateTags: ['posts']
 * });
 * ```
 *
 * @example With retry configuration
 * ```typescript
 * const response = await apiRequest('GET', '/api/data', {
 *   retryAttempts: 5,
 *   retryDelay: 2000,
 *   timeout: 10000
 * });
 * ```
 *
 * Key Features:
 * - Type Safety: Full TypeScript support with request/response typing
 * - Retry Logic: Automatic retries with exponential backoff and jitter
 * - Caching: Deep Next.js cache integration with granular control
 * - Error Handling: Comprehensive error categorization and debugging
 * - Security: CSRF protection, rate limiting, circuit breakers
 * - Performance: Request/response size validation, timeout controls
 */
export async function apiRequest<T>(
  method: HttpMethod,
  url: string,
  options: RequestOptions = {},
): Promise<ApiResponse<T>> {
  const requestId = `req_${crypto.randomUUID()}`;
  const isClient = typeof window !== 'undefined';

  const {
    data,
    query,
    cache = 'default',
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
    clientConfig,
    includeDetailedErrors,
  } = options;

  if (isClient && !clientConfig) {
    return {
      success: false,
      error: createError(
        STATUS.BAD_REQUEST,
        'VALIDATION_ERROR',
        'clientConfig is required for client-side requests. Create it server-side with createClientConfig()',
        requestId,
      ),
      data: null,
    };
  }

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

  const baseUrl = isClient ? clientConfig!.baseUrl : createEnv().BASE_URL;
  const authHeader = isClient
    ? clientConfig!.authHeader
    : (() => {
        try {
          return getAuthHeader(createEnv());
        } catch {
          return undefined;
        }
      })();

  // Determine whether to include detailed errors for this request
  const shouldIncludeDetails =
    includeDetailedErrors !== undefined
      ? includeDetailedErrors
      : isClient
        ? clientConfig?.includeDetailedErrors
        : shouldIncludeDetailedErrors({}, createEnv());

  if (!baseUrl) {
    return {
      success: false,
      error: createError(
        STATUS.BAD_REQUEST,
        'VALIDATION_ERROR',
        'Base URL not configured',
        requestId,
      ),
      data: null,
    };
  }

  let fullUrl: URL;
  try {
    fullUrl = new URL(url, baseUrl);
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

  const isFormData = typeof FormData !== 'undefined' && data instanceof FormData;
  const headers: Record<string, string> = {
    Accept: 'application/json',
    'X-Requested-With': 'XMLHttpRequest',
    'X-Request-ID': requestId,
    ...customHeaders,
  };

  // Add forwarded Next.js headers for proper request context
  if (isClient && clientConfig?.forwardedHeaders) {
    Object.assign(headers, clientConfig.forwardedHeaders);
  }

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

      // Only use Next.js cache options on server-side
      if (!isClient && (revalidate !== undefined || revalidateTags.length)) {
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

      const getSafeHeaders = (headers: Record<string, string>): Record<string, string> => {
        const safeHeaderKeys = [
          'content-type',
          'content-length',
          'cache-control',
          'retry-after',
          'x-ratelimit-limit',
          'x-ratelimit-remaining',
          'x-ratelimit-reset',
          'x-request-id',
          'x-trace-id',
          'server-timing',
        ];

        const safeHeaders: Record<string, string> = {};
        safeHeaderKeys.forEach((key) => {
          const value = headers[key.toLowerCase()];
          if (value) safeHeaders[key] = value;
        });

        return safeHeaders;
      };

      let parsedData: T;
      let apiErrorData: unknown = null;
      try {
        const contentType = response.headers.get('Content-Type') || '';
        if (contentType.includes('application/json')) {
          parsedData = await response.json();
          // For failed requests, store the parsed error response (only if expose error headers enabled)
          if (!response.ok && shouldIncludeDetails) {
            apiErrorData = parsedData;
          }
        } else if (contentType.startsWith('text/')) {
          const textData = await response.text();
          parsedData = textData as unknown as T;
          // For failed requests, store the text response (only if expose error headers enabled)
          if (!response.ok && shouldIncludeDetails) {
            apiErrorData = textData;
          }
        } else if (
          contentType.includes('application/octet-stream') ||
          contentType.startsWith('image/')
        ) {
          parsedData = (await response.blob()) as unknown as T;
          // For binary data, we can't really parse the error, so leave it null
        } else {
          throw new Error(`Unsupported content type: ${contentType}`);
        }
      } catch (error: unknown) {
        console.error('Failed to parse response:', error);

        const baseError = createError(
          response.status as StatusCode,
          'NETWORK_ERROR',
          'Failed to parse response',
          requestId,
        );

        return {
          success: false,
          error: {
            ...baseError,
            // Include parsing error details only if expose error headers enabled
            ...(shouldIncludeDetails && {
              apiError: error instanceof Error ? error.message : 'Unknown parsing error',
              rawResponse: {
                safeHeaders: getSafeHeaders(responseHeaders),
                statusText: response.statusText,
                url: fullUrl.toString(),
              },
            }),
          },
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

        const baseError = createError(
          response.status as StatusCode,
          getErrorType(response.status),
          response.statusText || 'Request failed',
          requestId,
          { url, method, attempt },
        );

        // Enhanced error response with actual API error data (only if expose error headers enabled)
        return {
          success: false,
          error: {
            ...baseError,
            // Only include detailed error information if enabled
            ...(shouldIncludeDetails && {
              apiError: apiErrorData,
              rawResponse: {
                safeHeaders: getSafeHeaders(responseHeaders),
                statusText: response.statusText,
                url: fullUrl.toString(),
              },
            }),
          },
          data: null,
        };
      }

      // Only invalidate cache on server-side
      if (!isClient) {
        await invalidateCache(revalidatePaths, revalidateTags, revalidateType);
      }

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

      const baseError = createError(
        isTimeout ? 408 : 500,
        isTimeout ? 'TIMEOUT_ERROR' : 'NETWORK_ERROR',
        isTimeout ? 'Request timeout' : 'Network error',
        requestId,
      );

      return {
        success: false,
        error: {
          ...baseError,
          // Include network error details only if expose error headers are enabled
          ...(shouldIncludeDetails && {
            apiError:
              err instanceof Error
                ? {
                    name: err.name,
                    message: err.message,
                    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
                  }
                : err,
            rawResponse: {
              safeHeaders: {}, // No headers available for network errors
              statusText: isTimeout ? 'Request Timeout' : 'Network Error',
              url: fullUrl.toString(),
            },
          }),
        },
        data: null,
      };
    } finally {
      clearTimeout(timeoutId);
    }
  };

  return makeRequest();
}

/**
 * SafeFetch factory function that creates a configured instance with defaults
 */
export async function createSafeFetch(config: SafeFetchConfig = {}) {
  const defaults = config.defaults || {};
  const clientConfig = await createClientConfig(config);

  return {
    /**
     * Returns the previously resolved ClientConfig for client-side usage
     */
    createClientConfig: async () => clientConfig,

    /**
     * Makes an HTTP request using this SafeFetch instance's configuration
     */
    request: async <T>(
      method: HttpMethod,
      url: string,
      options: RequestOptions = {},
    ): Promise<ApiResponse<T>> => {
      const mergedOptions = {
        timeout: defaults.timeout,
        retryAttempts: defaults.retryAttempts,
        retryDelay: defaults.retryDelay,
        cache: defaults.cache,
        ...options,
        // Pass through the global includeDetailedErrors setting if not overridden
        includeDetailedErrors: options.includeDetailedErrors ?? config.includeDetailedErrors,
      };

      return apiRequest<T>(method, url, mergedOptions);
    },
  };
}

/**
 * Makes a GET request to retrieve data from the server
 */
export const get = <T>(url: string, options?: GetOptions): Promise<ApiResponse<T>> =>
  apiRequest<T>('GET', url, options);

/**
 * Makes a POST request to create resources or submit data to the server
 */
export const post = <T, TData = unknown>(
  url: string,
  options?: PostOptions<TData>,
): Promise<ApiResponse<T>> => apiRequest<T, TData>('POST', url, options);

/**
 * Makes a PUT request to completely replace or update a resource
 */
export const put = <T, TData = unknown>(
  url: string,
  options?: PutOptions<TData>,
): Promise<ApiResponse<T>> => apiRequest<T, TData>('PUT', url, options);

/**
 * Makes a PATCH request to partially update a resource
 */
export const patch = <T, TData = unknown>(
  url: string,
  options?: PatchOptions<TData>,
): Promise<ApiResponse<T>> => apiRequest<T, TData>('PATCH', url, options);

/**
 * Makes a DELETE request to remove a resource from the server
 */
export const del = <T>(url: string, options?: DeleteOptions): Promise<ApiResponse<T>> =>
  apiRequest<T>('DELETE', url, options);

// SafeFetch Default Export - The core apiRequest function

export default apiRequest;
