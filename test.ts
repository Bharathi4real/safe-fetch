/**
 * SafeFetch – Next.js typed fetch utility with retry, timeout & caching
 * Enhanced with configurable limits and better defaults
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

// Configurable limits for various operations
export interface SafeFetchLimits {
  /** Maximum number of cache tags allowed per request @default 10 */
  maxTags?: number;
  /** Maximum length of individual cache tag in characters @default 64 */
  maxTagLength?: number;
  /** Maximum number of paths to revalidate per request @default 10 */
  maxPaths?: number;
  /** Maximum response size in bytes @default 5MB */
  maxResponseSize?: number;
  /** Maximum request payload size in bytes @default 1MB */
  maxPayloadSize?: number;
  /** Default request timeout in milliseconds @default 60s */
  defaultTimeout?: number;
  /** Rate limiting time window in milliseconds @default 60s */
  rateLimitWindow?: number;
  /** Maximum requests allowed per rate limit window @default 1000 */
  rateLimitMax?: number;
  /** Circuit breaker timeout in milliseconds @default 30s */
  circuitBreakerTtl?: number;
  /** Circuit breaker failure threshold @default 10 */
  circuitBreakerMax?: number;
}

// Default limits with reasonable values for modern applications
const DEFAULT_LIMITS: Required<SafeFetchLimits> = {
  maxTags: 20,
  maxTagLength: 128,
  maxPaths: 20,
  maxResponseSize: 5_000_000, // 5MB - better for modern APIs
  maxPayloadSize: 1_000_000, // 1MB - reasonable for file uploads
  defaultTimeout: 60_000, // 60 seconds - better for slower APIs
  rateLimitWindow: 60_000,
  rateLimitMax: 1000, // More generous rate limiting
  circuitBreakerTtl: 30_000,
  circuitBreakerMax: 10, // Actually use this threshold
} as const;

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

// Creates environment configuration object from process.env
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
 * Supported HTTP methods with enhanced IntelliSense
 * @example 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
 */
export type HttpMethod = 
  | 'GET'    // Retrieve data from server
  | 'POST'   // Create new resource
  | 'PUT'    // Update entire resource
  | 'PATCH'  // Partial update of resource
  | 'DELETE' // Remove resource from server;

/**
 * Supported HTTP methods array for validation
 */
const HTTP_METHODS: readonly HttpMethod[] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as const;

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
const circuitMap = new Map<string, { count: number; lastFailure: number; openUntil: number }>();

// Checks if current request would exceed rate limits
const isRateLimited = (limits: Required<SafeFetchLimits>): boolean => {
  const now = Date.now();
  while (rateTimestamps.length && rateTimestamps[0] < now - limits.rateLimitWindow) {
    rateTimestamps.shift();
  }
  if (rateTimestamps.length >= limits.rateLimitMax) return true;
  rateTimestamps.push(now);
  return false;
};

// Circuit breaker implementation with configurable thresholds
const checkCircuitBreaker = (
  circuitKey: string,
  _limits: Required<SafeFetchLimits>,
): { isOpen: boolean; shouldRetry: boolean } => {
  const now = Date.now();
  const circuit = circuitMap.get(circuitKey);

  if (!circuit) {
    return { isOpen: false, shouldRetry: true };
  }

  // Circuit is open, check if it should remain open
  if (circuit.openUntil > now) {
    return { isOpen: true, shouldRetry: false };
  }

  // Circuit was open but timeout expired, allow one retry
  if (circuit.openUntil > 0 && circuit.openUntil <= now) {
    return { isOpen: false, shouldRetry: true };
  }

  return { isOpen: false, shouldRetry: true };
};

// Records a failure in the circuit breaker
const recordCircuitFailure = (circuitKey: string, limits: Required<SafeFetchLimits>): void => {
  const now = Date.now();
  const circuit = circuitMap.get(circuitKey) || { count: 0, lastFailure: 0, openUntil: 0 };

  circuit.count += 1;
  circuit.lastFailure = now;

  if (circuit.count >= limits.circuitBreakerMax) {
    circuit.openUntil = now + limits.circuitBreakerTtl;
  }

  circuitMap.set(circuitKey, circuit);
};

// Records a success in the circuit breaker (resets failure count)
const recordCircuitSuccess = (circuitKey: string): void => {
  circuitMap.delete(circuitKey);
};

// Client configuration for making requests
export interface ClientConfig {
  baseUrl: string;
  authHeader?: string;
  forwardedHeaders?: Record<string, string>;
  // Whether to include detailed error information (headers, raw response)
  includeDetailedErrors?: boolean;
  // Custom limits for this client
  limits?: SafeFetchLimits;
}

// Configuration for SafeFetch instance
export interface SafeFetchConfig {
  envConfig?: EnvConfig;
  allowedDomains?: string[];
  // Whether to include detailed error information in responses
  includeDetailedErrors?: boolean;
  // Global limits configuration
  limits?: SafeFetchLimits;
  defaults?: {
    timeout?: number;
    retryAttempts?: number | 0;
    retryDelay?: number;
    cache?: NextCacheStrategy;
  };
}

// Generates authorization header from environment variables
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

// Determines whether to include detailed error information based on environment and configuration
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
    limits: config.limits,
  };
}

// Sanitizes cache tags to ensure they meet Next.js requirements
const sanitizeTags = (tags: string[], limits: Required<SafeFetchLimits>): string[] =>
  tags
    .filter((tag) => /^[\w:-]+$/.test(tag))
    .map((tag) => (tag.startsWith('api:') ? tag : `api:${tag}`))
    .slice(0, limits.maxTags)
    .map((t) => t.slice(0, limits.maxTagLength));

// Sanitizes revalidation paths to prevent directory traversal
const sanitizePaths = (paths: string[], limits: Required<SafeFetchLimits>): string[] =>
  paths.filter((p) => p.startsWith('/') && !p.includes('..')).slice(0, limits.maxPaths);

// Invalidates Next.js cache for specified paths and tags
const invalidateCache = async (
  paths: string[],
  tags: string[],
  limits: Required<SafeFetchLimits>,
  type?: 'page' | 'layout',
): Promise<void> => {
  if (typeof window !== 'undefined') return;
  const safePaths = sanitizePaths(paths, limits);
  const safeTags = sanitizeTags(tags, limits);

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

  /** Request timeout in milliseconds @default 60000 */
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

  /**
   * Custom limits for this specific request
   * Overrides global and client limits
   */
  limits?: SafeFetchLimits;
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

// Standardized API response wrapper with discriminated union for type safety
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

// Infers TypeScript type from runtime value for development logging
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

// Creates standardized error object
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

// Maps HTTP status codes to error categories
function getErrorType(status: number): ErrorType {
  if (status === 400 || status === 422) return 'VALIDATION_ERROR';
  if (status === 401 || status === 403) return 'AUTH_ERROR';
  if (status === 408) return 'TIMEOUT_ERROR';
  if (status === 429) return 'RATE_LIMIT_ERROR';
  if (status >= 500) return 'SERVER_ERROR';
  return 'NETWORK_ERROR';
}

// Type guard to validate HTTP methods
function isValidMethod(method: string): method is HttpMethod {
  return HTTP_METHODS.includes(method as HttpMethod);
}

// Merges limits from multiple sources with precedence
function mergeLimits(
  globalLimits?: SafeFetchLimits,
  clientLimits?: SafeFetchLimits,
  requestLimits?: SafeFetchLimits,
): Required<SafeFetchLimits> {
  return {
    ...DEFAULT_LIMITS,
    ...globalLimits,
    ...clientLimits,
    ...requestLimits,
  };
}

/**
 * Core HTTP request function with comprehensive features for Next.js applications.
 * 
 * @param method HTTP method - Available options:
 * - `'GET'` - Retrieve data from server (no body data allowed)
 * - `'POST'` - Create new resource (with optional body data)
 * - `'PUT'` - Update entire resource (with optional body data)  
 * - `'PATCH'` - Partial update of resource (with optional body data)
 * - `'DELETE'` - Remove resource from server (no body data allowed)
 * 
 * @param url Request URL (relative to baseUrl or absolute HTTPS URL)
 * 
 * @param options Request configuration options:
 * - `data?` - Request body (for POST/PUT/PATCH methods)
 * - `query?` - URL query parameters object
 * - `cache?` - Next.js cache strategy: 'force-cache' | 'no-store' | 'no-cache' | 'default'
 * - `timeout?` - Request timeout in milliseconds (default: 60000)
 * - `retryAttempts?` - Number of retry attempts (default: 3)
 * - `customHeaders?` - Additional HTTP headers
 * - `revalidateTags?` - Cache tags for Next.js revalidation
 * - `revalidatePaths?` - Paths to revalidate after successful request
 * 
 * @returns Promise<ApiResponse<T>> - Discriminated union:
 * - `{ success: true, data: T, status: number, headers: object, requestId: string }`
 * - `{ success: false, error: ApiError, data: null }`
 * 
 * @example Basic Usage
 * ```typescript
 * // GET request - retrieve data
 * const users = await apiRequest<User[]>('GET', '/api/users');
 * if (users.success) {
 *   console.log(users.data); // User[] type
 * }
 * 
 * // POST request - create resource
 * const newUser = await apiRequest<User>('POST', '/api/users', {
 *   data: { name: 'John Doe', email: 'john@example.com' }
 * });
 * 
 * // PUT request - full update
 * const updatedUser = await apiRequest<User>('PUT', '/api/users/1', {
 *   data: { name: 'Jane Doe', email: 'jane@example.com' }
 * });
 * 
 * // PATCH request - partial update  
 * const patchedUser = await apiRequest<User>('PATCH', '/api/users/1', {
 *   data: { email: 'newemail@example.com' }
 * });
 * 
 * // DELETE request - remove resource
 * const deleted = await apiRequest<void>('DELETE', '/api/users/1');
 * ```
 * 
 * @example Advanced Configuration
 * ```typescript
 * // With caching and revalidation
 * const cachedData = await apiRequest<Product[]>('GET', '/api/products', {
 *   cache: 'force-cache',
 *   revalidate: 3600, // 1 hour
 *   revalidateTags: ['products'],
 *   query: { category: 'electronics', limit: 10 }
 * });
 * 
 * // With custom headers and timeout
 * const response = await apiRequest<ApiResponse>('POST', '/api/upload', {
 *   data: formData,
 *   timeout: 120000, // 2 minutes
 *   customHeaders: { 'X-Upload-Type': 'profile-image' }
 * });
 * ```
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
    cache = 'no-store', // Changed default to no-store for better predictability
    revalidate,
    revalidateTags = [],
    revalidatePaths = [],
    revalidateType,
    timeout, // Will use merged limits default
    retryAttempts = 3,
    retryDelay = 1000,
    csrfToken,
    logTypes = false,
    customHeaders = {},
    clientConfig,
    includeDetailedErrors,
    limits: requestLimits,
  } = options;

  // Merge limits from all sources (no global limits from env, use defaults)
  const clientLimits = clientConfig?.limits;
  const limits = mergeLimits(undefined, clientLimits, requestLimits);

  // Use the merged timeout if not specified in options
  const finalTimeout = timeout ?? limits.defaultTimeout;

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

  if (isRateLimited(limits)) {
    return {
      success: false,
      error: createError(STATUS.RATE_LIMITED, 'RATE_LIMIT_ERROR', 'Rate limit exceeded', requestId),
      data: null,
    };
  }

  const circuitKey = `${fullUrl.origin}${fullUrl.pathname}`;
  const circuitStatus = checkCircuitBreaker(circuitKey, limits);
  if (circuitStatus.isOpen) {
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
    const timeoutId = setTimeout(() => controller.abort(), finalTimeout);

    try {
      let body: string | FormData | undefined;
      if (!['GET', 'HEAD'].includes(method)) {
        if (isFormData) {
          body = data as FormData;
        } else if (data !== undefined) {
          body = JSON.stringify(data);
          if (body.length > limits.maxPayloadSize) {
            return {
              success: false,
              error: createError(
                STATUS.PAYLOAD_TOO_LARGE,
                'VALIDATION_ERROR',
                `Payload too large (${body.length} bytes, max: ${limits.maxPayloadSize})`,
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
          tags: sanitizeTags(revalidateTags, limits),
        };
      }

      const response = await fetch(fullUrl.toString(), fetchOptions);

      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        responseHeaders[key] = value;
      });

      const contentLength = Number(response.headers.get('Content-Length') || '0');
      if (contentLength > limits.maxResponseSize) {
        return {
          success: false,
          error: createError(
            STATUS.PAYLOAD_TOO_LARGE,
            'VALIDATION_ERROR',
            `Response too large (${contentLength} bytes, max: ${limits.maxResponseSize})`,
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
        recordCircuitFailure(circuitKey, limits);

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
          recordCircuitFailure(circuitKey, limits);
          const retryAfter = response.headers.get('Retry-After');
          const delay = retryAfter
            ? Number(retryAfter) * 1000
            : retryDelay * 2 ** (attempt - 1) * (0.5 + Math.random());
          await new Promise((r) => setTimeout(r, delay));
          return makeRequest(attempt + 1);
        }

        recordCircuitFailure(circuitKey, limits);

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

      // Record success in circuit breaker
      recordCircuitSuccess(circuitKey);

      // Only invalidate cache on server-side
      if (!isClient) {
        await invalidateCache(revalidatePaths, revalidateTags, limits, revalidateType);
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

      recordCircuitFailure(circuitKey, limits);

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
     * 
     * @param method HTTP method - 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
     * @param url Request URL
     * @param options Request configuration options
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
        cache: defaults.cache || 'no-store',
        ...options,
        // Pass through the global includeDetailedErrors setting if not overridden
        includeDetailedErrors: options.includeDetailedErrors ?? config.includeDetailedErrors,
        // Pass through the global limits setting if not overridden
        limits: options.limits ? { ...config.limits, ...options.limits } : config.limits,
      };

      return apiRequest<T>(method, url, mergedOptions);
    },
  };
}

// SafeFetch Default Export - The core apiRequest function
export default apiRequest;
