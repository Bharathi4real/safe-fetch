/**
 * SafeFetch – Next.js typed fetch utility with retry, timeout & caching
 * Optimized version with essential features
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
}

/**
 * Supported HTTP methods with enhanced IntelliSense
 * @example 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
 */
export type HttpMethod =
  | 'GET' // Retrieve data from server
  | 'POST' // Create new resource
  | 'PUT' // Update entire resource
  | 'PATCH' // Partial update of resource
  | 'DELETE'; // Remove resource from server;

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
  TIMEOUT: 408,
  RATE_LIMITED: 429,
  INTERNAL_ERROR: 500,
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

// Default configuration
const DEFAULT_ENV_CONFIG = {
  authUsername: 'AUTH_USERNAME',
  authPassword: 'AUTH_PASSWORD',
  authToken: 'AUTH_TOKEN',
  baseUrl: 'BASE_URL',
  allowBasicAuthInProd: 'ALLOW_BASIC_AUTH_IN_PROD',
};

const DEFAULT_TIMEOUT = 60000;
const MAX_RETRIES = 3;
const RETRY_DELAY = 1000;
const RATE_LIMIT_WINDOW = 60000;
const RATE_LIMIT_MAX = 100;

// Environment variables type
interface EnvVars {
  AUTH_USERNAME?: string;
  AUTH_PASSWORD?: string;
  AUTH_TOKEN?: string;
  BASE_URL: string;
  ALLOW_BASIC_AUTH_IN_PROD: boolean;
}

// Simple rate limiting
const rateLimitMap = new Map<string, number[]>();
let envCache: EnvVars | null = null;

// Creates environment configuration object from process.env
const createEnv = (envConfig: EnvConfig = {}): EnvVars | Record<string, never> => {
  if (typeof window !== 'undefined') return {};

  if (!envCache) {
    const config = { ...DEFAULT_ENV_CONFIG, ...envConfig };
    envCache = {
      AUTH_USERNAME: process.env[config.authUsername]?.trim(),
      AUTH_PASSWORD: process.env[config.authPassword]?.trim(),
      AUTH_TOKEN: process.env[config.authToken]?.trim(),
      BASE_URL: process.env[config.baseUrl]?.trim() || '',
      ALLOW_BASIC_AUTH_IN_PROD: process.env[config.allowBasicAuthInProd] === 'true',
    };
  }

  return envCache;
};

// Client configuration for making requests
export interface ClientConfig {
  baseUrl: string;
  authHeader?: string;
  forwardedHeaders?: Record<string, string>;
}

// Configuration for SafeFetch instance
export interface SafeFetchConfig {
  envConfig?: EnvConfig;
  allowedDomains?: string[];
  defaults?: {
    timeout?: number;
    retryAttempts?: number;
    retryDelay?: number;
    cache?: NextCacheStrategy;
  };
}

// Generates authorization header from environment variables
const getAuthHeader = (env: EnvVars | Record<string, never>): string | undefined => {
  if (typeof window !== 'undefined') throw new Error('getAuthHeader must run server-side');

  // Type guard to check if env has the required properties
  if (!('AUTH_TOKEN' in env)) return undefined;

  const envVars = env as EnvVars;

  if (envVars.AUTH_TOKEN) return `Bearer ${envVars.AUTH_TOKEN}`;

  if (process.env.NODE_ENV === 'production' && !envVars.ALLOW_BASIC_AUTH_IN_PROD) {
    throw new Error('Basic Auth not allowed in production without ALLOW_BASIC_AUTH_IN_PROD=true');
  }

  if (envVars.AUTH_USERNAME && envVars.AUTH_PASSWORD) {
    return `Basic ${Buffer.from(`${envVars.AUTH_USERNAME}:${envVars.AUTH_PASSWORD}`).toString('base64')}`;
  }

  return undefined;
};

/**
 * Creates client configuration for API requests (server-side only)
 */
export async function createClientConfig(config: SafeFetchConfig = {}): Promise<ClientConfig> {
  if (typeof window !== 'undefined') {
    throw new Error('createClientConfig must run server-side');
  }

  const env = createEnv(config.envConfig) as EnvVars;

  if (!env.BASE_URL?.startsWith('https://')) {
    throw new Error('BASE_URL must start with https://');
  }

  const forwardedHeaders: Record<string, string> = {};

  try {
    const headersList = await headers();
    const userAgent = headersList.get('user-agent');
    const xForwardedFor = headersList.get('x-forwarded-for');

    if (userAgent) forwardedHeaders['User-Agent'] = userAgent;
    if (xForwardedFor) forwardedHeaders['X-Forwarded-For'] = xForwardedFor;
  } catch {
    // Headers not available in some contexts
  }

  return {
    baseUrl: env.BASE_URL!,
    authHeader: getAuthHeader(env),
    forwardedHeaders,
  };
}

// Simple rate limiting check
const isRateLimited = (key: string): boolean => {
  const now = Date.now();
  const timestamps = rateLimitMap.get(key) || [];
  const recent = timestamps.filter((t) => now - t < RATE_LIMIT_WINDOW);

  if (recent.length >= RATE_LIMIT_MAX) return true;

  recent.push(now);
  rateLimitMap.set(key, recent);
  return false;
};

// Sanitizes cache tags
const sanitizeTags = (tags: string[]): string[] =>
  tags
    .filter((tag) => /^[\w:-]+$/.test(tag))
    .map((tag) => (tag.startsWith('api:') ? tag : `api:${tag}`))
    .slice(0, 10); // Max 10 tags

// Invalidates Next.js cache for specified paths and tags
const invalidateCache = async (
  paths: string[] = [],
  tags: string[] = [],
  type?: 'page' | 'layout',
): Promise<void> => {
  if (typeof window !== 'undefined') return;

  const safePaths = paths.filter((p) => p.startsWith('/') && !p.includes('..')).slice(0, 10);
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
      error: ApiError;
      data: null;
    };

// Infers TypeScript type from runtime value for development logging
function inferType(val: unknown, depth = 0): string {
  if (val === null) return 'null';
  if (val === undefined) return 'undefined';
  if (Array.isArray(val)) {
    const itemType = val.length > 0 ? inferType(val[0], depth) : 'unknown';
    return `${itemType}[]`;
  }
  if (typeof val === 'object' && val !== null) {
    if (depth > 2) return 'object';
    const indent = '  '.repeat(depth);
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
const HTTP_METHODS: readonly HttpMethod[] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as const;
const isValidMethod = (method: string): method is HttpMethod =>
  HTTP_METHODS.includes(method as HttpMethod);

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
    cache = 'no-store',
    revalidate,
    revalidateTags = [],
    revalidatePaths = [],
    revalidateType,
    timeout = DEFAULT_TIMEOUT,
    retryAttempts = MAX_RETRIES,
    retryDelay = RETRY_DELAY,
    csrfToken,
    logTypes = false,
    customHeaders = {},
    clientConfig,
  } = options;

  if (isClient && !clientConfig) {
    return {
      success: false,
      error: createError(
        STATUS.BAD_REQUEST,
        'VALIDATION_ERROR',
        'clientConfig is required for client-side requests',
        requestId,
      ),
      data: null,
    };
  }

  if (!isValidMethod(method)) {
    return {
      success: false,
      error: createError(
        STATUS.BAD_REQUEST,
        'VALIDATION_ERROR',
        `Invalid HTTP method: ${method}`,
        requestId,
      ),
      data: null,
    };
  }

  const env = createEnv() as EnvVars;
  const baseUrl = isClient ? clientConfig!.baseUrl : env.BASE_URL;
  const authHeader = isClient ? clientConfig!.authHeader : getAuthHeader(env);

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

  if (isRateLimited(fullUrl.hostname)) {
    return {
      success: false,
      error: createError(STATUS.RATE_LIMITED, 'RATE_LIMIT_ERROR', 'Rate limit exceeded', requestId),
      data: null,
    };
  }

  if (query) {
    for (const [key, val] of Object.entries(query)) {
      if (val != null) fullUrl.searchParams.append(key, String(val));
    }
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

  const isFormData = typeof FormData !== 'undefined' && data instanceof FormData;
  const headers: Record<string, string> = {
    Accept: 'application/json',
    'X-Requested-With': 'XMLHttpRequest',
    'X-Request-ID': requestId,
    ...customHeaders,
  };

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

      let parsedData: T;
      try {
        const contentType = response.headers.get('Content-Type') || '';
        if (contentType.includes('application/json')) {
          parsedData = await response.json();
        } else if (contentType.startsWith('text/')) {
          parsedData = (await response.text()) as unknown as T;
        } else {
          parsedData = (await response.blob()) as unknown as T;
        }
      } catch (_error) {
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
          const delay = retryDelay * 2 ** (attempt - 1);
          await new Promise((r) => setTimeout(r, delay));
          return makeRequest(attempt + 1);
        }

        return {
          success: false,
          error: createError(
            response.status as StatusCode,
            getErrorType(response.status),
            response.statusText || 'Request failed',
            requestId,
          ),
          data: null,
        };
      }

      // Invalidate cache on server-side
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
        const delay = retryDelay * 2 ** (attempt - 1);
        await new Promise((r) => setTimeout(r, delay));
        return makeRequest(attempt + 1);
      }

      return {
        success: false,
        error: createError(
          isTimeout ? STATUS.TIMEOUT : STATUS.INTERNAL_ERROR,
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
        timeout: defaults.timeout || DEFAULT_TIMEOUT,
        retryAttempts: defaults.retryAttempts || MAX_RETRIES,
        retryDelay: defaults.retryDelay || RETRY_DELAY,
        cache: defaults.cache || 'no-store',
        ...options,
      };

      return apiRequest<T>(method, url, mergedOptions);
    },
  };
}

// SafeFetch Default Export - The core apiRequest function

export default apiRequest;
