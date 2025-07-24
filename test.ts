/**
 * SafeFetch – Typed fetch utility with retry, timeout & Next.js support
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * https://github.com/Bharathi4real/safe-fetch
 */

"use server";

import { revalidatePath, revalidateTag } from 'next/cache';

/**
 * Configuration for environment variables
 * Allows customizing which env vars to use
 */
export interface EnvConfig {
  authUsername?: string;
  authPassword?: string;
  authToken?: string;
  baseUrl?: string;
  allowBasicAuthInProd?: string;
}

/**
 * Default environment variable names
 */
const DEFAULT_ENV_CONFIG: Required<EnvConfig> = {
  authUsername: 'AUTH_USERNAME',
  authPassword: 'AUTH_PASSWORD',
  authToken: 'AUTH_TOKEN',
  baseUrl: 'BASE_URL',
  allowBasicAuthInProd: 'ALLOW_BASIC_AUTH_IN_PROD',
};

/**
 * Environment configuration (server-side only)
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
  };
};

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
 * Next.js specific cache options
 */
export type CacheOption =
  | 'force-cache' // Cache the request indefinitely
  | 'no-store' // Never cache (default - always fetch fresh)
  | 'no-cache' // Cache but revalidate every time
  | 'default'; // Use Next.js default caching behavior

/**
 * Query parameter types
 */
export type QueryValue = string | number | boolean | null | undefined;
export type QueryParams = Record<string, QueryValue>;

// Rate limiting and circuit breaker (shared between client/server)
const rateTimestamps: number[] = [];
const circuitMap = new Map<string, number>();

const isRateLimited = (): boolean => {
  const now = Date.now();
  while (rateTimestamps.length && rateTimestamps[0] < now - MAX.RATE_WINDOW) rateTimestamps.shift();
  if (rateTimestamps.length >= MAX.RATE_MAX) return true;
  rateTimestamps.push(now);
  return false;
};

/**
 * Client configuration passed from server
 */
export interface ClientConfig {
  baseUrl: string;
  authHeader?: string;
}

/**
 * Configuration for creating SafeFetch instance
 */
export interface SafeFetchConfig {
  /**
   * Custom environment variable names
   */
  envConfig?: EnvConfig;

  /**
   * Allowed production domains for security
   */
  allowedDomains?: string[];

  /**
   * Default request options
   */
  defaults?: {
    timeout?: number;
    retryAttempts?: number | 0;
    retryDelay?: number;
    cache?: CacheOption;
  };
}

/**
 * Server-side auth header generation
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
 * Create client config on server-side
 * This should be called in Server Components or API routes
 */
export function createClientConfig(config: SafeFetchConfig = {}): ClientConfig {
  if (typeof window !== 'undefined') {
    throw new Error('createClientConfig must run server-side');
  }

  const env = createEnv(config.envConfig);

  // Server-side validation
  if (!env.BASE_URL?.startsWith('https://')) {
    throw new Error('BASE_URL must start with https://');
  }

  const DEFAULT_ALLOWED_DOMAINS = ['api.example.com', 'another.example.com'];
  const allowedDomains = config.allowedDomains || DEFAULT_ALLOWED_DOMAINS;

  if (
    process.env.NODE_ENV === 'production' &&
    !allowedDomains.includes(new URL(env.BASE_URL).hostname)
  ) {
    throw new Error(
      `BASE_URL must be one of the allowed production domains: ${allowedDomains.join(', ')}`,
    );
  }

  return {
    baseUrl: env.BASE_URL!,
    authHeader: getAuthHeader(env),
  };
}

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
   * Only for network/server errors.
   * Default: 3
   */
  retryAttempts?: number;

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

  /**
   * Client config (required for client-side requests)
   * Pass the result of createClientConfig() from server-side
   */
  clientConfig?: ClientConfig;
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
  method: 'DELETE',
  url: string,
  options?: DeleteOptions,
): Promise<ApiResponse<T>>;
export async function apiRequest<T, TData = unknown>(
  method: 'POST',
  url: string,
  options?: PostOptions<TData>,
): Promise<ApiResponse<T>>;
export async function apiRequest<T, TData = unknown>(
  method: 'PUT',
  url: string,
  options?: PutOptions<TData>,
): Promise<ApiResponse<T>>;
export async function apiRequest<T, TData = unknown>(
  method: 'PATCH',
  url: string,
  options?: PatchOptions<TData>,
): Promise<ApiResponse<T>>;
export async function apiRequest<T>(
  method: HttpMethod,
  url: string,
  options?: RequestOptions,
): Promise<ApiResponse<T>>;

/**
 * Makes a safe, typed HTTP request to your backend or any HTTPS API.
 * Works on both server and client side.
 *
 * ## Server Usage (automatic credentials):
 * ```ts
 * const res = await apiRequest<User[]>('GET', '/api/users');
 * ```
 *
 * ## Client Usage (requires clientConfig):
 * ```ts
 * // In your Server Component or API route:
 * const clientConfig = createClientConfig();
 *
 * // Pass to client component as prop, then:
 * const res = await apiRequest<User[]>('GET', '/api/users', {
 *   clientConfig
 * });
 * ```
 *
 * ## Next.js App Router Pattern:
 * ```tsx
 * // app/page.tsx (Server Component)
 * import { createClientConfig } from './lib/safe-fetch';
 * import UserList from './components/UserList';
 *
 * export default function Page() {
 *   const clientConfig = createClientConfig();
 *   return <UserList clientConfig={clientConfig} />;
 * }
 *
 * // components/UserList.tsx (Client Component)
 * 'use client';
 * import { apiRequest, ClientConfig } from '../lib/safe-fetch';
 *
 * interface Props {
 *   clientConfig: ClientConfig;
 * }
 *
 * export default function UserList({ clientConfig }: Props) {
 *   const [users, setUsers] = useState([]);
 *
 *   useEffect(() => {
 *     apiRequest<User[]>('GET', '/api/users', { clientConfig })
 *       .then(res => res.success && setUsers(res.data));
 *   }, [clientConfig]);
 *
 *   return <div>{users.map(user => <div key={user.id}>{user.name}</div>)}</div>;
 * }
 * ```
 *
 * ## Custom Environment Variables:
 * ```ts
 * const clientConfig = createClientConfig({
 *   envConfig: {
 *     baseUrl: 'MY_API_URL',
 *     authToken: 'MY_AUTH_TOKEN'
 *   },
 *   allowedDomains: ['my-api.com']
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
    timeout = MAX.TIMEOUT,
    retryAttempts = 3,
    retryDelay = 1000,
    csrfToken,
    logTypes = false,
    customHeaders = {},
    clientConfig,
  } = options;

  // Client-side validation
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

  // Get base URL and auth from appropriate source
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
          parsedData = (await response.blob()) as unknown as T;
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

/**
 * Create a SafeFetch instance with custom configuration
 * Useful for multiple APIs or different configurations
 */
export function createSafeFetch(config: SafeFetchConfig = {}) {
  const defaults = config.defaults || {};

  return {
    /**
     * Create client config for this instance
     */
    createClientConfig: () => createClientConfig(config),

    /**
     * Make an API request with instance defaults
     */
    request: <T>(
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
      };

      return apiRequest<T>(method, url, mergedOptions);
    },
  };
}

export default apiRequest;
