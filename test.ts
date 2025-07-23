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

const PROD_ALLOWED_DOMAINS = ['api.example.com', 'another.example.com'] as const;

if (
  process.env.NODE_ENV === 'production' &&
  !PROD_ALLOWED_DOMAINS.includes(new URL(env.BASE_URL).hostname as any)
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
export const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as const;
export type HttpMethod = typeof HTTP_METHODS[number];

/**
 * HTTP status codes
 */
export const STATUS = {
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

export type StatusCode = typeof STATUS[keyof typeof STATUS];

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
  | 'no-store'         // Never cache (default)
  | 'force-cache'      // Always use cache
  | 'default'          // Browser default
  | 'no-cache'         // Revalidate before use
  | 'reload'           // Always fetch fresh
  | 'only-if-cached';  // Use cache only

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
    .map((tag) => tag.startsWith('api:') ? tag : `api:${tag}`)
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
 * Configuration options for API requests
 */
export interface ApiRequestOptions<TData = unknown> {
  /** 
   * Request data (POST/PUT/PATCH only)
   * @example { name: "John", email: "john@example.com" }
   */
  data?: TData;
  
  /** 
   * URL query parameters
   * @example { page: 1, limit: 10, search: "john" }
   */
  query?: QueryParams;
  
  /** 
   * Cache strategy
   * @default 'no-store'
   */
  cache?: CacheOption;
  
  /** 
   * Cache revalidation time in seconds
   * @example 3600 // 1 hour
   */
  revalidate?: number | false;
  
  /** 
   * Cache tags to invalidate on success
   * @example ['users', 'posts']
   */
  revalidateTags?: string[];
  
  /** 
   * Paths to revalidate on success  
   * @example ['/users', '/dashboard']
   */
  revalidatePaths?: string[];
  
  /** 
   * Revalidation type
   */
  revalidateType?: 'page' | 'layout';
  
  /** 
   * Request timeout in milliseconds
   * @default 30000
   */
  timeout?: number;
  
  /** 
   * Number of retry attempts (0-5)
   * @default 3
   */
  retryAttempts?: 0 | 1 | 2 | 3 | 4 | 5;
  
  /** 
   * Base retry delay in milliseconds
   * @default 1000
   */
  retryDelay?: number;
  
  /** 
   * CSRF token (required for POST/PUT/PATCH/DELETE)
   * Must be 32+ characters of alphanumeric, hyphens, underscores
   */
  csrfToken?: string;
  
  /** 
   * Log inferred TypeScript types in development
   * @default false
   */
  logTypes?: boolean;

  /**
   * Additional request headers
   * @example { 'X-Client-Version': '1.0.0' }
   */
  customHeaders?: Record<string, string>;
}

/**
 * Method-specific options with proper typing
 */
export type GetOptions = Omit<ApiRequestOptions<never>, 'data' | 'csrfToken'>;
export type PostOptions<T> = ApiRequestOptions<T> & { csrfToken: string };
export type PutOptions<T> = ApiRequestOptions<T> & { csrfToken: string };
export type PatchOptions<T> = ApiRequestOptions<T> & { csrfToken: string };
export type DeleteOptions = ApiRequestOptions<never> & { csrfToken: string };

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
      error: ApiError;
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
  details?: Record<string, unknown>
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

// Overloaded function signatures for perfect IntelliSense
export async function apiRequest<T>(method: 'GET', url: string, options?: GetOptions): Promise<ApiResponse<T>>;
export async function apiRequest<T>(method: 'POST', url: string, options: PostOptions<T>): Promise<ApiResponse<T>>;
export async function apiRequest<T>(method: 'PUT', url: string, options: PutOptions<T>): Promise<ApiResponse<T>>;
export async function apiRequest<T>(method: 'PATCH', url: string, options: PatchOptions<T>): Promise<ApiResponse<T>>;
export async function apiRequest<T>(method: 'DELETE', url: string, options: DeleteOptions): Promise<ApiResponse<T>>;

/**
 * Production-ready HTTP client with type safety, security, and reliability.
 * 
 * Features:
 * - Full TypeScript support with method-specific options
 * - Automatic authentication (JWT/Basic Auth)
 * - Rate limiting and circuit breaker
 * - Retry logic with exponential backoff
 * - CSRF protection for mutations
 * - Next.js cache integration
 * - Request/response size limits
 * - Comprehensive error handling
 * 
 * @example GET request
 * ```typescript
 * const users = await apiRequest<User[]>('GET', '/api/users', {
 *   query: { page: 1, limit: 10 }
 * });
 * 
 * if (users.success) {
 *   console.log(users.data); // User[] with full IntelliSense
 * } else {
 *   console.error(users.error.message);
 * }
 * ```
 * 
 * @example POST request  
 * ```typescript
 * const newUser = await apiRequest<User>('POST', '/api/users', {
 *   data: { name: 'John', email: 'john@example.com' },
 *   csrfToken: 'your-csrf-token', // Required for mutations
 *   revalidateTags: ['users']
 * });
 * ```
 * 
 * @example Advanced usage
 * ```typescript
 * const response = await apiRequest<User>('PUT', '/api/users/123', {
 *   data: { name: 'Jane' },
 *   csrfToken: 'token',
 *   cache: 'force-cache',
 *   revalidate: 3600,
 *   revalidatePaths: ['/users'],
 *   timeout: 15000,
 *   retryAttempts: 2
 * });
 * ```
 */
export async function apiRequest<T>(
  method: HttpMethod,
  url: string,
  options: ApiRequestOptions = {}
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

  // Validate method
  if (!HTTP_METHODS.includes(method)) {
    return { 
      success: false, 
      error: createError(
        STATUS.METHOD_NOT_ALLOWED, 
        'VALIDATION_ERROR',
        `Invalid method: ${method}`,
        requestId
      ), 
      data: null 
    };
  }

  // Build and validate URL
  let fullUrl: URL;
  try {
    fullUrl = new URL(url, env.BASE_URL);
  } catch {
    return {
      success: false,
      error: createError(STATUS.BAD_REQUEST, 'VALIDATION_ERROR', 'Invalid URL', requestId),
      data: null
    };
  }

  if (fullUrl.protocol !== 'https:') {
    return { 
      success: false, 
      error: createError(STATUS.BAD_REQUEST, 'VALIDATION_ERROR', 'HTTPS required', requestId),
      data: null 
    };
  }

  // Rate limiting
  if (isRateLimited()) {
    return { 
      success: false, 
      error: createError(STATUS.RATE_LIMITED, 'RATE_LIMIT_ERROR', 'Rate limit exceeded', requestId),
      data: null 
    };
  }

  // Circuit breaker
  const circuitKey = `${fullUrl.origin}${fullUrl.pathname}`;
  const now = Date.now();
  if ((circuitMap.get(circuitKey) ?? 0) > now) {
    return { 
      success: false, 
      error: createError(STATUS.SERVICE_UNAVAILABLE, 'SERVER_ERROR', 'Service unavailable', requestId),
      data: null 
    };
  }

  // Add query parameters
  if (query) {
    Object.entries(query).forEach(([key, val]) => {
      if (val != null) {
        fullUrl.searchParams.append(key, String(val));
      }
    });
  }

  // Validate request body for GET/HEAD
  if (['GET', 'HEAD'].includes(method) && data !== undefined) {
    return {
      success: false,
      error: createError(STATUS.BAD_REQUEST, 'VALIDATION_ERROR', 'GET/HEAD cannot have body', requestId),
      data: null,
    };
  }

  // Validate CSRF token for mutations
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    if (!csrfToken) {
      return { 
        success: false, 
        error: createError(STATUS.FORBIDDEN, 'AUTH_ERROR', 'CSRF token required', requestId),
        data: null 
      };
    }
    if (!/^[a-zA-Z0-9-_]{32,}$/.test(csrfToken)) {
      return { 
        success: false, 
        error: createError(STATUS.BAD_REQUEST, 'VALIDATION_ERROR', 'Invalid CSRF token', requestId),
        data: null 
      };
    }
  }

  // Get auth header
  let authHeader: string | undefined;
  try {
    authHeader = getAuthHeader();
  } catch (err) {
    return {
      success: false,
      error: createError(STATUS.UNAUTHORIZED, 'AUTH_ERROR', 'Authentication failed', requestId),
      data: null
    };
  }

  // Build headers
  const isFormData = typeof FormData !== 'undefined' && data instanceof FormData;
  const headers: Record<string, string> = {
    Accept: 'application/json',
    'X-Requested-With': 'XMLHttpRequest',
    'X-Request-ID': requestId,
    ...customHeaders,
  };
  
  if (authHeader) headers.Authorization = authHeader;
  if (!isFormData && !['GET', 'HEAD'].includes(method)) headers['Content-Type'] = 'application/json';
  if (csrfToken) headers['X-CSRF-Token'] = csrfToken;

  // Make request with retries
  const makeRequest = async (attempt = 1): Promise<ApiResponse<T>> => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      // Prepare request body
      let body: string | FormData | undefined;
      if (!['GET', 'HEAD'].includes(method)) {
        if (isFormData) {
          body = data as FormData;
        } else if (data !== undefined) {
          body = JSON.stringify(data);
          if (body.length > MAX.PAYLOAD) {
            return { 
              success: false, 
              error: createError(STATUS.PAYLOAD_TOO_LARGE, 'VALIDATION_ERROR', 'Payload too large', requestId),
              data: null 
            };
          }
        }
      }

      // Make fetch request
      const fetchOptions: RequestInit = {
        method,
        headers,
        cache,
        signal: controller.signal,
        body,
      };

      // Add Next.js cache options
      if (revalidate !== undefined || revalidateTags.length) {
        (fetchOptions as any).next = { 
          revalidate, 
          tags: sanitizeTags(revalidateTags) 
        };
      }

      const response = await fetch(fullUrl.toString(), fetchOptions);

      // Extract response headers
      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        responseHeaders[key] = value;
      });

      // Check response size
      const contentLength = Number(response.headers.get('Content-Length') || '0');
      if (contentLength > MAX.RES_SIZE) {
        return { 
          success: false, 
          error: createError(STATUS.PAYLOAD_TOO_LARGE, 'VALIDATION_ERROR', 'Response too large', requestId),
          data: null 
        };
      }

      // Parse response
      let parsedData: T;
      try {
        const contentType = response.headers.get('Content-Type') || '';
        if (contentType.includes('application/json')) {
          parsedData = await response.json();
        } else if (contentType.includes('text/')) {
          parsedData = (await response.text()) as unknown as T;
        } else {
          throw new Error(`Unsupported content type: ${contentType}`);
        }
      } catch (parseError) {
        return { 
          success: false, 
          error: createError(
            response.status as StatusCode, 
            'NETWORK_ERROR', 
            'Failed to parse response', 
            requestId
          ),
          data: null 
        };
      }

      // Handle non-OK responses
      if (!response.ok) {
        // Retry server errors
        if (response.status >= 500 && attempt < retryAttempts) {
          const retryAfter = response.headers.get('Retry-After');
          const delay = retryAfter 
            ? Number(retryAfter) * 1000
            : retryDelay * Math.pow(2, attempt - 1) * (0.5 + Math.random());
          
          await new Promise(resolve => setTimeout(resolve, delay));
          return makeRequest(attempt + 1);
        }

        // Update circuit breaker
        circuitMap.set(circuitKey, now + MAX.CIRCUIT_TTL);

        return { 
          success: false, 
          error: createError(
            response.status as StatusCode,
            getErrorType(response.status),
            response.statusText || 'Request failed',
            requestId,
            { url: url, method, attempt }
          ),
          data: null 
        };
      }

      // Success - invalidate cache
      await invalidateCache(revalidatePaths, revalidateTags, revalidateType);

      // Development type logging
      if (process.env.NODE_ENV === 'development' && logTypes) {
        console.group(`🔍 ${method} ${url} - Type Inference`);
        console.log('Inferred Type:', inferType(parsedData));
        console.groupEnd();
      }

      return { 
        success: true, 
        data: parsedData,
        status: response.status as StatusCode,
        headers: responseHeaders,
        requestId
      };

    } catch (err) {
      const isTimeout = err instanceof Error && err.name === 'AbortError';
      const isNetwork = err instanceof TypeError;

      // Retry network/timeout errors (but not mutations to avoid duplication)
      if ((isNetwork || isTimeout) && attempt < retryAttempts && ['GET', 'HEAD'].includes(method)) {
        const delay = retryDelay * Math.pow(2, attempt - 1) * (0.5 + Math.random());
        await new Promise(resolve => setTimeout(resolve, delay));
        return makeRequest(attempt + 1);
      }

      // Circuit breaker for repeated failures
      circuitMap.set(circuitKey, now + MAX.CIRCUIT_TTL);

      return {
        success: false,
        error: createError(
          isTimeout ? 408 : 500,
          isTimeout ? 'TIMEOUT_ERROR' : 'NETWORK_ERROR',
          isTimeout ? 'Request timeout' : 'Network error',
          requestId
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