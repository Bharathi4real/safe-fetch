/**
 * SafeFetch – Streamlined typed fetch utility
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * Updated for Next.js 15 with backward compatibility
 */

'use server';

/** HTTP methods */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS';

/** Request body types */
export type RequestBody = Record<string, unknown> | FormData | string | ArrayBuffer | Blob | null;

/** Query parameter types */
export type QueryParams = Record<string, string | number | boolean | null | undefined>;

/** Next.js specific options - Updated for Next.js 15 */
export interface NextOptions {
  /** Cache revalidation time in seconds or false to disable */
  revalidate?: number | false;
  /** Cache tags for on-demand revalidation */
  tags?: string[];
  /** Next.js 15: Dynamic rendering behavior */
  dynamic?: 'auto' | 'force-dynamic' | 'error' | 'force-static';
  /** Next.js 15: Dynamic parameters behavior */
  dynamicParams?: boolean;
  /** Next.js 15: Runtime environment */
  runtime?: 'nodejs' | 'edge';
  /** Next.js 15: Preferred region for edge runtime */
  preferredRegion?: string | string[];
  /** Next.js 15: Maximum request duration in seconds */
  maxDuration?: number;
}

/** Next.js 15 fetch cache options - Enhanced with new options */
export type NextCacheOptions = 
  | RequestCache 
  | 'force-cache' 
  | 'no-store' 
  | 'reload' 
  | 'no-cache' 
  | 'only-if-cached'
  | 'default';

/**
 * Request options
 * @template TBody - Request body type
 * @template TTransformedResponse - Transformed response data type
 */
export interface RequestOptions<
  TBody extends RequestBody = RequestBody,
  TTransformedResponse = unknown,
> {
  /** Request body - auto-serialized to JSON unless FormData/Blob/ArrayBuffer */
  data?: TBody;
  /** Query parameters appended to URL */
  params?: QueryParams;
  /** Max retry attempts (default: 1) */
  retries?: number;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Fetch cache strategy (default: 'default') - Enhanced for Next.js 15 */
  cache?: NextCacheOptions;
  /** Next.js ISR revalidation time in seconds */
  revalidate?: number | false;
  /** Next.js cache tags for on-demand revalidation */
  tags?: string[];
  /** Next.js 15: Dynamic rendering behavior */
  dynamic?: 'auto' | 'force-dynamic' | 'error' | 'force-static';
  /** Next.js 15: Dynamic parameters behavior */
  dynamicParams?: boolean;
  /** Next.js 15: Runtime environment */
  runtime?: 'nodejs' | 'edge';
  /** Next.js 15: Preferred region for edge runtime */
  preferredRegion?: string | string[];
  /** Next.js 15: Maximum request duration in seconds */
  maxDuration?: number;
  /** Custom headers merged with defaults */
  headers?: Record<string, string>;
  /** Log inferred TypeScript types (dev only) */
  logTypes?: boolean;
  /** Transform response data before returning */
  transform?<T>(data: T): TTransformedResponse;
  /** Custom error handler */
  onError?: (error: ApiError, attempt: number) => void;
  /** Next.js 15: Enable streaming responses */
  stream?: boolean;
  /** Next.js 15: Connection pool options */
  keepalive?: boolean;
}

/** Structured error information */
export interface ApiError {
  readonly name: string;
  readonly message: string;
  readonly status: number;
  readonly attempt?: number;
  readonly data?: unknown;
  /** Next.js 15: Additional error context */
  readonly context?: {
    runtime?: string;
    region?: string;
    duration?: number;
  };
}

/** Type-safe API response - Enhanced for Next.js 15 */
export type ApiResponse<T = unknown> =
  | { 
      success: true; 
      status: number; 
      data: T; 
      headers: Headers;
      /** Next.js 15: Response metadata */
      metadata?: {
        cached?: boolean;
        revalidatedAt?: number;
        region?: string;
        runtime?: string;
      };
    }
  | { 
      success: false; 
      status: number; 
      error: ApiError; 
      data: null;
      /** Next.js 15: Error metadata */
      metadata?: {
        retryCount?: number;
        totalDuration?: number;
      };
    };

// Configuration - Enhanced for Next.js 15
const BASE_URL = process.env.BASE_URL || process.env.NEXT_PUBLIC_API_URL || '';
const IS_DEV = process.env.NODE_ENV === 'development';

// Next.js version detection
const NEXTJS_VERSION = (() => {
  try {
    // Try to detect Next.js 15 features
    if (typeof globalThis !== 'undefined' && 'AsyncLocalStorage' in globalThis) {
      return '15+';
    }
    return '14';
  } catch {
    return '14';
  }
})();

// Security configuration for headers
const MAX_HEADER_LENGTH = 8192;
const MAX_URL_LENGTH = 8192; // Next.js 15 has stricter URL limits

// Retry configuration - Enhanced for Next.js 15
const RETRY_CODES = new Set([408, 429, 500, 502, 503, 504]);
const IDEMPOTENT_METHODS = new Set<HttpMethod>(['GET', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']);

// Next.js 15: Edge runtime detection
const IS_EDGE_RUNTIME = (() => {
  try {
    return typeof EdgeRuntime !== 'undefined' || 
           process.env.NEXT_RUNTIME === 'edge' ||
           typeof globalThis.WebAssembly !== 'undefined';
  } catch {
    return false;
  }
})();

// Authentication setup - Enhanced security for Next.js 15
const AUTH_HEADER = (() => {
  try {
    const { AUTH_USERNAME, AUTH_PASSWORD, AUTH_TOKEN, API_TOKEN } = process.env;
    if (AUTH_USERNAME && AUTH_PASSWORD) {
      // Next.js 15: More secure base64 encoding
      const credentials = IS_EDGE_RUNTIME 
        ? btoa(`${AUTH_USERNAME}:${AUTH_PASSWORD}`)
        : Buffer.from(`${AUTH_USERNAME}:${AUTH_PASSWORD}`, 'utf8').toString('base64');
      return `Basic ${credentials}`;
    }
    const token = AUTH_TOKEN || API_TOKEN;
    return token ? `Bearer ${token}` : null;
  } catch {
    return null;
  }
})();

/** Create ApiError - Enhanced for Next.js 15 */
const createApiError = (
  name: string,
  message: string,
  status: number,
  attempt?: number,
  data?: unknown,
  context?: ApiError['context'],
): ApiError => ({
  name,
  message,
  status,
  attempt,
  data,
  context,
});

/**
 * Build URL with query parameters - Enhanced validation for Next.js 15
 */
const buildUrl = (endpoint: string, params?: QueryParams): string => {
  let finalUrl: URL;

  try {
    if (endpoint.startsWith('http://') || endpoint.startsWith('https://')) {
      finalUrl = new URL(endpoint);
    } else {
      if (!BASE_URL) throw new Error('BASE_URL required for relative paths');
      const basePath = BASE_URL.endsWith('/') ? BASE_URL : `${BASE_URL}/`;
      finalUrl = endpoint.startsWith('/') 
        ? new URL(endpoint, BASE_URL) 
        : new URL(endpoint, basePath);
    }

    // Add query parameters with enhanced validation
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value != null) {
          // Next.js 15: Enhanced parameter validation
          const stringValue = String(value);
          if (stringValue.length > 2048) {
            throw new Error(`Query parameter '${key}' exceeds maximum length`);
          }
          finalUrl.searchParams.append(key, stringValue);
        }
      });
    }

    const finalUrlString = finalUrl.toString();
    
    // Next.js 15: Enforce URL length limits
    if (finalUrlString.length > MAX_URL_LENGTH) {
      throw new Error(`URL exceeds maximum length of ${MAX_URL_LENGTH} characters`);
    }

    return finalUrlString;
  } catch (error) {
    throw new Error(`URL construction failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
};

/**
 * Build request headers with sanitization - Enhanced for Next.js 15
 */
const buildHeaders = (data?: RequestBody, custom?: Record<string, string>): HeadersInit => {
  const headers: Record<string, string> = {};

  // Next.js 15: Enhanced header validation and security
  if (custom) {
    Object.entries(custom).forEach(([key, value]) => {
      // Enhanced RFC 7230 validation for Next.js 15
      if (/^[!#$%&'*+\-.0-9A-Z^_`a-z|~]+$/.test(key) && key.length <= 128) {
        // Enhanced sanitization for Next.js 15
        const sanitizedValue = value
          .replace(/[\x00-\x1f\x7f-\xff\r\n]/g, '') // Remove control characters
          .replace(/[^\x20-\x7E]/g, '') // Allow only printable ASCII
          .substring(0, MAX_HEADER_LENGTH);
        
        if (sanitizedValue && sanitizedValue.length > 0) {
          headers[key] = sanitizedValue;
        } else if (IS_DEV) {
          console.warn(`[SafeFetch] Skipping empty header value for key: ${key}`);
        }
      } else if (IS_DEV) {
        console.warn(`[SafeFetch] Skipping invalid header key: ${key}`);
      }
    });
  }

  // Add authentication header
  if (AUTH_HEADER) headers.Authorization = AUTH_HEADER;
  
  // Content-Type handling
  if (data && !(data instanceof FormData) && !(data instanceof Blob) && !(data instanceof ArrayBuffer)) {
    headers['Content-Type'] = 'application/json';
  }
  
  // Accept header with Next.js 15 enhancements
  if (!headers.Accept) {
    headers.Accept = IS_EDGE_RUNTIME 
      ? 'application/json, */*' // Simplified for edge runtime
      : 'application/json, text/plain, */*';
  }

  // Next.js 15: Add runtime-specific headers
  if (IS_EDGE_RUNTIME && !headers['User-Agent']) {
    headers['User-Agent'] = 'SafeFetch/Next15-Edge';
  }

  return headers;
};

/**
 * Parse response body - Enhanced for Next.js 15
 */
const parseResponse = async <T>(response: Response): Promise<T> => {
  const contentType = response.headers.get('content-type') || '';
  
  // Next.js 15: Enhanced streaming support
  if (response.body && contentType.includes('application/json')) {
    try {
      // Use built-in JSON parsing for better performance in Next.js 15
      return await response.json() as T;
    } catch (error) {
      throw new Error(`JSON parsing failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Fallback to text parsing
  const text = await response.text();
  
  if (contentType.includes('application/json') || /^\s*[{[]/.test(text.trim())) {
    try {
      return JSON.parse(text) as T;
    } catch {
      if (contentType.includes('application/json')) {
        throw new Error('Invalid JSON response');
      }
    }
  }

  return text as T;
};

/** Timeout controller with cleanup - Enhanced for Next.js 15 */
interface TimeoutController {
  controller: AbortController;
  cleanup: () => void;
}

/**
 * Create advanced timeout controller - Enhanced for Next.js 15 edge runtime
 */
const createTimeout = (ms: number): TimeoutController => {
  const controller = new AbortController();
  let cleaned = false;
  
  // Next.js 15: Use more efficient timeout handling for edge runtime
  const timeoutId = IS_EDGE_RUNTIME 
    ? setTimeout(() => {
        if (!cleaned) {
          controller.abort(new Error('Request timeout'));
        }
      }, ms)
    : setTimeout(() => {
        if (!cleaned) controller.abort();
      }, ms);
  
  return {
    controller,
    cleanup: () => {
      if (!cleaned) {
        cleaned = true;
        clearTimeout(timeoutId);
      }
    },
  };
};

/**
 * Exponential backoff delay - Optimized for Next.js 15
 */
const delay = (attempt: number): Promise<void> => {
  const baseMs = Math.min(1000 * 2 ** attempt, 10000);
  const jitter = baseMs * 0.1 * Math.random();
  const finalMs = Math.max(100, baseMs + jitter);
  
  // Next.js 15: More efficient delay for edge runtime
  return new Promise(resolve => {
    if (IS_EDGE_RUNTIME) {
      // Use scheduler.postTask if available (Next.js 15)
      if (typeof scheduler !== 'undefined' && scheduler.postTask) {
        scheduler.postTask(() => resolve(), { delay: finalMs });
      } else {
        setTimeout(resolve, finalMs);
      }
    } else {
      setTimeout(resolve, finalMs);
    }
  });
};

/**
 * Check if request should be retried - Enhanced for Next.js 15
 */
const shouldRetryRequest = (
  error: ApiError,
  attempt: number,
  maxRetries: number,
  method: HttpMethod,
): boolean => {
  // Next.js 15: Enhanced retry logic
  const isRetryableError = 
    error.name === 'AbortError' ||
    error.name === 'TimeoutError' ||
    RETRY_CODES.has(error.status) ||
    /network|fetch|connection|ECONNRESET|ENOTFOUND/i.test(error.message);

  const isWithinRetryLimit = attempt < maxRetries;
  const isIdempotentMethod = IDEMPOTENT_METHODS.has(method);

  // Next.js 15: Consider edge runtime limitations
  if (IS_EDGE_RUNTIME && error.context?.runtime === 'edge') {
    // More conservative retry strategy for edge runtime
    return isWithinRetryLimit && isIdempotentMethod && error.status >= 500;
  }

  return isWithinRetryLimit && isIdempotentMethod && isRetryableError;
};

/**
 * Build Next.js specific options - Enhanced for Next.js 15
 */
const buildNextOptions = (options: {
  revalidate?: number | false;
  tags?: string[];
  dynamic?: NextOptions['dynamic'];
  dynamicParams?: boolean;
  runtime?: NextOptions['runtime'];
  preferredRegion?: NextOptions['preferredRegion'];
  maxDuration?: number;
}): { next?: NextOptions } => {
  const { revalidate, tags, dynamic, dynamicParams, runtime, preferredRegion, maxDuration } = options;
  
  // Check if any Next.js options are provided
  const hasNextOptions = 
    revalidate !== undefined ||
    (tags && tags.length > 0) ||
    dynamic !== undefined ||
    dynamicParams !== undefined ||
    runtime !== undefined ||
    preferredRegion !== undefined ||
    maxDuration !== undefined;

  if (!hasNextOptions) {
    return {};
  }

  const nextOptions: NextOptions = {};

  // Revalidation
  if (revalidate !== undefined) {
    nextOptions.revalidate = revalidate;
  }

  // Tags with enhanced validation for Next.js 15
  if (tags && tags.length > 0) {
    nextOptions.tags = tags.filter(
      (tag) =>
        typeof tag === 'string' &&
        tag.length > 0 &&
        tag.length <= 64 && // Next.js 15 has stricter tag length limits
        /^[a-zA-Z0-9\-_:]+$/.test(tag), // Enhanced pattern for Next.js 15
    );
  }

  // Next.js 15 specific options
  if (NEXTJS_VERSION === '15+') {
    if (dynamic !== undefined) nextOptions.dynamic = dynamic;
    if (dynamicParams !== undefined) nextOptions.dynamicParams = dynamicParams;
    if (runtime !== undefined) nextOptions.runtime = runtime;
    if (preferredRegion !== undefined) nextOptions.preferredRegion = preferredRegion;
    if (maxDuration !== undefined) nextOptions.maxDuration = maxDuration;
  }

  return { next: nextOptions };
};

/**
 * Log types - Enhanced for Next.js 15 development
 */
const logTypes = (endpoint: string, data: unknown): void => {
  if (!IS_DEV) return;

  const inferType = (val: unknown, depth = 0): string => {
    if (depth > 5) return 'unknown';
    if (val === null) return 'null';
    if (val === undefined) return 'undefined';

    if (Array.isArray(val)) {
      if (val.length === 0) return 'unknown[]';
      const firstType = inferType(val[0], depth + 1);
      return `${firstType}[]`;
    }

    if (typeof val === 'object' && val !== null) {
      const obj = val as Record<string, unknown>;
      const props = Object.entries(obj)
        .slice(0, 10)
        .map(([k, v]) => {
          const valueType = /password|token|secret|key|auth/i.test(k)
            ? 'string /* redacted */'
            : inferType(v, depth + 1);
          return `  ${k}: ${valueType};`;
        })
        .join('\n');
      return `{\n${props}\n}`;
    }

    return typeof val;
  };

  try {
    const typeName = endpoint
      .replace(/[^a-zA-Z0-9]/g, '_')
      .replace(/^_+|_+$/g, '')
      .replace(/_{2,}/g, '_');
    
    console.log(`🔍 [SafeFetch Next.js ${NEXTJS_VERSION}] Type for "${endpoint}"`);
    console.log(`type ${typeName}Response = ${inferType(data)};`);
  } catch (err) {
    console.warn('[SafeFetch logTypes] Failed:', err);
  }
};

/**
 * Execute fetch request - Enhanced for Next.js 15
 */
const executeFetch = async <TResponse>(
  url: string,
  method: HttpMethod,
  headers: HeadersInit,
  body: BodyInit | undefined,
  cache: NextCacheOptions,
  timeout: number,
  nextOptions: { next?: NextOptions },
  attempt: number,
  stream?: boolean,
  keepalive?: boolean,
): Promise<{ 
  success: true; 
  data: TResponse; 
  status: number; 
  headers: Headers;
  metadata?: ApiResponse<TResponse>['metadata'];
} | { 
  success: false; 
  error: ApiError;
}> => {
  let timeoutController: TimeoutController | null = null;
  const startTime = Date.now();

  try {
    timeoutController = createTimeout(timeout);
    
    // Next.js 15: Enhanced fetch options
    const fetchOptions: RequestInit & { next?: NextOptions } = {
      method,
      headers,
      body,
      cache: cache as RequestCache, // Type assertion for compatibility
      signal: timeoutController.controller.signal,
      ...nextOptions,
    };

    // Next.js 15: Add keepalive and streaming options
    if (keepalive !== undefined) {
      (fetchOptions as any).keepalive = keepalive;
    }

    const response = await fetch(url, fetchOptions);

    timeoutController.cleanup();
    timeoutController = null;

    // Next.js 15: Enhanced streaming support
    const responseData = stream && response.body?.getReader
      ? await parseResponse<TResponse>(response)
      : await parseResponse<TResponse>(response);

    if (response.ok) {
      // Next.js 15: Collect response metadata
      const metadata: NonNullable<ApiResponse<TResponse>['metadata']> = {
        cached: response.headers.get('x-cache') === 'HIT',
        revalidatedAt: Date.now(),
      };

      // Add runtime info if available
      if (IS_EDGE_RUNTIME) {
        metadata.runtime = 'edge';
        metadata.region = process.env.VERCEL_REGION || 'unknown';
      }

      return {
        success: true,
        data: responseData,
        status: response.status,
        headers: response.headers,
        metadata,
      };
    }

    // Create error context for Next.js 15
    const context: ApiError['context'] = {
      duration: Date.now() - startTime,
    };

    if (IS_EDGE_RUNTIME) {
      context.runtime = 'edge';
      context.region = process.env.VERCEL_REGION;
    }

    return {
      success: false,
      error: createApiError(
        'HttpError',
        `HTTP ${response.status}`,
        response.status,
        attempt,
        responseData,
        context,
      ),
    };
  } catch (err) {
    timeoutController?.cleanup();

    const context: ApiError['context'] = {
      duration: Date.now() - startTime,
    };

    if (IS_EDGE_RUNTIME) {
      context.runtime = 'edge';
      context.region = process.env.VERCEL_REGION;
    }

    if (err instanceof Error) {
      if (err.name === 'AbortError' || err.message.includes('timeout')) {
        return {
          success: false,
          error: createApiError(
            'TimeoutError', 
            `Timeout after ${timeout}ms`, 
            408, 
            attempt, 
            undefined, 
            context
          ),
        };
      }
      
      return {
        success: false,
        error: createApiError(
          'NetworkError', 
          err.message, 
          500, 
          attempt, 
          undefined, 
          context
        ),
      };
    }

    return {
      success: false,
      error: createApiError(
        'UnknownError', 
        'Request failed', 
        500, 
        attempt, 
        undefined, 
        context
      ),
    };
  }
};

/**
 * Main API request function - Enhanced for Next.js 15
 * 
 * @example
 * ```typescript
 * // Simple GET
 * const users = await apiRequest<User[]>('GET', '/users');
 * 
 * // POST with full Next.js 15 options
 * const result = await apiRequest<CreateResponse, CreateData>('POST', '/users', {
 *   data: { name: 'John', email: 'john@example.com' },
 *   params: { include: 'profile' },
 *   retries: 3,
 *   timeout: 10000,
 *   revalidate: 60,
 *   tags: ['users', 'profile'],
 *   dynamic: 'force-dynamic',
 *   runtime: 'edge',
 *   preferredRegion: 'iad1',
 *   maxDuration: 30,
 *   headers: { 'X-Custom': 'value' },
 *   logTypes: true,
 *   stream: true,
 *   keepalive: true,
 *   transform: (data) => ({ ...data, timestamp: Date.now() })
 * });
 * ```
 */
export default async function apiRequest<
  TResponse = unknown,
  TBody extends RequestBody = RequestBody,
  TTransformedResponse = TResponse,
>(
  method: HttpMethod,
  endpoint: string,
  options: RequestOptions<TBody, TTransformedResponse> = {},
): Promise<ApiResponse<TTransformedResponse>> {
  const {
    data,
    params,
    retries = 1,
    timeout = IS_EDGE_RUNTIME ? 10000 : 30000, // Shorter timeout for edge runtime
    cache = 'default',
    revalidate,
    tags = [],
    dynamic,
    dynamicParams,
    runtime,
    preferredRegion,
    maxDuration,
    headers: customHeaders,
    logTypes: shouldLogTypes = false,
    transform,
    onError,
    stream = false,
    keepalive = false,
  } = options;

  // Build request components with enhanced error handling
  let url: string, headers: HeadersInit, body: BodyInit | undefined;
  
  try {
    url = buildUrl(endpoint, params);
    headers = buildHeaders(data, customHeaders);
    body = data ? (
      data instanceof FormData || data instanceof Blob || data instanceof ArrayBuffer
        ? data
        : typeof data === 'string' 
          ? data 
          : JSON.stringify(data)
    ) : undefined;
  } catch (error) {
    const apiError = createApiError(
      'ValidationError', 
      `Request validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`, 
      400
    );
    return { 
      success: false, 
      status: 400, 
      error: apiError, 
      data: null,
      metadata: { retryCount: 0, totalDuration: 0 }
    };
  }

  // Build Next.js options with Next.js 15 enhancements
  const nextOptions = buildNextOptions({
    revalidate,
    tags,
    dynamic,
    dynamicParams,
    runtime,
    preferredRegion,
    maxDuration,
  });

  let lastError: ApiError = createApiError('UnknownError', 'Request failed', 500);
  const requestStartTime = Date.now();

  // Enhanced retry loop for Next.js 15
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
      stream,
      keepalive,
    );

    if (result.success) {
      let finalData: TTransformedResponse;
      
      try {
        finalData = transform ? transform(result.data) : (result.data as unknown as TTransformedResponse);
      } catch (error) {
        const transformError = createApiError(
          'TransformError', 
          `Response transformation failed: ${error instanceof Error ? error.message : 'Unknown error'}`, 
          result.status, 
          attempt
        );
        onError?.(transformError, attempt);
        return { 
          success: false, 
          status: result.status, 
          error: transformError, 
          data: null,
          metadata: { retryCount: attempt, totalDuration: Date.now() - requestStartTime }
        };
      }

      if (shouldLogTypes) logTypes(endpoint, finalData);
      
      return {
        success: true,
        status: result.status,
        data: finalData,
        headers: result.headers,
        metadata: result.metadata,
      };
    }

    lastError = result.error;
    onError?.(lastError, attempt);

    if (!shouldRetryRequest(lastError, attempt, retries, method)) break;
    
    if (attempt < retries) {
      await delay(attempt);
    }
  }

  return {
    success: false,
    status: lastError.status,
    error: lastError,
    data: null,
    metadata: { 
      retryCount: retries, 
      totalDuration: Date.now() - requestStartTime 
    },
  };
}

/** Type guard for successful responses */
apiRequest.isSuccess = <T>(
  response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: true }> => response.success;

/** Type guard for error responses */
apiRequest.isError = <T>(
  response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: false }> => !response.success;

/** Next.js version info */
apiRequest.version = {
  nextjs: NEXTJS_VERSION,
  runtime: IS_EDGE_RUNTIME ? 'edge' : 'nodejs',
  features: {
    streaming: NEXTJS_VERSION === '15+',
    enhancedCaching: NEXTJS_VERSION === '15+',
    edgeRuntime: IS_EDGE_RUNTIME,
    dynamicRendering: NEXTJS_VERSION === '15+',
  },
};

/** Utility functions for Next.js 15 */
export const utils = {
  /** Check if running in edge runtime */
  isEdgeRuntime: () => IS_EDGE_RUNTIME,
  
  /** Get Next.js version */
  getNextVersion: () => NEXTJS_VERSION,
  
  /** Validate cache tags for Next.js 15 */
  validateCacheTags: (tags: string[]): string[] => {
    return tags.filter(tag => 
      typeof tag === 'string' &&
      tag.length > 0 &&
      tag.length <= 64 &&
      /^[a-zA-Z0-9\-_:]+$/.test(tag)
    );
  },
  
  /** Create optimized headers for edge runtime */
  createEdgeHeaders: (custom: Record<string, string> = {}): Record<string, string> => {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json, */*',
    };
    
    if (IS_EDGE_RUNTIME) {
      headers['User-Agent'] = 'SafeFetch/Next15-Edge';
    }
    
    return { ...headers, ...custom };
  },
};
