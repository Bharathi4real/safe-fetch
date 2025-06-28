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
  /** Allowed hosts for SSRF protection (merged with ALLOWED_HOSTS env var) */
  allowedHosts?: string[];
  /** Maximum response size in bytes (default: 10MB) */
  maxResponseSize?: number;
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

// Environment and security configuration
const BASE_URL = process.env.BASE_URL || process.env.NEXT_PUBLIC_API_URL || '';
const IS_DEV = process.env.NODE_ENV === 'development';
const MAX_RESPONSE_SIZE_DEFAULT = 10 * 1024 * 1024; // 10MB

// Parse allowed hosts from environment (comma-separated)
const ENV_ALLOWED_HOSTS = (() => {
  const hostsEnv =
    process.env.ALLOWED_HOSTS || process.env.SAFEFETCH_ALLOWED_HOSTS;
  return hostsEnv
    ? hostsEnv
        .split(',')
        .map((h) => h.trim().toLowerCase())
        .filter((h) => h && /^[a-z0-9.-]+$/.test(h))
    : [];
})();

// Security and retry configuration
const SECURITY = {
  allowedProtocols: new Set(['http:', 'https:']),
  blockedHosts: new Set([
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    '169.254.169.254',
    '100.100.100.200',
    'metadata.google.internal',
    'metadata',
  ]),
  blockedIpRanges: [
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[01])\./,
    /^192\.168\./,
    /^::1$/,
    /^fe80:/,
    /^fc00:/,
  ],
  maxUrlLength: 2048,
  maxHeaderLength: 8192,
};

const RETRY = {
  codes: new Set([408, 429, 500, 502, 503, 504]),
  idempotentMethods: new Set<HttpMethod>([
    'GET',
    'PUT',
    'DELETE',
    'HEAD',
    'OPTIONS',
  ]),
};

// Safe authentication setup
const AUTH_HEADER = (() => {
  try {
    const { AUTH_USERNAME, AUTH_PASSWORD, AUTH_TOKEN, API_TOKEN } = process.env;
    if (AUTH_USERNAME && AUTH_PASSWORD) {
      return `Basic ${Buffer.from(`${AUTH_USERNAME}:${AUTH_PASSWORD}`, 'utf8').toString('base64')}`;
    }
    const token = AUTH_TOKEN || API_TOKEN;
    return token && /^[A-Za-z0-9\-._~+/]+=*$/.test(token)
      ? `Bearer ${token}`
      : null;
  } catch {
    return null;
  }
})();

// Helper for creating ApiError to reduce repetition and streamline error handling
const createApiError = (
  name: string,
  message: string,
  status: number,
  attempt?: number,
): ApiError => ({
  name,
  message,
  status,
  attempt,
});

/** Validate URL for SSRF protection */
const isUrlSafe = (url: string, allowedHosts?: string[]): boolean => {
  try {
    if (url.length > SECURITY.maxUrlLength) return false;
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();

    // Protocol, blocked hosts, IP range checks
    if (
      !SECURITY.allowedProtocols.has(parsed.protocol) ||
      SECURITY.blockedHosts.has(hostname) ||
      SECURITY.blockedIpRanges.some((range) => range.test(hostname))
    )
      return false;

    // Allowed hosts check
    const allAllowed = [
      ...ENV_ALLOWED_HOSTS,
      ...(allowedHosts?.map((h) => h.toLowerCase()) || []),
    ];
    if (
      allAllowed.length > 0 &&
      !allAllowed.some((h) => hostname === h || hostname.endsWith(`.${h}`))
    )
      return false;

    // No credentials, standard ports only
    return (
      !parsed.username &&
      !parsed.password &&
      (!parsed.port || ['80', '443', ''].includes(parsed.port))
    );
  } catch {
    return false;
  }
};

/** Build secure URL with query parameters */
const buildUrl = (
  endpoint: string,
  params?: QueryParams,
  allowedHosts?: string[],
): string => {
  let finalUrl: URL;

  if (endpoint.startsWith('http://') || endpoint.startsWith('https://')) {
    if (!isUrlSafe(endpoint, allowedHosts))
      throw new Error('URL not allowed: potential SSRF risk');
    finalUrl = new URL(endpoint);
  } else {
    if (!BASE_URL) throw new Error('BASE_URL required for relative paths');
    const basePath = BASE_URL.endsWith('/') ? BASE_URL : `${BASE_URL}/`;
    const fullUrl = endpoint.startsWith('/')
      ? new URL(endpoint, BASE_URL).toString()
      : new URL(endpoint, basePath).toString();
    if (!isUrlSafe(fullUrl, allowedHosts))
      throw new Error('URL not allowed: potential SSRF risk');
    finalUrl = endpoint.startsWith('/')
      ? new URL(endpoint, BASE_URL)
      : new URL(endpoint, basePath);
  }

  // Add sanitized query parameters
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (value != null) {
        const sanitizedKey = key.replace(/[^\w\-_.]/g, '').substring(0, 100);
        const sanitizedValue = String(value)
          .substring(0, 1000)
          .replace(/[\x00-\x1f\x7f-\x9f]/g, '');
        if (sanitizedKey && sanitizedValue)
          finalUrl.searchParams.append(sanitizedKey, sanitizedValue);
      }
    });
  }

  return finalUrl.toString();
};

/** Build request headers */
const buildHeaders = (
  data?: RequestBody,
  custom?: Record<string, string>,
): HeadersInit => {
  const headers: Record<string, string> = {};

  // Sanitize custom headers
  if (custom) {
    Object.entries(custom).forEach(([key, value]) => {
      if (/^[!#$%&'*+\-.0-9A-Z^_`a-z|~]+$/.test(key)) {
        const sanitizedValue = value
          .replace(/[\x00-\x1f\x7f-\xff]/g, '')
          .substring(0, SECURITY.maxHeaderLength);
        if (sanitizedValue) headers[key] = sanitizedValue;
      }
    });
  }

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

/** Parse response with size limits and intelligent content-type handling */
const parseResponse = async <T>(
  response: Response,
  maxSize: number,
): Promise<T> => {
  const contentType = response.headers.get('content-type') || '';
  const contentLength = response.headers.get('content-length');

  if (contentLength && parseInt(contentLength, 10) > maxSize) {
    throw new Error(
      `Response too large: ${contentLength} bytes (max: ${maxSize})`,
    );
  }

  const reader = response.body?.getReader();
  if (!reader) return '' as T;

  const chunks: Uint8Array[] = [];
  let totalSize = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      totalSize += value.length;
      if (totalSize > maxSize)
        throw new Error(`Response too large: exceeded ${maxSize} bytes`);
      chunks.push(value);
    }

    const combined = new Uint8Array(totalSize);
    let offset = 0;
    for (const chunk of chunks) {
      combined.set(chunk, offset);
      offset += chunk.length;
    }

    const text = new TextDecoder('utf-8', { fatal: false }).decode(combined);

    // Parse JSON if content-type indicates or text looks like JSON
    if (
      contentType.includes('application/json') ||
      /^[{\[]/.test(text.trim()) // Simplified check for JSON start
    ) {
      try {
        return JSON.parse(text);
      } catch (parseError) {
        if (contentType.includes('application/json'))
          throw new Error('Invalid JSON response');
      }
    }

    return text as T;
  } catch (error) {
    if (error instanceof Error && error.message.includes('too large'))
      throw error;
    throw new Error('Failed to read response body');
  }
};

/** Create timeout with cleanup */
const createTimeout = (ms: number) => {
  const controller = new AbortController();
  let cleaned = false;
  const id = setTimeout(() => {
    if (!cleaned) controller.abort();
  }, ms);
  return {
    controller,
    cleanup: () => {
      if (!cleaned) {
        cleaned = true;
        clearTimeout(id);
      }
    },
  };
};

/** Check if request should be retried */
const shouldRetryRequest = (
  error: ApiError,
  attempt: number,
  maxRetries: number,
  method: HttpMethod,
  customRetry?: (error: ApiError, attempt: number) => boolean,
): boolean => {
  if (customRetry) {
    try {
      return attempt < maxRetries && customRetry(error, attempt);
    } catch {
      return false;
    }
  }

  return (
    attempt < maxRetries &&
    RETRY.idempotentMethods.has(method) &&
    (error.name === 'AbortError' ||
      error.name === 'TimeoutError' ||
      RETRY.codes.has(error.status) ||
      /network|fetch|connection/i.test(error.message))
  );
};

/** Exponential backoff with jitter */
const delay = (attempt: number) => {
  const baseMs = Math.min(1000 * Math.pow(2, attempt), 10000);
  const jitter = baseMs * 0.25 * (Math.random() - 0.5);
  const finalMs = Math.max(100, Math.min(baseMs + jitter, 10000));
  return new Promise((resolve) => setTimeout(resolve, finalMs));
};

/** Log TypeScript types (dev only) */
const logTypes = (endpoint: string, data: unknown): void => {
  if (!IS_DEV) return;

  const inferType = (val: unknown, depth = 0): string => {
    if (depth > 10) return 'any /* depth exceeded */';
    if (val === null) return 'null';
    if (val === undefined) return 'undefined';

    if (Array.isArray(val)) {
      if (val.length === 0) return 'unknown[]';
      const firstType = inferType(val[0], depth + 1);
      const allSame = val.every((item) => typeof item === typeof val[0]);
      return allSame ? `${firstType}[]` : 'Array<unknown>';
    }

    if (typeof val === 'object' && val !== null) {
      const obj = val as Record<string, unknown>;
      const props = Object.entries(obj)
        .map(([k, v]) => {
          const valueType = /password|token|secret|key|auth/i.test(k)
            ? 'string /* redacted */'
            : inferType(v, depth + 1);
          return `   ${JSON.stringify(k)}: ${valueType};`;
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
      .replace(/_{2,}/g, '_')
      .replace(/^(\d)/, '_$1');

    const inferred = inferType(data);
    console.log(`🔍 Inferred Type for "${endpoint}"`);
    console.log(`type ${typeName}Type = ${inferred}`);
  } catch (err) {
    console.warn('[logTypes] Failed to infer types:', err);
  }
};

/**
 * API request function with comprehensive TypeScript support
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
 * data: { name: 'John', email: 'john@example.com' },
 * params: { userId: 123, status: 'active' }, // Added: Query parameters
 * retries: 3,
 * timeout: 5000, // Added: Request timeout
 * cache: "force-cache",
 * revalidate: 60, // Added: Next.js ISR revalidation time
 * tags:["id", "users"],
 * headers: { 'X-Custom-Header': 'foobar' }, // Added: Custom headers
 * shouldRetry: (error, attempt) => error.status === 503 && attempt < 2,
 * onError: (error, attempt) => console.warn(`Retry ${attempt}:`, error),
 * transform: (data) => ({ ...data, timestamp: Date.now() }),
 * logTypes: true,
 * allowedHosts: ['api.example.com'], // Additional hosts (merged with env)
 * maxResponseSize: 5 * 1024 * 1024 // 5MB
 * });
 *
 * // Environment configuration:
 * // ALLOWED_HOSTS=api.example.com,cdn.example.com
 * // SAFEFETCH_ALLOWED_HOSTS=secure-api.com
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
    allowedHosts,
    maxResponseSize = MAX_RESPONSE_SIZE_DEFAULT,
  } = options;

  // Input validation
  if (retries < 0 || retries > 10)
    throw new Error('Retries must be between 0 and 10');
  if (timeout < 1000 || timeout > 300000)
    throw new Error('Timeout must be between 1s and 5 minutes');
  if (maxResponseSize < 1024 || maxResponseSize > 100 * 1024 * 1024) {
    throw new Error('Max response size must be between 1KB and 100MB');
  }

  let url: string, headers: HeadersInit;
  try {
    url = buildUrl(endpoint, params, allowedHosts);
    headers = buildHeaders(data, customHeaders);
  } catch (error) {
    const apiError = createApiError(
      'ValidationError',
      error instanceof Error ? error.message : 'Request validation failed',
      400,
    );
    return { success: false, status: 400, error: apiError, data: null };
  }

  let lastError: ApiError = createApiError(
    'UnknownError',
    'Request failed',
    500,
  );

  for (let attempt = 0; attempt <= retries; attempt++) {
    const { controller, cleanup } = createTimeout(timeout);
    let currentResponseStatus = 500; // Default status for network/unknown errors

    try {
      // Prepare request body
      let body: BodyInit | undefined;
      if (data != null) {
        if (
          data instanceof FormData ||
          data instanceof Blob ||
          data instanceof ArrayBuffer
        ) {
          body = data;
        } else if (typeof data === 'string') {
          if (data.length > maxResponseSize)
            throw new Error('Request body too large');
          body = data;
        } else {
          // Assume it's Record<string, unknown>
          const jsonString = JSON.stringify(data);
          if (jsonString.length > maxResponseSize)
            throw new Error('Request body too large');
          body = jsonString;
        }
      }

      // Next.js options (inlined)
      const nextOptions =
        revalidate !== undefined || tags.length
          ? {
              next: {
                ...(revalidate !== undefined && { revalidate }),
                ...(tags.length && {
                  tags: tags.filter(
                    (tag) =>
                      typeof tag === 'string' &&
                      tag.length > 0 &&
                      tag.length <= 100 &&
                      /^[a-zA-Z0-9\-_]+$/.test(tag),
                  ),
                }),
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
      currentResponseStatus = response.status; // Update status for potential error reporting

      const responseData = await parseResponse<TResponse>(
        response,
        maxResponseSize,
      );

      if (response.ok) {
        let finalData: TResponse;
        try {
          finalData = transform ? transform(responseData) : responseData;
        } catch (transformError) {
          lastError = createApiError(
            'TransformError',
            'Response transformation failed',
            response.status,
            attempt,
          );
          onError?.(lastError, attempt);
          return {
            success: false,
            status: response.status,
            error: lastError,
            data: null,
          };
        }

        if (shouldLogTypes) logTypes(endpoint, finalData);
        return {
          success: true,
          status: response.status,
          data: finalData,
          headers: response.headers,
        };
      }

      // Handle HTTP errors (response not ok) - try to get error from body
      let errorMessage =
        response.status >= 500
          ? `Server error (${response.status})`
          : `HTTP ${response.status}: ${response.statusText}`;
      let errorName = 'HttpError';

      // Attempt to extract more detailed error from responseData if it's an object
      if (typeof responseData === 'object' && responseData !== null) {
        const dataAsRecord = responseData as Record<string, unknown>;
        if (
          typeof dataAsRecord.message === 'string' &&
          dataAsRecord.message.length > 0
        ) {
          errorMessage = dataAsRecord.message;
        } else if (
          typeof dataAsRecord.error === 'string' &&
          dataAsRecord.error.length > 0
        ) {
          errorMessage = dataAsRecord.error;
        }
        if (
          typeof dataAsRecord.code === 'string' &&
          dataAsRecord.code.length > 0
        ) {
          errorName = dataAsRecord.code;
        } else if (
          typeof dataAsRecord.name === 'string' &&
          dataAsRecord.name.length > 0
        ) {
          errorName = dataAsRecord.name;
        }
      }

      lastError = createApiError(
        errorName,
        errorMessage,
        response.status,
        attempt,
      );
    } catch (err) {
      cleanup();

      // Determine the specific error type
      if (err instanceof Error) {
        if (err.name === 'AbortError' || err.message.includes('timeout')) {
          lastError = createApiError(
            'TimeoutError',
            `Request timeout after ${timeout}ms`,
            408,
            attempt,
          );
        } else if (err.message.includes('too large')) {
          lastError = createApiError(
            'PayloadTooLargeError',
            'Response or request too large',
            413,
            attempt,
          );
        } else if (
          err.message.includes('not allowed') ||
          err.message.includes('SSRF')
        ) {
          lastError = createApiError(
            'SecurityError',
            'Request blocked for security reasons',
            403,
            attempt,
          );
        } else {
          lastError = createApiError(
            'NetworkError',
            'Network request failed',
            500,
            attempt,
          );
        }
      } else {
        lastError = createApiError(
          'UnknownError',
          'Unexpected error occurred',
          currentResponseStatus,
          attempt,
        );
      }
    }

    onError?.(lastError, attempt); // Call custom onError handler for any error

    // Decide whether to retry or break the loop
    if (
      shouldRetryRequest(lastError, attempt, retries, method, customShouldRetry)
    ) {
      await delay(attempt);
      continue; // Proceed to the next retry attempt
    } else {
      break; // Stop retrying if not allowed or retries exhausted
    }
  }

  // Return the final error response if all retries failed or no more retries allowed
  return {
    success: false,
    status: lastError.status,
    error: lastError,
    data: null,
  };
}

/**
 * Type guard for successful responses
 *
 * @example
 * const res = await apiRequest('GET', '/users');
 * if (apiRequest.isSuccess(res)) {
 * // Safe access to res.data
 * } else {
 * console.error(res.error);
 * }
 */
apiRequest.isSuccess = <T>(
  response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: true }> => response.success;

/**
 * Type guard for error responses
 *
 * @example
 * const res = await apiRequest('GET', '/users');
 * if (apiRequest.isError(res)) {
 * console.error(res.error);
 * }
 */
apiRequest.isError = <T>(
  response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: false }> => !response.success;
