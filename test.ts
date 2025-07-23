import { revalidatePath, revalidateTag } from 'next/cache';

const env = {
  AUTH_USERNAME: process.env.AUTH_USERNAME?.trim(),
  AUTH_PASSWORD: process.env.AUTH_PASSWORD?.trim(),
  AUTH_TOKEN: process.env.AUTH_TOKEN?.trim(),
  BASE_URL: process.env.BASE_URL?.trim(),
  ALLOW_BASIC_AUTH_IN_PROD: process.env.ALLOW_BASIC_AUTH_IN_PROD === 'true',
};

if (!env.BASE_URL?.startsWith('https://')) {
  throw new Error('BASE_URL must start with https://');
}

const PROD_ALLOWED_DOMAINS = ['api.example.com', 'another.example.com'];

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
};

const ALLOWED_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as const;
type HttpMethod = (typeof ALLOWED_METHODS)[number];

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
      throw new Error('Invalid AUTH_TOKEN');
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

export interface ApiRequestOptions {
  data?: unknown;
  query?: Record<string, string | number | boolean | null | undefined>;
  cache?: RequestCache;
  revalidate?: number | false;
  revalidateTags?: string[];
  revalidatePaths?: string[];
  revalidateType?: 'page' | 'layout';
  timeout?: number;
  retryAttempts?: number;
  retryDelay?: number;
  csrfToken?: string;
  logTypes?: boolean;
}

export type ApiResponse<T> =
  | { success: true; data: T }
  | { success: false; status: number; error: string; data: null };

function inferType(val: unknown, depth = 0): string {
  const pad = (level: number): string => '  '.repeat(level);
  if (val === null) return 'null';
  if (Array.isArray(val)) return `Array<${inferType(val[0], depth) || 'unknown'}>`;
  if (typeof val === 'object') {
    const entries = Object.entries(val as Record<string, unknown>)
      .slice(0, 10)
      .map(([k, v]) => `${pad(depth + 1)}${k}: ${inferType(v, depth + 1)};`)
      .join('\n');
    return `{\n${entries}\n${pad(depth)}}`;
  }
  return typeof val;
}

export async function apiRequest<T>(
  method: HttpMethod,
  url: string,
  options: ApiRequestOptions = {},
): Promise<ApiResponse<T>> {
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
    logTypes,
  } = options;

  const upperMethod = method.toUpperCase() as HttpMethod;
  if (!ALLOWED_METHODS.includes(upperMethod)) {
    return { success: false, status: 405, error: 'Invalid HTTP method', data: null };
  }

  const fullUrl = new URL(url, env.BASE_URL);
  if (fullUrl.protocol !== 'https:') {
    return { success: false, status: 400, error: 'Only HTTPS requests are allowed', data: null };
  }

  if (isRateLimited()) {
    return { success: false, status: 429, error: 'Rate limit exceeded', data: null };
  }

  const circuitKey = fullUrl.origin + fullUrl.pathname;
  const now = Date.now();
  if ((circuitMap.get(circuitKey) ?? 0) > now) {
    return { success: false, status: 503, error: 'Circuit breaker active', data: null };
  }

  Object.entries(query || {}).forEach(([key, val]) => {
    if (val != null) fullUrl.searchParams.append(key, encodeURIComponent(String(val)));
  });

  const isForm = typeof FormData !== 'undefined' && data instanceof FormData;

  if (['GET', 'HEAD'].includes(upperMethod) && data) {
    return {
      success: false,
      status: 400,
      error: 'GET/HEAD requests cannot have a body',
      data: null,
    };
  }

  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(upperMethod) && !csrfToken) {
    return { success: false, status: 403, error: 'CSRF token is required', data: null };
  }

  const csrfValid = !csrfToken || /^[a-zA-Z0-9-_]{32,}$/.test(csrfToken);
  if (csrfToken && !csrfValid) {
    return { success: false, status: 400, error: 'Malformed CSRF token', data: null };
  }

  const authHeader = getAuthHeader();

  const headers: Record<string, string> = {
    Accept: 'application/json',
    'X-Requested-With': 'XMLHttpRequest',
    'X-Request-ID': `req_${crypto.randomUUID()}`,
    ...(authHeader && { Authorization: authHeader }),
    ...(!isForm && { 'Content-Type': 'application/json' }),
    ...(csrfToken && { 'X-CSRF-Token': csrfToken }),
  };

  const makeRequest = async (attempt = 1): Promise<ApiResponse<T>> => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const body =
        isForm || ['GET', 'HEAD'].includes(upperMethod) ? undefined : JSON.stringify(data ?? {});
      if (body && body.length > MAX.PAYLOAD) {
        return { success: false, status: 413, error: 'Payload too large', data: null };
      }

      const res = await fetch(fullUrl.toString(), {
        method: upperMethod,
        headers,
        cache,
        signal: controller.signal,
        body,
        ...(revalidate !== undefined || revalidateTags.length
          ? { next: { revalidate, tags: sanitizeTags(revalidateTags) } }
          : {}),
      });

      const retryAfter = res.headers.get('Retry-After');
      const contentLength = Number(res.headers.get('Content-Length') || '0');
      const contentType = res.headers.get('Content-Type') || '';

      if (contentLength > MAX.RES_SIZE) {
        return { success: false, status: 413, error: 'Response too large', data: null };
      }

      let parsed: T;
      try {
        parsed = contentType.includes('application/json')
          ? await res.json()
          : contentType.includes('text/plain')
            ? ((await res.text()) as unknown as T)
            : (() => {
                throw new Error('Unsupported content type');
              })();
      } catch {
        return { success: false, status: res.status, error: 'Failed to parse response', data: null };
      }

      if (!res.ok) {
        if (res.status >= 500 && attempt < retryAttempts) {
          const delay = retryAfter
            ? Number(retryAfter) * 1000
            : retryDelay * 2 ** (attempt - 1) * (0.5 + Math.random());
          await new Promise((r) => setTimeout(r, delay));
          return makeRequest(attempt + 1);
        }

        if (circuitMap.size >= MAX.CIRCUIT_MAX) {
          const oldest = circuitMap.keys().next().value;
          if (oldest) circuitMap.delete(oldest);
        }

        circuitMap.set(circuitKey, now + MAX.CIRCUIT_TTL);
        return { success: false, status: res.status, error: res.statusText, data: null };
      }

      await invalidateCache(revalidatePaths, revalidateTags, revalidateType);

      if (process.env.NODE_ENV === 'development' && logTypes) {
        const typeDef = inferType(parsed);
        console.log(`[DEBUG] Inferred Type for ${method} ${url}:\n`);
        console.log(`type ApiResponse = ${typeDef};`);
      }

      return { success: true, data: parsed };
    } catch (err) {
      const isAbort =
        typeof err === 'object' && err !== null && 'name' in err && (err as { name: string }).name === 'AbortError';

      if (!['GET', 'HEAD'].includes(upperMethod) || attempt >= retryAttempts) {
        circuitMap.set(circuitKey, now + MAX.CIRCUIT_TTL);
        return {
          success: false,
          status: isAbort ? 408 : 500,
          error: 'Request failed',
          data: null,
        };
      }

      await new Promise((r) =>
        setTimeout(r, retryDelay * 2 ** (attempt - 1) * (0.5 + Math.random())),
      );
      return makeRequest(attempt + 1);
    } finally {
      clearTimeout(timeoutId);
    }
  };

  return makeRequest();
}

export default apiRequest;
