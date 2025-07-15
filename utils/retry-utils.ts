import { ApiError, HttpMethod } from '../types';

const IS_DEV = process.env.NODE_ENV === 'development';
const CONFIG = {
  retry: {
    codes: new Set([408, 429, 500, 502, 503, 504]),
    idempotentMethods: new Set<HttpMethod>(['GET', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']),
  },
} as const;

export function shouldRetryRequest(
  error: ApiError,
  attempt: number,
  maxRetries: number,
  method: HttpMethod,
  customRetry?: (error: ApiError, attempt: number) => boolean,
): boolean {
  if (customRetry) {
    try {
      return attempt < maxRetries && customRetry(error, attempt);
    } catch (e) {
      if (IS_DEV) console.error('Custom shouldRetry function threw an error:', e);
      return false;
    }
  }
  return (
    attempt < maxRetries &&
    CONFIG.retry.idempotentMethods.has(method) &&
    (error.name === 'AbortError' ||
      error.name === 'TimeoutError' ||
      CONFIG.retry.codes.has(error.status) ||
      /network|fetch|connection|dns/i.test(error.message))
  );
}

export function delay(attempt: number): Promise<void> {
  const baseMs = Math.min(1000 * Math.pow(2, attempt), 10000);
  const jitter = baseMs * 0.25 * (Math.random() - 0.5);
  const finalMs = Math.max(100, Math.min(baseMs + jitter, 10000));
  return new Promise((resolve) => setTimeout(resolve, finalMs));
}
