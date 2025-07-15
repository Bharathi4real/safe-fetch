import { SafeFetchPlugin, PluginContext, RequestOptions, RequestBody } from '../types';
import { isUrlSafe } from '../utils/url-safety';
import { createApiError } from '../utils/create-api-error';

const BASE_URL = process.env.BASE_URL || process.env.NEXT_PUBLIC_API_URL || '';

export const UrlValidationPlugin: SafeFetchPlugin<unknown, unknown> = {
  name: 'UrlValidationPlugin',
  beforeRequest: async (context: PluginContext<unknown>, options: RequestOptions<RequestBody, unknown>) => {
    const { params, allowedHosts } = options;
    try {
      let finalUrl: URL;
      if (context.url.startsWith('http://') || context.url.startsWith('https://')) {
        if (!isUrlSafe(context.url, allowedHosts)) throw new Error('URL not allowed: potential SSRF risk');
        finalUrl = new URL(context.url);
      } else {
        if (!BASE_URL) throw new Error('BASE_URL required for relative paths');
        const basePath = BASE_URL.endsWith('/') ? BASE_URL : `${BASE_URL}/`;
        const fullUrl = context.url.startsWith('/')
          ? new URL(context.url, BASE_URL).toString()
          : new URL(context.url, basePath).toString();
        if (!isUrlSafe(fullUrl, allowedHosts)) throw new Error('URL not allowed: potential SSRF risk');
        finalUrl = context.url.startsWith('/') ? new URL(context.url, BASE_URL) : new URL(context.url, basePath);
      }
      if (params) {
        Object.entries(params).forEach(([key, value]) => {
          if (value != null) {
            const sanitizedKey = key.replace(/[^\w\-_.]/g, '').substring(0, 100);
            const sanitizedValue = String(value)
              .substring(0, 1000)
              .replace(/[\x00-\x1f\x7f-\x9f]/g, '');
            if (sanitizedKey && sanitizedValue) {
              finalUrl.searchParams.append(sanitizedKey, sanitizedValue);
            } else if (process.env.NODE_ENV === 'development') {
              console.warn(`Skipping malformed query parameter: ${key}=${value}`);
            }
          }
        });
      }
      context.url = finalUrl.toString();
    } catch (error) {
      throw createApiError(
        'ValidationError',
        'Request validation failed',
        400,
        undefined,
        null,
        error instanceof Error ? `URL validation failed: ${error.message}` : 'URL validation failed',
      );
    }
  },
};
