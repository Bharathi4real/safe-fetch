import { SafeFetchPlugin, PluginContext, RequestOptions, RequestBody } from '../types';

const AUTH_HEADER = (() => {
  try {
    const { AUTH_USERNAME, AUTH_PASSWORD, AUTH_TOKEN, API_TOKEN } = process.env;
    if (AUTH_USERNAME && AUTH_PASSWORD) {
      return `Basic ${Buffer.from(`${AUTH_USERNAME}:${AUTH_PASSWORD}`, 'utf8').toString('base64')}`;
    }
    const token = AUTH_TOKEN || API_TOKEN;
    return token && /^[A-Za-z0-9\-._~+/]+=*$/.test(token) ? `Bearer ${token}` : null;
  } catch (e) {
    if (process.env.NODE_ENV === 'development') console.warn('Failed to set AUTH_HEADER:', e);
    return null;
  }
})();

const CONFIG = {
  security: {
    maxHeaderLength: 8192,
  },
} as const;

export const HeadersPlugin: SafeFetchPlugin<unknown, unknown> = {
  name: 'HeadersPlugin',
  beforeRequest: async (context: PluginContext<unknown>, options: RequestOptions<RequestBody, unknown>) => {
    const { data, headers: customHeaders } = options;
    const headers: Record<string, string> = {};
    if (customHeaders) {
      Object.entries(customHeaders).forEach(([key, value]) => {
        if (/^[!#$%&'*+\-.0-9A-Z^_`a-z|~]+$/.test(key)) {
          const sanitizedValue = value
            .replace(/[\x00-\x1f\x7f-\xff\r\n]/g, '')
            .substring(0, CONFIG.security.maxHeaderLength);
          if (sanitizedValue) headers[key] = sanitizedValue;
          else if (process.env.NODE_ENV === 'development') console.warn(`Skipping empty or invalid header value for key: ${key}`);
        } else if (process.env.NODE_ENV === 'development') {
          console.warn(`Skipping invalid header key: ${key}`);
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
    context.headers = headers;
  },
};
