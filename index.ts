/**
 * SafeFetch – Typed fetch utility with plugin-based architecture and Next.js support
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * https://github.com/Bharathi4real/safe-fetch
 */

'use server';

import  "./plugins"

import {
  ApiError,
  ApiResponse,
  FetchResult,
  HttpMethod,
  PluginContext,
  RequestBody,
  RequestOptions
} from './types';
import { createApiError } from './utils/create-api-error';
import { prepareRequestBody } from './utils/prepare-body';
import { isUrlSafe } from './utils/url-safety';

import {
  UrlValidationPlugin,
  HeadersPlugin,
  TimeoutPlugin,
  RetryPlugin,
  ResponseParserPlugin,
  TransformPlugin,
  TypeLoggingPlugin,
  NextJsPlugin,
} from './plugins';

const MAX_RESPONSE_SIZE_DEFAULT = 10 * 1024 * 1024;
const MAX_REQUEST_BODY_SIZE_DEFAULT = 10 * 1024 * 1024;

const CONFIG = {
  security: {
    maxRedirects: 5,
  },
} as const;

async function executeFetch<TResponse>(
  context: PluginContext<TResponse>,
): Promise<FetchResult<TResponse>> {
  let currentUrl = context.url;
  let response: Response | undefined;
  let responseContentType: string | null = null;
  try {
    while (true) {
      if (context.redirectCount > CONFIG.security.maxRedirects) {
        throw new Error('Too many redirects', { cause: 'TooManyRedirects' });
      }
      response = await fetch(currentUrl, {
        method: context.method,
        headers: context.headers,
        body: context.body,
        cache: context.cache,
        signal: context.signal,
        redirect: 'manual',
        ...context.nextOptions,
      });
      context.response = response;
      responseContentType = response.headers.get('content-type');
      if (response.status >= 300 && response.status < 400 && response.headers.has('Location')) {
        const redirectUrl = response.headers.get('Location')!;
        const resolvedRedirectUrl = new URL(redirectUrl, currentUrl).toString();
        if (!isUrlSafe(resolvedRedirectUrl)) {
          throw new Error('Redirect URL not allowed: potential SSRF risk', {
            cause: 'SecurityError',
          });
        }
        currentUrl = resolvedRedirectUrl;
        context.redirectCount++;
        continue;
      }
      break;
    }
    return {
      success: true,
      data: null as any, // Will be overwritten by ResponseParserPlugin
      status: response.status,
      headers: response.headers,
    };
  } catch (err) {
    context.cleanup?.();
    const originalError = err instanceof Error ? err : new Error(String(err));
    if (err instanceof Error) {
      if (err.name === 'AbortError' || err.message.includes('timeout')) {
        return {
          success: false,
          error: createApiError(
            'TimeoutError',
            `Request timeout after ${context.timeout}ms`,
            408,
            context.attempt,
            null,
            `Request to ${currentUrl} timed out after ${context.timeout}ms`,
            originalError,
            responseContentType || undefined,
          ),
        };
      }
      if (err.message.includes('too large') || err.cause === 'PayloadTooLarge') {
        return {
          success: false,
          error: createApiError(
            'PayloadTooLargeError',
            'Response or request body too large',
            413,
            context.attempt,
            null,
            `Payload too large for URL: ${currentUrl}`,
            originalError,
            responseContentType || undefined,
          ),
        };
      }
      if (
        err.message.includes('not allowed') ||
        err.message.includes('SSRF') ||
        err.cause === 'SecurityError'
      ) {
        return {
          success: false,
          error: createApiError(
            'SecurityError',
            'Request blocked for security reasons',
            403,
            context.attempt,
            null,
            `Security error for URL: ${currentUrl} - ${err.message}`,
            originalError,
            responseContentType || undefined,
          ),
        };
      }
      if (err.cause === 'TooManyRedirects') {
        return {
          success: false,
          error: createApiError(
            'TooManyRedirectsError',
            'Too many redirects',
            400,
            context.attempt,
            null,
            `Exceeded max redirects (${CONFIG.security.maxRedirects}) for URL: ${currentUrl}`,
            originalError,
            responseContentType || undefined,
          ),
        };
      }
      if (err.cause === 'InvalidJson') {
        return {
          success: false,
          error: createApiError(
            'ParseError',
            'Invalid JSON response',
            response?.status || 500,
            context.attempt,
            null,
            `Failed to parse JSON response from ${currentUrl}: ${err.message}`,
            originalError,
            responseContentType || undefined,
          ),
        };
      }
      return {
        success: false,
        error: createApiError(
          'NetworkError',
          'Network request failed',
          response?.status || 500,
          context.attempt,
          null,
          `Network error for URL: ${currentUrl} - ${err.message} (Code: ${(err as NodeJS.ErrnoException).code || 'N/A'})`,
          originalError,
          responseContentType || undefined,
        ),
      };
    }
    return {
      success: false,
      error: createApiError(
        'UnknownError',
        'An unexpected error occurred',
        response?.status || 500,
        context.attempt,
        null,
        `An unknown non-Error type was thrown for URL: ${currentUrl}`,
        originalError,
        responseContentType || undefined,
      ),
    };
  } finally {
    context.cleanup?.();
  }
}

export async function apiRequest<
  TResponse = unknown,
  TBody extends RequestBody = RequestBody,
  TTransformedResponse extends TResponse = TResponse,
>(
  method: HttpMethod,
  endpoint: string,
  options: RequestOptions<TBody, TTransformedResponse> = {},
): Promise<ApiResponse<TTransformedResponse>> {
  const {
    data,
    cache = 'default',
    maxResponseSize = MAX_RESPONSE_SIZE_DEFAULT,
    maxRequestBodySize = MAX_REQUEST_BODY_SIZE_DEFAULT,
    onError,
    plugins = [
      UrlValidationPlugin,
      HeadersPlugin,
      TimeoutPlugin,
      RetryPlugin,
      ResponseParserPlugin,
      TransformPlugin,
      TypeLoggingPlugin,
      NextJsPlugin,
    ],
  } = options;

  let context: PluginContext<TResponse> = {
    url: endpoint,
    method,
    headers: {},
    body: prepareRequestBody(data, maxRequestBodySize),
    cache,
    nextOptions: {},
    attempt: 0,
    maxResponseSize,
    maxRequestBodySize,
    redirectCount: 0,
    timeout: options.timeout || 30000,
  };

  let lastError: ApiError = createApiError(
    'UnknownError',
    'Request failed',
    500,
    undefined,
    null,
    'Initial unknown error before fetch attempt',
  );

  while (context.attempt <= (options.retries || 1)) {
    for (const plugin of plugins) {
      if (plugin.beforeRequest) {
        try {
          const result = await plugin.beforeRequest(context, options);
          if (result) context = result as PluginContext<TResponse>;
        } catch (error) {
          lastError = createApiError(
            'PluginError',
            `Plugin ${plugin.name} failed in beforeRequest`,
            500,
            context.attempt,
            null,
            error instanceof Error ? error.message : String(error),
          );
          onError?.(lastError, context.attempt);
          return { success: false, status: lastError.status, error: lastError, data: null };
        }
      }
    }

    let result = await executeFetch<TResponse>(context);

    for (const plugin of plugins) {
      if (plugin.afterResponse) {
        try {
          const pluginResult = await plugin.afterResponse(context, result, options);
          if (pluginResult) result = pluginResult as FetchResult<TTransformedResponse>;
        } catch (error) {
          lastError = createApiError(
            'PluginError',
            `Plugin ${plugin.name} failed in afterResponse`,
            result.success ? result.status : lastError.status,
            context.attempt,
            null,
            error instanceof Error ? error.message : String(error),
          );
          onError?.(lastError, context.attempt);
          return { success: false, status: lastError.status, error: lastError, data: null };
        }
      }
    }

    if (result.success) {
      return {
        success: true,
        status: result.status,
        data: result.data as TTransformedResponse,
        headers: result.headers,
      };
    }

    lastError = result.error;
    onError?.(lastError, context.attempt);

    let shouldRetry = false;
    for (const plugin of plugins) {
      if (plugin.onError) {
        const retryResult = await plugin.onError(context, lastError, options);
        if (retryResult) {
          return {
            success: false,
            status: 'error' in retryResult ? retryResult.error.status : 500,
            error: 'error' in retryResult ? retryResult.error : lastError,
            data: null,
          };
        }
        shouldRetry = true;
      }
    }

    if (!shouldRetry) break;
    context.attempt++;
  }

  return {
    success: false,
    status: lastError.status,
    error: lastError,
    data: null,
  };
}

apiRequest.isSuccess = <T>(
  response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: true }> => response.success;

apiRequest.isError = <T>(
  response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: false }> => !response.success;

export default apiRequest;
