import { SafeFetchPlugin, PluginContext, RequestOptions, RequestBody, FetchResult, ApiError } from '../types';
import { createApiError } from '../utils/create-api-error';
import { shouldRetryRequest, delay } from '../utils/retry-utils';

export const RetryPlugin: SafeFetchPlugin<unknown, unknown> = {
  name: 'RetryPlugin',
  onError: async (
    context: PluginContext<unknown>,
    error: ApiError,
    options: RequestOptions<RequestBody, unknown>,
  ): Promise<FetchResult<unknown> | void> => {
    const { retries = 1, shouldRetry: customShouldRetry } = options;
    if (retries < 0 || retries > 10) {
      return {
        success: false,
        error: createApiError(
          'ValidationError',
          'Retries must be between 0 and 10',
          400,
          undefined,
          null,
          'Invalid retries option',
        ),
      };
    }
    if (shouldRetryRequest(error, context.attempt, retries, context.method, customShouldRetry)) {
      await delay(context.attempt);
      return undefined; // Continue to retry
    }
    return { success: false, error };
  },
};
