import { SafeFetchPlugin, PluginContext, RequestOptions, RequestBody, FetchResult } from '../types';
import { createApiError } from '../utils/create-api-error';

export const TransformPlugin: SafeFetchPlugin<unknown, unknown> = {
  name: 'TransformPlugin',
  afterResponse: async (
    context: PluginContext<unknown>,
    result: FetchResult<unknown>,
    options: RequestOptions<RequestBody, unknown>,
  ): Promise<FetchResult<unknown>> => {
    if (!result.success) return result;
    const { transform } = options;
    if (transform) {
      try {
        const transformedData = transform(result.data);
        return {
          success: true,
          data: transformedData,
          status: result.status,
          headers: result.headers,
        };
      } catch (error) {
        return {
          success: false,
          error: createApiError(
            'TransformError',
            'Response transformation failed',
            result.status,
            context.attempt,
            null,
            `Response transformation failed for URL: ${context.url}. Error: ${error instanceof Error ? error.message : String(error)}`,
          ),
        };
      }
    }
    return result;
  },
};
