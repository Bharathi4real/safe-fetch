import { RequestOptions } from "../safe-fetch";
import { FetchResult, PluginContext, RequestBody, SafeFetchPlugin } from "../types";
import { createApiError } from "../utils/create-api-error";
import { parseResponse } from "../utils/parse-response";
import { logTypes } from "../utils/type-logger";

export const ResponseParserPlugin: SafeFetchPlugin<unknown, unknown> = {
  name: 'ResponseParserPlugin',
  afterResponse: async (
    context: PluginContext<unknown>,
    result: FetchResult<unknown>,
    options: RequestOptions<RequestBody, unknown>,
  ): Promise<FetchResult<unknown>> => {
    if (!result.success && result.error) return result;
    const { maxResponseSize = 10 * 1024 * 1024 } = options;
    if (!context.response) throw new Error('Response missing in context');
    const responseData = await parseResponse<unknown>(context.response, maxResponseSize);
    if (context.response.ok) {
      return {
        success: true,
        data: responseData,
        status: context.response.status,
        headers: context.response.headers,
      };
    }
    if (process.env.NODE_ENV === 'development') logTypes(context.url, responseData, 'Error_');
    return {
      success: false,
      error: createApiError(
        'HttpError',
        `HTTP ${context.response.status} Error`,
        context.response.status,
        context.attempt,
        responseData,
        `HTTP ${context.response.status} error for URL: ${context.url}`,
        undefined,
        context.response.headers.get('content-type') || undefined,
      ),
    };
  },
};
