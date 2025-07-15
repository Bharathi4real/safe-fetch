import { SafeFetchPlugin, PluginContext, RequestOptions, RequestBody, FetchResult } from '../types';
import { logTypes } from '../utils/type-logger';


export const TypeLoggingPlugin: SafeFetchPlugin<unknown, unknown> = {
  name: 'TypeLoggingPlugin',
  afterResponse: async (
    context: PluginContext<unknown>,
    result: FetchResult<unknown>,
    options: RequestOptions<RequestBody, unknown>,
  ): Promise<FetchResult<unknown>> => {
    if (options.logTypes && result.success) {
      logTypes(context.url, result.data);
    }
    return result;
  },
};
