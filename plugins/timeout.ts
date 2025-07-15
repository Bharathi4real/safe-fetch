import { SafeFetchPlugin, PluginContext, RequestOptions, RequestBody } from '../types';
import { createApiError } from '../utils/create-api-error';

export const TimeoutPlugin: SafeFetchPlugin<unknown, unknown> = {
  name: 'TimeoutPlugin',
  beforeRequest: async (context: PluginContext<unknown>, options: RequestOptions<RequestBody, unknown>) => {
    const timeout = options.timeout || 30000;
    if (timeout < 1000 || timeout > 300000) {
      throw createApiError(
        'ValidationError',
        'Timeout must be between 1s and 5 minutes',
        400,
        undefined,
        null,
        'Invalid timeout option',
      );
    }
    const controller = new AbortController();
    let cleaned = false;
    const id = setTimeout(() => {
      if (!cleaned) controller.abort();
    }, timeout);
    context.signal = controller.signal;
    context.cleanup = () => {
      if (!cleaned) {
        cleaned = true;
        clearTimeout(id);
      }
    };
  },
};
