import { SafeFetchPlugin, PluginContext, RequestOptions, RequestBody } from '../types';

export const NextJsPlugin: SafeFetchPlugin<unknown, unknown> = {
  name: 'NextJsPlugin',
  beforeRequest: async (context: PluginContext<unknown>, options: RequestOptions<RequestBody, unknown>) => {
    const { revalidate, tags = [] } = options;
    if (revalidate !== undefined || tags.length > 0) {
      const nextOptions: { revalidate?: number | false; tags?: string[] } = {};
      if (revalidate !== undefined) {
        nextOptions.revalidate = revalidate;
      }
      if (tags.length > 0) {
        nextOptions.tags = tags.filter(
          (tag) =>
            typeof tag === 'string' &&
            tag.length > 0 &&
            tag.length <= 100 &&
            /^[a-zA-Z0-9\-_]+$/.test(tag),
        );
      }
      context.nextOptions = { next: nextOptions };
    }
  },
};
