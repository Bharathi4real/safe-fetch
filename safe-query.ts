/**
 * SafeFetch + TanStack Query Integration (Server Action Compatible)
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * Handles serialization boundaries for 'use server' SafeFetch
 */

'use client';

import {
  useQuery,
  useMutation,
  useQueryClient,
  type UseQueryOptions,
  type UseMutationOptions,
  type QueryKey,
} from '@tanstack/react-query';
import apiRequest, {
  type HttpMethod,
  type RequestOptions,
  type ApiResponse,
  type RequestBody,
  type ApiError,
} from './safefetch';

// -------------------- Custom Error Wrapper --------------------

export class SafeFetchError extends Error {
  readonly name: string;
  readonly status: number;
  readonly retryable: boolean;
  readonly originalError: ApiError;

  constructor(error: ApiError) {
    super(error.message);
    this.name = error.name;
    this.status = error.status;
    this.retryable = !!error.retryable;
    this.originalError = error;
    Object.setPrototypeOf(this, SafeFetchError.prototype);
  }
}

// -------------------- Serialization Utility --------------------

/**
 * Strips non-serializable properties (functions, signals) before sending to Server Action.
 * Server Actions cannot accept functions or complex objects like AbortSignal.
 */
function prepareServerOptions<TBody extends RequestBody>(
  options: RequestOptions<TBody>
): RequestOptions<TBody> {
  const {
    // Non-serializable properties to STRIP
    signal, 
    transform, 
    timeout, 
    // Serializable properties to KEEP
    ...serializableOptions 
  } = options;

  // We can pass numeric timeouts, but not functions
  if (typeof timeout === 'number') {
    return { ...serializableOptions, timeout };
  }

  return serializableOptions;
}

// -------------------- Core Query Function --------------------

interface QueryOptions<TResponse = unknown>
  extends Omit<RequestOptions, 'data'>,
    Omit<
      UseQueryOptions<TResponse, SafeFetchError, TResponse, QueryKey>,
      'queryKey' | 'queryFn'
    > {
  queryKey: QueryKey;
}

export function query<TResponse = unknown>(
  queryKey: QueryKey,
  method: 'GET',
  endpoint: string,
  options?: Omit<QueryOptions<TResponse>, 'queryKey'>
) {
  const {
    enabled,
    staleTime,
    gcTime,
    refetchOnWindowFocus,
    refetchOnMount,
    refetchInterval,
    retry,
    retryDelay,
    placeholderData,
    transform, // Extract transform to run on CLIENT
    ...requestOpts
  } = options ?? {};

  return useQuery<TResponse, SafeFetchError, TResponse, QueryKey>({
    queryKey,
    queryFn: async () => {
      // 1. Prepare options (strip functions/signals)
      const serverOpts = prepareServerOptions(requestOpts);

      // 2. Call Server Action
      // Note: We cannot pass the Client's 'signal' to the Server Action easily
      const response = await apiRequest<TResponse>(method, endpoint, serverOpts);

      // 3. Handle Errors
      if (!response.success) {
        throw new SafeFetchError(response.error);
      }

      // 4. Run Transform on Client (since we couldn't pass it to server)
      if (transform) {
        return transform(response.data) as TResponse;
      }

      return response.data;
    },
    enabled,
    staleTime,
    gcTime,
    refetchOnWindowFocus,
    refetchOnMount,
    refetchInterval,
    retry,
    retryDelay,
    placeholderData,
  });
}

// -------------------- Mutation Function --------------------

interface MutationOptions<TResponse = unknown, TBody extends RequestBody | void = RequestBody>
  extends Omit<RequestOptions<TBody extends RequestBody ? TBody : RequestBody, TResponse>, 'data'>,
    Omit<
      UseMutationOptions<TResponse, SafeFetchError, TBody, unknown>,
      'mutationFn'
    > {
  invalidate?: QueryKey[];
}

export function mutate<TResponse = unknown, TBody extends RequestBody | void = RequestBody>(
  method: Exclude<HttpMethod, 'GET'>,
  endpoint: string,
  options?: MutationOptions<TResponse, TBody>
) {
  const queryClient = useQueryClient();
  const { 
    invalidate, 
    onSuccess, 
    onError, 
    onSettled, 
    transform, // Extract transform
    ...requestOpts 
  } = options ?? {};

  return useMutation<TResponse, SafeFetchError, TBody, unknown>({
    mutationFn: async (variables) => {
      const dataPayload = (variables ?? null) as RequestBody;
      
      // 1. Prepare options
      const serverOpts = prepareServerOptions({
        ...requestOpts,
        data: dataPayload,
      });

      // 2. Call Server Action
      const response = await apiRequest<TResponse>(method, endpoint, serverOpts);

      // 3. Handle Errors
      if (!response.success) {
        throw new SafeFetchError(response.error);
      }

      // 4. Client-side Transform
      if (transform) {
        return transform(response.data) as TResponse;
      }

      return response.data;
    },
    onSuccess: async (data, variables, context) => {
      if (invalidate && invalidate.length > 0) {
        await Promise.all(
          invalidate.map((key) =>
            queryClient.invalidateQueries({ queryKey: key })
          )
        );
      }
      if (onSuccess) await onSuccess(data, variables, context);
    },
    onError,
    onSettled,
  });
}

// -------------------- Direct Method Exports --------------------

export const GET = query;

export function POST<TResponse = unknown, TBody extends RequestBody = RequestBody>(
  endpoint: string,
  options?: MutationOptions<TResponse, TBody>
) {
  return mutate<TResponse, TBody>('POST', endpoint, options);
}

export function PUT<TResponse = unknown, TBody extends RequestBody = RequestBody>(
  endpoint: string,
  options?: MutationOptions<TResponse, TBody>
) {
  return mutate<TResponse, TBody>('PUT', endpoint, options);
}

export function PATCH<TResponse = unknown, TBody extends RequestBody = RequestBody>(
  endpoint: string,
  options?: MutationOptions<TResponse, TBody>
) {
  return mutate<TResponse, TBody>('PATCH', endpoint, options);
}

export function DELETE<TResponse = unknown>(
  endpoint: string,
  options?: MutationOptions<TResponse, void>
) {
  return mutate<TResponse, void>('DELETE', endpoint, options);
}

// -------------------- Utilities --------------------

// Note: prefetch runs on the server (usually), so direct calls are fine, 
// but we keep the wrapper consistent.
export async function prefetch<TResponse = unknown>(
  queryClient: ReturnType<typeof useQueryClient>,
  queryKey: QueryKey,
  endpoint: string,
  options?: RequestOptions
) {
  await queryClient.prefetchQuery({
    queryKey,
    queryFn: async () => {
      // Direct call is safe here if prefetch is running on server component, 
      // but if running on client, we must sanitize.
      const serverOpts = prepareServerOptions(options || {});
      const response = await apiRequest<TResponse>('GET', endpoint, serverOpts);
      
      if (!response.success) {
        throw new SafeFetchError(response.error);
      }
      
      // We don't transform prefetch data usually, but if needed, 
      // logic would go here.
      return response.data;
    },
  });
}

export function keys<T extends string>(prefix: T) {
  return {
    all: [prefix] as const,
    lists: () => [prefix, 'list'] as const,
    list: (filters?: Record<string, unknown>) =>
      filters ? ([prefix, 'list', filters] as const) : ([prefix, 'list'] as const),
    details: () => [prefix, 'detail'] as const,
    detail: (id: string | number) => [prefix, 'detail', id] as const,
  };
}
