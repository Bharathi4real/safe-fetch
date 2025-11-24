/**
 * SafeFetch + TanStack Query Integration
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * Drop-in query/mutation wrappers with SafeFetch DX
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
} from './safefetch';

// -------------------- Core Query Function --------------------

interface QueryOptions<TResponse = unknown> extends RequestOptions {
  queryKey: QueryKey;
  enabled?: boolean;
  staleTime?: number;
  gcTime?: number;
  refetchOnWindowFocus?: boolean;
  refetchOnMount?: boolean;
  refetchInterval?: number | false;
  retry?: number | boolean;
  retryDelay?: number | ((attempt: number) => number);
  placeholderData?: TResponse;
}

/**
 * Main query function - similar DX to apiRequest
 * @example
 * const result = query(['users', id], 'GET', `/users/${id}`, {
 *   staleTime: 5 * 60 * 1000
 * });
 */
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
    ...requestOpts
  } = options ?? {};

  return useQuery({
    queryKey,
    queryFn: async ({ signal }) => {
      const response = await apiRequest<TResponse>(method, endpoint, {
        ...requestOpts,
        signal,
      });

      if (!response.success) {
        throw new Error(response.error.message, { cause: response.error });
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

interface MutationOptions<TResponse = unknown, TBody extends RequestBody = RequestBody>
  extends Omit<RequestOptions<TBody, TResponse>, 'data'> {
  invalidate?: QueryKey[];
  onSuccess?: (data: TResponse, variables: TBody | void) => void | Promise<void>;
  onError?: (error: Error, variables: TBody | void) => void | Promise<void>;
  onSettled?: (
    data: TResponse | undefined,
    error: Error | null,
    variables: TBody | void
  ) => void | Promise<void>;
}

/**
 * Main mutation function - similar DX to apiRequest
 * @example
 * const createUser = mutate('POST', '/users', {
 *   invalidate: [['users']],
 *   onSuccess: (data) => console.log('Created:', data)
 * });
 * createUser.mutate({ name: 'John' });
 */
export function mutate<TResponse = unknown, TBody extends RequestBody = RequestBody>(
  method: Exclude<HttpMethod, 'GET'>,
  endpoint: string,
  options?: MutationOptions<TResponse, TBody>
) {
  const queryClient = useQueryClient();
  const { invalidate, onSuccess, onError, onSettled, ...requestOpts } = options ?? {};

  return useMutation({
    mutationFn: async (data?: TBody) => {
      const response = await apiRequest<TResponse, TBody>(method, endpoint, {
        ...requestOpts,
        data: data ?? null,
      });

      if (!response.success) {
        throw new Error(response.error.message, { cause: response.error });
      }

      return response.data;
    },
    onSuccess: async (data, variables) => {
      if (invalidate && invalidate.length > 0) {
        await Promise.all(
          invalidate.map((key) => queryClient.invalidateQueries({ queryKey: key }))
        );
      }
      await onSuccess?.(data, variables);
    },
    onError,
    onSettled,
  });
}

// -------------------- Convenience Exports --------------------

/**
 * Simpler query hook when you don't need all options
 * @example
 * const { data, isLoading } = useQuery(['users'], '/users');
 */
export function useQuery_<TResponse = unknown>(
  queryKey: QueryKey,
  endpoint: string,
  options?: Omit<QueryOptions<TResponse>, 'queryKey'>
) {
  return query<TResponse>(queryKey, 'GET', endpoint, options);
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
  options?: MutationOptions<TResponse, never>
) {
  return mutate<TResponse, never>('DELETE', endpoint, options);
}

// -------------------- Utilities --------------------

/**
 * Prefetch data before navigation
 */
export async function prefetch<TResponse = unknown>(
  queryClient: ReturnType<typeof useQueryClient>,
  queryKey: QueryKey,
  endpoint: string,
  options?: RequestOptions
) {
  await queryClient.prefetchQuery({
    queryKey,
    queryFn: async () => {
      const response = await apiRequest<TResponse>('GET', endpoint, options);
      if (!response.success) {
        throw new Error(response.error.message, { cause: response.error });
      }
      return response.data;
    },
  });
}

/**
 * Query key factory
 */
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

/**
 * Optimistic update helper
 */
export async function optimistic<TData>(
  queryClient: ReturnType<typeof useQueryClient>,
  queryKey: QueryKey,
  updater: (old: TData) => TData
) {
  await queryClient.cancelQueries({ queryKey });
  const previousData = queryClient.getQueryData<TData>(queryKey);
  if (previousData) {
    queryClient.setQueryData<TData>(queryKey, updater(previousData));
  }
  return { previousData };
}
