/**
 * SafeFetch Types
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * https://github.com/Bharathi4real/safe-fetch
 */

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS';
export type RequestBody = Record<string, unknown> | FormData | string | ArrayBuffer | Blob | null;
export type QueryParams = Record<string, string | number | boolean | null | undefined>;
export type ErrorData =
  | string
  | number
  | boolean
  | null
  | undefined
  | Record<string, unknown>
  | Array<unknown>
  | Blob
  | ArrayBuffer
  | FormData
  | ReadableStream
  | BigInt
  | symbol;

export interface NextOptions {
  revalidate?: number | false;
  tags?: string[];
}

export interface RequestOptions<
  TBody extends RequestBody = RequestBody,
  TTransformedResponse = unknown,
> {
  data?: TBody;
  params?: QueryParams;
  retries?: number;
  timeout?: number;
  cache?: RequestCache;
  revalidate?: number | false;
  tags?: string[];
  headers?: Record<string, string>;
  logTypes?: boolean;
  transform?<T>(data: T): TTransformedResponse;
  onError?: (error: ApiError, attempt: number) => void;
  shouldRetry?: (error: ApiError, attempt: number) => boolean;
  allowedHosts?: string[];
  maxResponseSize?: number;
  maxRequestBodySize?: number;
  plugins?: SafeFetchPlugin<unknown, TTransformedResponse>[];
}

export interface ApiError {
  readonly name: string;
  readonly message: string;
  readonly status: number;
  readonly attempt?: number;
  readonly data?: ErrorData;
  readonly devMessage?: string;
  readonly originalError?: Error;
  readonly contentType?: string;
  readonly dataType?: string;
  readonly dataSizeBytes?: number;
}

export type ApiResponse<T = unknown> =
  | { success: true; status: number; data: T; headers: Headers }
  | { success: false; status: number; error: ApiError; data: null };

export interface SafeFetchPlugin<TResponse, TTransformedResponse> {
  name: string;
  beforeRequest?: (
    context: PluginContext<TResponse>,
    options: RequestOptions<RequestBody, TTransformedResponse>,
  ) => Promise<PluginContext<TResponse> | void>;
  afterResponse?: (
    context: PluginContext<TResponse>,
    response: FetchResult<TResponse>,
    options: RequestOptions<RequestBody, TTransformedResponse>,
  ) => Promise<FetchResult<TTransformedResponse> | void>;
  onError?: (
    context: PluginContext<TResponse>,
    error: ApiError,
    options: RequestOptions<RequestBody, TTransformedResponse>,
  ) => Promise<FetchResult<TTransformedResponse> | void>;
}

export interface PluginContext<TResponse> {
  url: string;
  method: HttpMethod;
  headers: HeadersInit;
  body?: BodyInit;
  cache: RequestCache;
  nextOptions: { next?: NextOptions };
  attempt: number;
  response?: Response;
  maxResponseSize: number;
  maxRequestBodySize: number;
  redirectCount: number;
  timeout: number;
  signal?: AbortSignal;
  cleanup?: () => void;
}

export type FetchResult<T> =
  | { success: true; data: T; status: number; headers: Headers }
  | { success: false; error: ApiError };
