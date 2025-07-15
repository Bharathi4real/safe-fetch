import { ApiError, ErrorData } from '../types';

const IS_DEV = process.env.NODE_ENV === 'development';

export function createApiError(
  name: string,
  message: string,
  status: number,
  attempt?: number,
  data?: unknown,
  devMessage?: string,
  originalError?: Error,
  contentType?: string,
): ApiError {
  const getDataInfo = (data: unknown): { dataType: string; dataSizeBytes?: number } => {
    if (data === null) return { dataType: 'null' };
    if (data === undefined) return { dataType: 'undefined' };
    if (typeof data === 'string') return { dataType: 'string', dataSizeBytes: new TextEncoder().encode(data).length };
    if (typeof data === 'number') return { dataType: 'number' };
    if (typeof data === 'boolean') return { dataType: 'boolean' };
    if (typeof data === 'bigint') return { dataType: 'bigint' };
    if (typeof data === 'symbol') return { dataType: 'symbol' };
    if (data instanceof Blob) return { dataType: 'Blob', dataSizeBytes: data.size };
    if (data instanceof ArrayBuffer) return { dataType: 'ArrayBuffer', dataSizeBytes: data.byteLength };
    if (data instanceof FormData) return { dataType: 'FormData' };
    if (data instanceof ReadableStream) return { dataType: 'ReadableStream' };
    if (Array.isArray(data)) return { dataType: 'Array', dataSizeBytes: JSON.stringify(data).length };
    if (typeof data === 'object') return { dataType: 'Object', dataSizeBytes: JSON.stringify(data).length };
    return { dataType: 'unknown' };
  };

  const { dataType, dataSizeBytes } = getDataInfo(data);
  return {
    name,
    message: IS_DEV && devMessage ? devMessage : message,
    status,
    attempt,
    data: data as ErrorData,
    ...(IS_DEV && devMessage && { devMessage }),
    ...(originalError && { originalError }),
    ...(contentType && { contentType }),
    dataType,
    ...(dataSizeBytes && { dataSizeBytes }),
  };
}
