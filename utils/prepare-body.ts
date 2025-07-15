import { RequestBody } from '../types';

export function prepareRequestBody(
  data: RequestBody | undefined,
  maxSize: number,
): BodyInit | undefined {
  if (data == null) return undefined;
  if (data instanceof FormData || data instanceof Blob || data instanceof ArrayBuffer) {
    return data;
  }
  if (typeof data === 'string') {
    if (new TextEncoder().encode(data).length > maxSize) {
      throw new Error('Request body too large (string)', { cause: 'PayloadTooLarge' });
    }
    return data;
  }
  const jsonString = JSON.stringify(data);
  if (new TextEncoder().encode(jsonString).length > maxSize) {
    throw new Error('Request body too large (JSON)', { cause: 'PayloadTooLarge' });
  }
  return jsonString;
}
