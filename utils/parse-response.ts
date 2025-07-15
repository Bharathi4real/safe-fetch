export async function parseResponse<T>(response: Response, maxSize: number): Promise<T> {
  const contentType = response.headers.get('content-type') || '';
  const contentLength = response.headers.get('content-length');
  if (contentLength && parseInt(contentLength, 10) > maxSize) {
    throw new Error(`Response too large: ${contentLength} bytes (max: ${maxSize})`, {
      cause: 'PayloadTooLarge',
    });
  }
  if (contentType.includes('application/json')) {
    const text = await response.text();
    if (text.length > maxSize) {
      throw new Error(`Response too large: ${text.length} bytes (max: ${maxSize})`, {
        cause: 'PayloadTooLarge',
      });
    }
    try {
      return JSON.parse(text) as T;
    } catch (error) {
      throw new Error(
        `Invalid JSON response: ${error instanceof Error ? error.message : String(error)}`,
        { cause: 'InvalidJson' },
      );
    }
  }
  if (contentType.includes('application/octet-stream') || contentType.includes('application/pdf')) {
    return response.arrayBuffer() as Promise<T>;
  }
  if (contentType.includes('multipart/form-data')) {
    return response.formData() as Promise<T>;
  }
  if (contentType.includes('image/') || contentType.includes('video/') || contentType.includes('audio/')) {
    return response.blob() as Promise<T>;
  }
  const reader = response.body?.getReader();
  if (!reader) return '' as T;
  const chunks: Uint8Array[] = [];
  let totalSize = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalSize += value.length;
      if (totalSize > maxSize)
        throw new Error(`Response too large: exceeded ${maxSize} bytes`, {
          cause: 'PayloadTooLarge',
        });
      chunks.push(value);
    }
    const combined = new Uint8Array(totalSize);
    let offset = 0;
    for (const chunk of chunks) {
      combined.set(chunk, offset);
      offset += chunk.length;
    }
    const text = new TextDecoder('utf-8', { fatal: false }).decode(combined);
    if (/^\s*[{[]/.test(text.trim())) {
      try {
        return JSON.parse(text) as T;
      } catch {
        return text as T;
      }
    }
    return text as T;
  } catch (error) {
    if (
      error instanceof Error &&
      (error.message.includes('too large') || error.cause === 'PayloadTooLarge')
    ) {
      throw error;
    }
    if (error instanceof Error && error.cause === 'InvalidJson') {
      throw error;
    }
    throw new Error('Failed to read or parse response body', { cause: error });
  }
}
