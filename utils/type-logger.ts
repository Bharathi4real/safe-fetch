const IS_DEV = process.env.NODE_ENV === 'development';

export function logTypes(endpoint: string, data: unknown, prefix = ''): void {
  if (!IS_DEV) return;
  const inferType = (val: unknown, depth = 0, path = ''): string => {
    if (depth > 10) return 'unknown /* depth exceeded */';
    if (val === null) return 'null';
    if (val === undefined) return 'undefined';
    if (Array.isArray(val)) {
      if (val.length === 0) return 'unknown[]';
      const firstType = inferType(val[0], depth + 1, `${path}[0]`);
      const allSameBasicType = val.every(
        (item) => typeof item === typeof val[0] || (item === null && val[0] === null),
      );
      return allSameBasicType ? `${firstType}[]` : `Array<${firstType} | unknown>`;
    }
    if (typeof val === 'object' && val !== null) {
      const obj = val as Record<string, unknown>;
      const props = Object.entries(obj)
        .slice(0, 50)
        .map(([k, v]) => {
          const keyPath = path ? `${path}.${k}` : k;
          const valueType = /password|token|secret|key|auth/i.test(k)
            ? 'string /* redacted */'
            : inferType(v, depth + 1, keyPath);
          return `    ${JSON.stringify(k)}: ${valueType}; // ${keyPath}`;
        })
        .join('\n');
      const ellipsis = Object.keys(obj).length > 50 ? '\n    // ... more properties' : '';
      return `{\n${props}${ellipsis}\n}`;
    }
    return typeof val;
  };
  try {
    const typeName = (prefix + endpoint)
      .replace(/[^a-zA-Z0-9]/g, '_')
      .replace(/^_+|_+$/g, '')
      .replace(/_{2,}/g, '_')
      .replace(/^(\d)/, '_$1');
    const inferred = inferType(data);
    console.log(`🔍 ${prefix}Inferred Type for "${endpoint}"`);
    console.log(`type ${typeName}Type = ${inferred};`);
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      const obj = data as Record<string, unknown>;
      if ('error' in obj) {
        console.log(`// Error message type: ${typeof obj.error}`);
        if (typeof obj.error === 'string') {
          console.log(`// Error: "${obj.error}"`);
        }
      }
      if ('message' in obj) {
        console.log(`// Message type: ${typeof obj.message}`);
        if (typeof obj.message === 'string') {
          console.log(`// Message: "${obj.message}"`);
        }
      }
    }
  } catch (err) {
    console.warn('[logTypes] Failed to infer types:', err);
  }
}
