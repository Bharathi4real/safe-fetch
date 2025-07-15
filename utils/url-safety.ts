const IS_DEV = process.env.NODE_ENV === 'development';

const CONFIG = {
  security: {
    allowedProtocols: new Set(['http:', 'https:']),
    blockedHosts: new Set([
      'localhost',
      '127.0.0.1',
      '0.0.0.0',
      '169.254.169.254',
      '100.100.100.200',
      'metadata.google.internal',
      'metadata',
    ]),
    blockedIpRanges: [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[01])\./,
      /^192\.168\./,
      /^::1$/,
      /^fe80:/,
      /^fc00:/,
    ],
    maxUrlLength: 2048,
    maxHeaderLength: 8192,
    maxRedirects: 5,
  },
} as const;

const ENV_ALLOWED_HOSTS = (() => {
  const hostsEnv = process.env.ALLOWED_HOSTS || process.env.SAFEFETCH_ALLOWED_HOSTS;
  return hostsEnv
    ?.split(',')
    .map((h) => h.trim().toLowerCase())
    .filter((h) => h && /^[a-z0-9.-]+$/.test(h)) || [];
})();

export function isUrlSafe(url: string, allowedHosts?: string[]): boolean {
  try {
    if (url.length > CONFIG.security.maxUrlLength) {
      if (IS_DEV) console.warn(`URL too long: ${url.length} > ${CONFIG.security.maxUrlLength}`);
      return false;
    }
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();
    if (!CONFIG.security.allowedProtocols.has(parsed.protocol)) {
      if (IS_DEV) console.warn(`Blocked protocol: ${parsed.protocol}`);
      return false;
    }
    if (CONFIG.security.blockedHosts.has(hostname)) {
      if (IS_DEV) console.warn(`Blocked hostname: ${hostname}`);
      return false;
    }
    const isIpAddress =
      /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^\[(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\]$|^[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7}$/.test(
        hostname,
      ) || hostname.includes(':');
    if (isIpAddress && CONFIG.security.blockedIpRanges.some((range) => range.test(hostname))) {
      if (IS_DEV) console.warn(`Blocked IP range: ${hostname}`);
      return false;
    }
    const allAllowed = [...ENV_ALLOWED_HOSTS, ...(allowedHosts?.map((h) => h.toLowerCase()) || [])];
    if (
      allAllowed.length > 0 &&
      !allAllowed.some((h) => hostname === h || hostname.endsWith(`.${h}`))
    ) {
      if (IS_DEV) console.warn(`Hostname not in allowed list: ${hostname}`);
      return false;
    }
    const isSafePort = !parsed.port || ['80', '443', ''].includes(parsed.port);
    if (!isSafePort) {
      if (IS_DEV) console.warn(`Blocked port: ${parsed.port}`);
      return false;
    }
    if (parsed.username || parsed.password) {
      if (IS_DEV) console.warn('URL contains credentials');
      return false;
    }
    return true;
  } catch (e) {
    if (IS_DEV) console.warn('isUrlSafe validation failed:', e);
    return false;
  }
}
