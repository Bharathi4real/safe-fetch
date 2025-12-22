/**
 * SafeFetch – Optimized Typed Fetch utility for Next.js 16
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * Memory-optimized with unified retry, timeout & adaptive pooling
 * https://github.com/Bharathi4real/safe-fetch/
 */

const HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"] as const;
export type HttpMethod = (typeof HTTP_METHODS)[number];
export type RequestBody = Record<string, unknown> | FormData | string | null;
export type QueryParams = Record<
  string,
  string | number | boolean | null | undefined
>;

export interface RequestOptions<
  TBody extends RequestBody = RequestBody,
  TResponse = unknown,
> {
  data?: TBody;
  params?: QueryParams;
  retries?: number;
  timeout?: number | ((attempt: number) => number);
  headers?: Record<string, string>;
  transform?(data: TResponse): TResponse;
  priority?: "high" | "normal" | "low";
  signal?: AbortSignal;
  logTypes?: boolean;
  cache?: RequestCache;
  next?: { revalidate?: number | false; tags?: string[] };
  dedupeKey?: string | null;
  skipAuth?: boolean;
}

export type ApiResponse<T = unknown> =
  | { success: true; status: number; data: T; headers: Record<string, string> }
  | { success: false; status: number; error: ApiError; data: null };

export interface ApiError {
  readonly name: string;
  readonly message: string;
  readonly status: number;
  readonly retryable?: boolean;
  readonly url?: string;
  readonly method?: string;
}

const IS_BUN = typeof globalThis !== "undefined" && "Bun" in globalThis;
const RETRY_CODES = new Set([408, 429, 500, 502, 503, 504]);

interface GlobalEnv {
  __ENV__?: Record<string, string>;
}

const getEnv = () => {
  const env = process.env || (globalThis as unknown as GlobalEnv).__ENV__ || {};
  const vals = {
    API_URL: env.NEXT_PUBLIC_API_URL || env.BASE_URL || env.API_URL || "",
    AUTH_USERNAME: env.AUTH_USERNAME || "",
    AUTH_PASSWORD: env.AUTH_PASSWORD || "",
    API_TOKEN: env.API_TOKEN || "",
    NODE_ENV: env.NODE_ENV || "development",
  };
  if (!vals.API_URL)
    console.error("\x1b[31m%s\x1b[0m", "❌ [SafeFetch] Missing API_URL");
  if (!vals.AUTH_USERNAME && !vals.API_TOKEN)
    console.error(
      "\x1b[31m%s\x1b[0m",
      "❌ [SafeFetch] Missing Auth Credentials",
    );
  return vals;
};
const ENV = getEnv();
const CFG = {
  RETRIES: 2,
  TIMEOUT: 60000,
  MAX_CONCURRENT: IS_BUN ? 20 : 10,
  RATE_MAX: 100,
  RATE_WINDOW: 60000,
};

/* --- Util Classes --- */
class RateLimiter {
  private reqs: number[] = [];
  async check(max = CFG.RATE_MAX, win = CFG.RATE_WINDOW): Promise<void> {
    const now = Date.now();
    this.reqs = this.reqs.filter((t) => now - t < win);
    if (this.reqs.length >= max) {
      await new Promise((r) => setTimeout(r, win - (now - this.reqs[0])));
      return this.check(max, win);
    }
    this.reqs.push(now);
  }
  stats = () => ({ current: this.reqs.length });
}
const limiter = new RateLimiter();

class Pool {
  private q: Array<{ fn: () => void; pri: number }> = [];
  private active = 0;
  private pend = new Map<string, Promise<unknown>>();

  constructor(private max = CFG.MAX_CONCURRENT) {}

  async exec<T>(
    fn: () => Promise<T>,
    pri: "high" | "normal" | "low" = "normal",
    key?: string | null,
  ): Promise<T> {
    if (key && this.pend.has(key)) return this.pend.get(key) as Promise<T>;

    const task = new Promise<T>((resolve, reject) => {
      const run = async () => {
        this.active++;
        try {
          resolve(await fn());
        } catch (e) {
          reject(e);
        } finally {
          this.active--;
          if (key) this.pend.delete(key);
          if (this.q.length && this.active < this.max) this.q.shift()?.fn();
        }
      };

      if (this.active < this.max) {
        run();
      } else {
        const pVal = { high: 3, normal: 2, low: 1 }[pri];
        const idx = this.q.findIndex((i) => i.pri < pVal);
        this.q.splice(idx === -1 ? this.q.length : idx, 0, {
          fn: run,
          pri: pVal,
        });
      }
    });

    if (key) this.pend.set(key, task);
    return task;
  }
  stats = () => ({ active: this.active, queued: this.q.length });
}
const pool = new Pool();

/* --- Requests --- */
const getAuth = (() => {
  let cache: Record<string, string> | null = null,
    last = 0;
  return () => {
    if (cache && Date.now() - last < 300000) return cache;
    const { AUTH_USERNAME: u, AUTH_PASSWORD: p, API_TOKEN: t } = ENV;
    const h: Record<string, string> = {};
    if (u && p)
      h.Authorization = `Basic ${typeof btoa !== "undefined" ? btoa(`${u}:${p}`) : Buffer.from(`${u}:${p}`).toString("base64")}`;
    else if (t) h.Authorization = `Bearer ${t}`;
    last = Date.now();
    cache = h;
    return h;
  };
})();

const buildUrl = (ep: string, p?: QueryParams): string => {
  let url = ep;
  if (!/^https?:\/\//i.test(ep)) {
    const base =
      (typeof window !== "undefined" ? window.location.origin : "") ||
      ENV.API_URL;
    url = `${base.replace(/\/+$/, "")}/${ep.replace(/^\/+/, "")}`;
  }
  if (p) {
    const qs = new URLSearchParams(
      Object.entries(p)
        .filter(([_, v]) => v != null)
        .map(([k, v]) => [k, String(v)]),
    ).toString();
    if (qs) url += `?${qs}`;
  }
  return url;
};

const inferType = (v: unknown, d = 0): string => {
  if (d > 8) return "unknown";
  if (v === null) return "null";
  if (Array.isArray(v))
    return v.length ? `(${inferType(v[0], d + 1)})[]` : "unknown[]";
  if (typeof v === "object" && v)
    return `{\n${Object.entries(v)
      .slice(0, 10)
      .map(([k, val]) => `  ${k}: ${inferType(val, d + 1)}`)
      .join(",\n")}\n}`;
  return typeof v;
};

const logTypes = (
  ep: string,
  method: string,
  data: unknown,
  meta?: { time: number; att?: number },
) => {
  if (ENV.NODE_ENV !== "development") return;
  let payload = data;
  if (typeof data === "object" && data !== null && "data" in data) {
    payload = (data as { data: unknown }).data;
  }
  console.log(
    `🔍 [SafeFetch] ${method} ${ep} (${meta?.time}ms) \nType: ${inferType(payload)}`,
  );
};

export default async function apiRequest<T = unknown>(
  method: HttpMethod,
  endpoint: string,
  opts: RequestOptions<RequestBody, T> = {},
): Promise<ApiResponse<T>> {
  if (!HTTP_METHODS.includes(method))
    return {
      success: false,
      status: 400,
      error: {
        name: "ValidationError",
        message: "Invalid method",
        status: 400,
      },
      data: null,
    };
  const {
    retries = CFG.RETRIES,
    timeout = CFG.TIMEOUT,
    priority = "normal",
    dedupeKey,
  } = opts;
  const url = buildUrl(endpoint, opts.params);
  const key =
    dedupeKey ??
    `${method}:${url}:${JSON.stringify(opts.data || "").slice(0, 50)}`;
  const start = performance.now();

  return pool.exec(
    async () => {
      let attempt = 0;
      while (true) {
        attempt++;
        await limiter.check();
        const ctrl = new AbortController();
        const tid = setTimeout(
          () => ctrl.abort(),
          typeof timeout === "function" ? timeout(attempt) : timeout,
        );
        try {
          const res = await fetch(url, {
            method,
            headers: {
              Accept: "application/json",
              ...(opts.skipAuth ? {} : getAuth()),
              ...opts.headers,
              ...(opts.data ? { "Content-Type": "application/json" } : {}),
            },
            body: opts.data
              ? opts.data instanceof FormData
                ? opts.data
                : JSON.stringify(opts.data)
              : undefined,
            signal: opts.signal || ctrl.signal,
            next: opts.next,
            cache: opts.cache,
          });
          clearTimeout(tid);

          const isJson = res.headers.get("content-type")?.includes("json");
          const data: unknown = await (isJson ? res.json() : res.text());

          if (!res.ok) {
            const d =
              typeof data === "object" && data !== null
                ? (data as Record<string, unknown>)
                : {};
            const msg =
              typeof data === "string"
                ? data
                : typeof d.message === "string"
                  ? d.message
                  : typeof d.error === "string"
                    ? d.error
                    : res.statusText;
            throw { status: res.status, msg };
          }

          if (opts.logTypes)
            logTypes(endpoint, method, data, {
              time: Math.round(performance.now() - start),
              att: attempt > 1 ? attempt : undefined,
            });

          const headers: Record<string, string> = {};
          res.headers.forEach((v, k) => {
            headers[k] = v;
          });

          return {
            success: true,
            status: res.status,
            data: opts.transform ? opts.transform(data as T) : (data as T),
            headers,
          };
        } catch (e: unknown) {
          clearTimeout(tid);
          interface ErrorWithStatus {
            status?: number;
            name?: string;
            msg?: string;
            message?: string;
          }
          const rErr =
            typeof e === "object" && e !== null
              ? (e as ErrorWithStatus)
              : { message: String(e) };
          const status = rErr.status || (rErr.name === "AbortError" ? 408 : 0);

          if (
            !(
              attempt <= retries &&
              (status === 408 || status >= 500 || RETRY_CODES.has(status))
            )
          ) {
            return {
              success: false,
              status,
              error: {
                name: rErr.name || "Error",
                message: rErr.msg || rErr.message || "Unknown",
                status,
                retryable: false,
                url,
                method,
              },
              data: null,
            };
          }
          await new Promise((r) =>
            setTimeout(r, Math.min(1000, 100 * 2 ** (attempt - 1))),
          );
        }
      }
    },
    priority,
    key,
  );
}

// Helpers
apiRequest.isSuccess = <T>(
  r: ApiResponse<T>,
): r is Extract<ApiResponse<T>, { success: true }> => r.success;
apiRequest.isError = <T>(
  r: ApiResponse<T>,
): r is Extract<ApiResponse<T>, { success: false }> => !r.success;
apiRequest.utils = {
  getStats: () => ({
    pool: pool.stats(),
    rateLimit: limiter.stats(),
    runtime: IS_BUN ? "bun" : "node",
  }),
  sanitizeHeaders: (h: Record<string, string>) => {
    const s = { ...h };
    ["Authorization", "X-API-Key", "Cookie"].forEach((k) => {
      if (s[k]) s[k] = "[REDACTED]";
    });
    return s;
  },
};
