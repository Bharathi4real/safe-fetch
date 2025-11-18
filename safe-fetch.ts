/**
 * SafeFetch – Optimized Typed Fetch utility for Next.js 15
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * Memory-optimized with unified retry, timeout & adaptive pooling
 */

"use server";

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
  transform?<T = TResponse, R = TResponse>(data: T): R;
  priority?: "high" | "normal" | "low";
  signal?: AbortSignal;
  batch?: boolean;
  logTypes?: boolean;
}

export interface ApiError {
  readonly name: string;
  readonly message: string;
  readonly status: number;
  readonly retryable?: boolean;
}

export type ApiResponse<T = unknown> =
  | { success: true; status: number; data: T; headers: Record<string, string> }
  | { success: false; status: number; error: ApiError; data: null };

// -------------------- Runtime Detection --------------------
const IS_BUN = typeof globalThis !== "undefined" && "Bun" in globalThis;
const IS_NODE = !IS_BUN && typeof process !== "undefined";

// -------------------- Configuration --------------------
const CONFIG = {
  API_URL: process.env.NEXT_PUBLIC_API_URL ?? process.env.BASE_URL ?? "",
  RETRY_CODES: new Set([408, 429, 500, 502, 503, 504]),
  IDEMPOTENT_METHODS: new Set<HttpMethod>(["GET", "PUT", "DELETE"]),
  DEFAULT_TIMEOUT: 60000,
  DEFAULT_RETRIES: 2,
  MAX_CONCURRENT: IS_BUN ? 20 : 10,
  BATCH_SIZE: IS_BUN ? 20 : 10,
  BATCH_DELAY: IS_BUN ? 25 : 50,
  IS_DEV: process.env.NODE_ENV === "development",
  LOG_SIZE_LIMIT: 50000,
} as const;

// -------------------- Adaptive Pool --------------------
class Pool {
  private readonly queue: Array<{
    fn: () => Promise<unknown>;
    resolve: (value: unknown) => void;
    reject: (reason?: unknown) => void;
    priority: number;
  }> = [];
  private active = 0;
  private readonly maxConcurrent = CONFIG.MAX_CONCURRENT;
  private readonly priorityMap = { high: 3, normal: 2, low: 1 };

  async execute<T>(
    fn: () => Promise<T>,
    priority: "high" | "normal" | "low" = "normal",
  ): Promise<T> {
    if (this.active < this.maxConcurrent) return this.run(fn);

    const priorityNum = this.priorityMap[priority];
    return new Promise<T>((resolve, reject) => {
      const task = {
        fn: fn as () => Promise<unknown>,
        resolve: resolve as (value: unknown) => void,
        reject,
        priority: priorityNum,
      };

      const idx = this.findInsertIndex(priorityNum);
      this.queue.splice(idx, 0, task);
    });
  }

  private findInsertIndex(priority: number): number {
    let left = 0;
    let right = this.queue.length;

    while (left < right) {
      const mid = (left + right) >>> 1;
      if (this.queue[mid].priority >= priority) left = mid + 1;
      else right = mid;
    }

    return left;
  }

  private async run<T>(fn: () => Promise<T>): Promise<T> {
    this.active++;
    try {
      return await fn();
    } finally {
      this.active--;
      this.processQueue();
    }
  }

  private processQueue(): void {
    while (this.queue.length > 0 && this.active < this.maxConcurrent) {
      // biome-ignore lint/style/noNonNullAssertion: <needed>
      const task = this.queue.shift()!;
      this.run(task.fn as () => Promise<unknown>)
        .then(task.resolve)
        .catch(task.reject);
    }
  }

  getStats(): { active: number; queued: number; maxConcurrent: number } {
    return {
      active: this.active,
      queued: this.queue.length,
      maxConcurrent: this.maxConcurrent,
    };
  }
}

const pool = new Pool();

// -------------------- Utilities --------------------
const buildUrl = (endpoint: string, params?: QueryParams): string => {
  const isAbsolute =
    endpoint.charCodeAt(0) === 104 && endpoint.startsWith("http");
  if (!params)
    return isAbsolute
      ? endpoint
      : `${CONFIG.API_URL}/${endpoint.replace(/^\//, "")}`;

  const parts: string[] = [];
  const entries = Object.entries(params);

  for (let i = 0, len = entries.length; i < len; i++) {
    const [key, value] = entries[i];
    if (value != null)
      parts.push(
        `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`,
      );
  }

  const query = parts.length > 0 ? `?${parts.join("&")}` : "";
  return isAbsolute
    ? `${endpoint}${query}`
    : `${CONFIG.API_URL}/${endpoint.replace(/^\//, "")}${query}`;
};

const getAuthHeaders = (() => {
  let cached: Record<string, string> | null = null;
  let lastCheck = 0;
  let authString = "";

  return (): Record<string, string> => {
    const now = Date.now();
    if (cached && now - lastCheck < 300000) return cached;

    const headers: Record<string, string> = {};
    const {
      AUTH_USERNAME: user,
      AUTH_PASSWORD: pass,
      API_TOKEN: token,
    } = process.env;

    if (user && pass) {
      if (!authString || now - lastCheck >= 300000) {
        authString = IS_BUN
          ? btoa(`${user}:${pass}`)
          : Buffer.from(`${user}:${pass}`).toString("base64");
      }
      headers.Authorization = `Basic ${authString}`;
    } else if (token) {
      headers.Authorization = `Bearer ${token}`;
    }

    cached = headers;
    lastCheck = now;
    return headers;
  };
})();

const createError = (
  name: string,
  message: string,
  status: number,
  retryable = false,
): ApiError => Object.freeze({ name, message, status, retryable });

// -------------------- Type Logging --------------------
const logTypes = <T>(
  endpoint: string,
  data: T,
  metadata?: { duration?: number; attempt?: number },
): void => {
  try {
    let payload: unknown = data;

    const isApiWrapper = (
      obj: unknown,
    ): obj is {
      success: boolean;
      data?: unknown;
      headers?: Record<string, string>;
      status?: number;
    } =>
      typeof obj === "object" &&
      obj !== null &&
      "success" in (obj as Record<string, unknown>) &&
      ("headers" in (obj as Record<string, unknown>) ||
        "status" in (obj as Record<string, unknown>));

    if (isApiWrapper(payload)) {
      payload = (payload as { data?: unknown }).data;
    }

    if (payload == null || typeof payload !== "object") {
      const simpleType = payload === null ? "null" : typeof payload;
      console.log(`🔍 [SafeFetch] "${endpoint}"`);
      console.log(
        `type ${endpoint.replace(/[^\w]/g, "_")}Response = ${simpleType};`,
      );
      return;
    }

    let dataStr: string;
    try {
      dataStr = JSON.stringify(payload);
    } catch (_error) {
      console.log(
        `🔍 [SafeFetch] "${endpoint}" - Response cannot be stringified for logging`,
      );
      return;
    }

    if (dataStr.length > CONFIG.LOG_SIZE_LIMIT) {
      console.log(
        `🔍 [SafeFetch] "${endpoint}" - Response too large to log (${dataStr.length} chars, limit: ${CONFIG.LOG_SIZE_LIMIT})`,
      );
      return;
    }

    const inferType = (val: unknown, depth = 0): string => {
      if (depth > 8) return "[Deep]";
      if (val == null) return val === null ? "null" : "undefined";
      if (Array.isArray(val)) {
        if (val.length === 0) return "unknown[]";
        const types = [
          ...new Set(val.slice(0, 3).map((item) => inferType(item, depth + 1))),
        ];
        return types.length === 1
          ? `${types[0]}[]`
          : `(${types.join(" | ")})[]`;
      }
      if (typeof val === "object") {
        const entries = Object.entries(val).slice(0, 15);
        const props = entries
          .map(([k, v]) => `  ${k}: ${inferType(v, depth + 1)};`)
          .join("\n");
        return `{\n${props}\n}`;
      }
      return typeof val;
    };

    const typeName = endpoint.replace(/[^\w]/g, "_") || "ApiResponse";
    const typeDefinition = `type ${typeName}Response = ${inferType(payload)};`;

    console.log(`[SafeFetch] "${endpoint}"\n${typeDefinition}`);
    if (metadata?.duration !== undefined) {
      console.log(
        `⏱️ ${metadata.duration}ms${metadata.attempt ? ` (attempt ${metadata.attempt})` : ""}`,
      );
    }
  } catch (err) {
    console.error("[SafeFetch] logTypes error:", err);
  }
};

// -------------------- Core Request Logic --------------------
const executeRequest = async <T>(
  method: HttpMethod,
  url: string,
  options: {
    body?: BodyInit;
    headers: Record<string, string>;
    timeout: number;
    signal?: AbortSignal;
  },
): Promise<ApiResponse<T>> => {
  const controller = new AbortController();
  let timeoutId: ReturnType<typeof setTimeout> | undefined;

  const signal = options.signal
    ? (() => {
        const combined = new AbortController();
        const abort = () => combined.abort();
        options.signal.addEventListener("abort", abort, { once: true });
        controller.signal.addEventListener("abort", abort, { once: true });
        return combined.signal;
      })()
    : controller.signal;

  timeoutId = setTimeout(() => controller.abort(), options.timeout);

  try {
    const fetchOptions: RequestInit = {
      method,
      headers: options.headers,
      signal,
    };
    if (options.body !== undefined) fetchOptions.body = options.body;

    const response = await fetch(url, fetchOptions);
    clearTimeout(timeoutId);

    const isJson = response.headers
      .get("content-type")
      ?.includes("application/json");
    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key] = value;
    });
    const data = isJson ? await response.json() : await response.text();

    if (response.ok) {
      return {
        success: true,
        status: response.status,
        data: data as T,
        headers,
      };
    }

    const message =
      typeof data === "object" && data && "message" in data
        ? data.message
        : typeof data === "string"
          ? data
          : `HTTP ${response.status}`;

    return {
      success: false,
      status: response.status,
      error: createError(
        "HttpError",
        message,
        response.status,
        CONFIG.RETRY_CODES.has(response.status),
      ),
      data: null,
    };
  } catch (err) {
    if (timeoutId) clearTimeout(timeoutId);
    const isAbortError =
      err instanceof Error &&
      (err.name === "AbortError" || /abort|timeout/i.test(err.message));
    const errorName = isAbortError ? "TimeoutError" : "NetworkError";
    const errorStatus = isAbortError ? 408 : 0;
    const errorMessage = err instanceof Error ? err.message : "Request failed";
    return {
      success: false,
      status: errorStatus,
      error: createError(errorName, errorMessage, errorStatus, true),
      data: null,
    };
  }
};

// -------------------- Main API Function --------------------
export default async function apiRequest<
  TResponse = unknown,
  TBody extends RequestBody = RequestBody,
>(
  method: HttpMethod,
  endpoint: string,
  options: RequestOptions<TBody, TResponse> = {},
): Promise<ApiResponse<TResponse>> {
  if (!HTTP_METHODS.includes(method)) {
    return {
      success: false,
      status: 400,
      error: createError("ValidationError", `Invalid method: ${method}`, 400),
      data: null,
    };
  }

  const {
    data,
    params,
    retries = CONFIG.DEFAULT_RETRIES,
    timeout = CONFIG.DEFAULT_TIMEOUT,
    headers: customHeaders,
    transform,
    priority = "normal",
    signal,
    logTypes: shouldLogTypes = false,
  } = options;

  const url = buildUrl(endpoint, params);
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...getAuthHeaders(),
    ...customHeaders,
  };

  let body: BodyInit | undefined;
  if (data) {
    if (data instanceof FormData) body = data;
    else if (typeof data === "string") body = data;
    else {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(data);
    }
  }

  const startTime = Date.now();

  return pool.execute(async () => {
    let attempt = 0;

    while (true) {
      attempt++;
      const timeoutValue =
        typeof timeout === "function" ? timeout(attempt) : timeout;
      const result = await executeRequest<TResponse>(method, url, {
        body,
        headers,
        timeout: timeoutValue,
        signal,
      });

      if (result.success) {
        const finalResult = transform
          ? { ...result, data: transform(result.data) }
          : result;

        // Only log the *data*, never headers or wrapper response
        if (shouldLogTypes && CONFIG.IS_DEV) {
          logTypes(endpoint, finalResult.data, {
            duration: Date.now() - startTime,
            attempt: attempt > 1 ? attempt : undefined,
          });
        }

        return finalResult;
      }

      const canRetry =
        attempt <= retries &&
        CONFIG.IDEMPOTENT_METHODS.has(method) &&
        (result.error.retryable || CONFIG.RETRY_CODES.has(result.status));

      if (!canRetry) return result;

      const baseDelay = 100 * (1 << (attempt - 1));
      const jitter = Math.random() * 100;
      const delay = Math.min(1000, baseDelay + jitter);
      await new Promise<void>((resolve) => setTimeout(resolve, delay));
    }
  }, priority);
}

// -------------------- Utility Methods --------------------
apiRequest.isSuccess = <T>(
  response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: true }> => response.success;

apiRequest.isError = <T>(
  response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: false }> => !response.success;

apiRequest.utils = {
  getStats: () => ({
    pool: pool.getStats(),
    runtime: IS_BUN ? "bun" : IS_NODE ? "node" : "unknown",
  }),
  timeout: (ms: number): AbortSignal => {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), ms);
    return controller.signal;
  },
};
