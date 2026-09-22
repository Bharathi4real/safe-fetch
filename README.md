# 🛡️ SafeFetch

**A high-performance, type-safe fetch utility for modern full-stack applications.**

SafeFetch is a lightweight HTTP client built on top of the native `fetch` API.
It introduces **intelligent retries, request deduplication, concurrency pooling, adaptive rate limiting, schema validation, and secure authentication handling** — all while keeping the runtime footprint extremely small.

Designed primarily for **Next.js, Node.js, Bun, and Edge Runtime environments**, SafeFetch focuses on **resilience, performance, and predictable API behavior**.

---

# Why SafeFetch Exists

Modern applications frequently suffer from problems such as:

| Problem                     | Typical Result              |
| --------------------------- | --------------------------- |
| Duplicate API calls         | Unnecessary load on servers |
| Unbounded concurrency       | Resource exhaustion         |
| Transient failures          | Random UI breakage          |
| Weak response typing        | Runtime bugs                |
| Credential refresh issues   | Authentication loops        |
| Unstructured error handling | Hard-to-debug failures      |

SafeFetch solves these issues through a **layered architecture** combining:

* concurrency pooling
* rate limiting
* retry orchestration
* typed validation
* authentication caching
* request deduplication

All implemented **without external runtime dependencies** — SafeFetch has no `node:crypto`, no `node:buffer`, and no other Node-only static imports, so the same file runs unmodified in Node.js, Bun, browsers, and the Edge Runtime.

---

# Key Features

## Intelligent Request Pooling

SafeFetch manages network concurrency using an internal priority queue.

```
high → normal → low
```

This ensures critical requests are executed first while background tasks are deferred.

---

## Built-in Rate Limiting

A sliding window limiter prevents API flooding.

Default configuration:

```
100 requests / minute
```

Requests exceeding the limit are queued automatically.

---

## Automatic Retries

SafeFetch retries transient network failures using exponential backoff.

Retryable status codes:

```
408
429
500
502
503
504
```

It also respects server-provided `Retry-After` headers.

---

## Request Deduplication

Concurrent requests targeting the same resource are automatically merged.

```
Component A
Component B
Component C
        ↓
     One network request
```

All callers receive the same resolved promise.

---

## Type-Safe Responses

SafeFetch returns a **discriminated union response type**, eliminating unsafe data access.

```ts
if (apiRequest.isSuccess(response)) {
  response.data
} else {
  response.error
}
```

This pattern prevents accessing data before verifying success.

---

## Zod Schema Validation

Optional runtime validation ensures API responses match expected structures.

```ts
schema: UserSchema
```

Invalid responses fail safely before reaching application logic.

`zod` is a peer dependency — install it if you use `schema`:

```
npm install zod
```

---

## Authentication Management

SafeFetch supports both:

**Bearer Token**

```
Authorization: Bearer <token>
```

**Basic Auth**

```
Authorization: Basic <base64>
```

Auth headers are cached for **5 minutes** to avoid unnecessary recomputation.

If a request returns **401**, the cache automatically invalidates.

---

## SSRF Protection

An instance can be restricted to a fixed set of hosts via `createSafeFetch()`:

```ts
createSafeFetch({
  allowedHosts: ["api.example.com"]
})
```

Any request whose resolved hostname isn't in the list is blocked before the network call is made.

---

## Runtime Awareness

SafeFetch automatically adapts default concurrency depending on runtime.

| Runtime          | Max Concurrent Requests |
| ---------------- | ------------------------ |
| Node.js           | 10                       |
| Bun                | 20                       |
| Edge Runtime | 10 (Node.js default)     |

---

# Runtime Compatibility

SafeFetch is written against Web-standard APIs only (`fetch`, `AbortController`, `URL`, `crypto.randomUUID`, `Float64Array`), so it works unchanged across:

| Environment                                             | Supported |
| -------------------------------------------------------- | :-------: |
| Node.js (API routes, Server Actions, Server Components) |     ✅     |
| Bun                                                       |     ✅     |
| Browser (client components)                              |     ✅     |
| Next.js Edge Middleware                                   |     ✅     |
| Next.js Edge Route Handlers (`runtime = "edge"`)           |     ✅     |

There is no separate "edge build" — import the same `safe-fetch.ts` everywhere.

---

# Architecture Overview

SafeFetch consists of several internal subsystems working together:

```
User Request
     │
     ▼
URL Builder (LRU Cache)
     │
     ▼
Deduplication Key Generator
     │
     ▼
Priority Connection Pool
     │
     ▼
Rate Limiter
     │
     ▼
Fetch Execution
     │
     ▼
Response Parser
     │
     ▼
Transform / Schema Validation
     │
     ▼
Typed ApiResponse
```

This layered architecture ensures **predictable networking behavior even under heavy load**.

---

# Getting Started

Clone the repository or copy the `safe-fetch.ts` file into your project.

Example structure:

```
project
 ├─ lib
 │   └─ safe-fetch.ts
 ├─ app
 ├─ components
 └─ services
```

Import the utility where needed:

```ts
import apiRequest from "@/lib/safe-fetch"
```

Using `schema` validation also requires `zod` as a dependency (see [Zod Schema Validation](#zod-schema-validation)).

---

# Basic Usage

```ts
interface User {
  id: string
  name: string
}

const response = await apiRequest<User>("GET", "/users/1")

if (apiRequest.isSuccess(response)) {
  console.log(response.data.name)
} else {
  console.error(response.error.message)
}
```

---

# REST Helper API

SafeFetch includes convenience wrappers.

```ts
import { api } from "@/lib/safe-fetch"

api.get<T>(endpoint, options)
api.post<T>(endpoint, options)
api.put<T>(endpoint, options)
api.patch<T>(endpoint, options)
api.delete<T>(endpoint, options)
```

Example:

```ts
const user = await api.get<User>("/users/1")
```

---

# Configuration

The default `apiRequest`/`api` export is a ready-to-use singleton. For a dedicated instance — a different base URL, stricter retries, a host allowlist — use `createSafeFetch()`:

```ts
import { createSafeFetch } from "@/lib/safe-fetch"

const { api, apiRequest, invalidateAuthCache } = createSafeFetch({
  baseUrl: "https://api.example.com",
  retries: 2,
  timeout: 60_000,
  maxConcurrent: 10,
  rateMax: 100,
  rateWindow: 60_000,
  authCacheTtl: 300_000,
  allowedHosts: ["api.example.com"],
  getAuthHeaders: () => ({ Authorization: "Bearer <token>" })
})
```

| Option            | Default                        | Purpose                                                        |
| ------------------ | ------------------------------- | ---------------------------------------------------------------- |
| `baseUrl`             | `API_URL` / `NEXT_PUBLIC_API_URL` | Base URL prepended to relative endpoints                          |
| `retries`             | `2`                              | Max retry attempts per request                                    |
| `timeout`             | `60000` (ms)                     | Per-attempt request timeout                                       |
| `maxConcurrent`       | `10` (`20` on Bun)               | Connection pool size                                               |
| `rateMax`             | `100`                            | Max requests per `rateWindow`                                     |
| `rateWindow`          | `60000` (ms)                     | Rate-limit sliding window                                          |
| `authCacheTtl`        | `300000` (ms)                    | How long auth headers are cached before rebuilding                 |
| `allowedHosts`        | *(unset — all hosts allowed)*    | SSRF allowlist                                                     |
| `getAuthHeaders`      | env-based token/basic-auth       | Override to supply auth headers from your own logic                |

Each instance created by `createSafeFetch()` has its own pool, rate limiter, URL cache, and auth cache — instances never share state.

---

# Request Options

`RequestOptions` controls request behavior.

```ts
interface RequestOptions {
  data?: RequestBody
  params?: QueryParams
  retries?: number
  timeout?: number | ((attempt:number)=>number)
  headers?: Record<string,string>
  transform?(data): unknown
  schema?: ZodSchema
  priority?: "high" | "normal" | "low"
  signal?: AbortSignal
  logTypes?: boolean
  cache?: RequestCache
  next?: { revalidate?: number | false; tags?: string[] }
  dedupeKey?: string | null
  skipAuth?: boolean
}
```

---

# Sending Data

### JSON

```ts
await api.post("/users", {
  data: { name: "Bharathi" }
})
```

### FormData

```ts
const form = new FormData()
form.append("avatar", file)

await api.post("/upload", { data: form })
```

---

# Query Parameters

```ts
await api.get("/posts", {
  params: {
    page: 1,
    limit: 10,
    search: "NextJS"
  }
})
```

Produces:

```
/posts?page=1&limit=10&search=NextJS
```

---

# Retry Configuration

```ts
await api.get("/critical-resource", {
  retries: 5
})
```

---

# Adaptive Timeout

```ts
await api.get("/slow-api", {
  timeout: attempt => attempt * 4000
})
```

---

# Request Deduplication

```ts
await api.get("/settings", {
  dedupeKey: "global-settings"
})
```

Omit `dedupeKey` and SafeFetch derives one automatically from the method, URL, and (for non-`GET` requests) a hash of the body — so identical concurrent calls still dedupe without any extra config.

---

# Next.js Cache Integration

SafeFetch supports Next.js extended fetch caching.

```ts
await api.get("/products", {
  cache: "force-cache",
  next: {
    revalidate: 3600,
    tags: ["products"]
  }
})
```

> Since Next.js 15, `fetch` requests are **uncached by default**. Pass `cache: "force-cache"` and/or `next.revalidate` explicitly when you want caching — omit both for always-fresh data.

---

# Request Cancellation

```ts
const controller = new AbortController()

api.get("/large-dataset", {
  signal: controller.signal
})

controller.abort()
```

---

# Runtime Monitoring

```ts
const stats = apiRequest.utils.getStats()
```

Example:

```ts
{
  pool: { active: 2, queued: 3 },
  rateLimit: { current: 5 },
  runtime: "node"
}
```

---

# Environment Variables

SafeFetch reads the following environment variables (checked in this order per credential type):

| Variable                       | Purpose                              |
| -------------------------------- | --------------------------------------- |
| `API_URL`                          | Default API base URL                    |
| `NEXT_PUBLIC_API_URL`              | Fallback base URL (e.g. client bundles) |
| `AUTH_USERNAME` / `API_USERNAME`   | Basic auth username                     |
| `AUTH_PASSWORD` / `API_PASSWORD`   | Basic auth password                     |
| `AUTH_TOKEN` / `API_TOKEN`         | Bearer token                            |

If both a username/password pair and a token are set, Basic Auth takes priority. Any of these can be bypassed per-instance with the `getAuthHeaders` config option, or per-request with `skipAuth: true`.

---

# Security Considerations

SafeFetch includes safeguards against common networking risks:

- SSRF protection via `allowedHosts`
- Auth cache invalidation on unauthorized (401) responses
- Header sanitization utilities (`apiRequest.utils.sanitizeHeaders`)
- Request timeout enforcement (fixed or per-attempt function)
- Retry-storm prevention (bounded exponential backoff + jitter, `Retry-After` aware)

---

# License

BSD 3-Clause License

Copyright © 2025 Bharathi4real

---

# Author

Bharathi4real
https://github.com/Bharathi4real/safe-fetch

---

⭐ If this utility helps your project, consider starring the repository.
