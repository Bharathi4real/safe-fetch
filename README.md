# 🛡️ SafeFetch

**A high-performance, type-safe fetch utility for modern full-stack applications.**

SafeFetch is a lightweight HTTP client built on top of the native `fetch` API.
It introduces **intelligent retries, request deduplication, concurrency pooling, adaptive rate limiting, schema validation, and secure authentication handling** — all while keeping the runtime footprint extremely small.

Designed primarily for **Next.js, Node.js, and Bun environments**, SafeFetch focuses on **resilience, performance, and predictable API behavior**.

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

All implemented **without external runtime dependencies**.

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

Requests can be restricted to specific hosts.

```ts
allowedHosts: ["api.example.com"]
```

Requests targeting other hosts are blocked immediately.

---

## Runtime Awareness

SafeFetch automatically adapts concurrency depending on runtime.

| Runtime | Max Concurrent Requests |
| ------- | ----------------------- |
| Node.js | 10                      |
| Bun     | 20                      |

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

SafeFetch reads the following environment variables:

| Variable            | Purpose               |
| ------------------- | --------------------- |
| API_URL             | Default API base URL  |
| NEXT_PUBLIC_API_URL | Client-side API URL   |
| API_TOKEN           | Bearer authentication |
| AUTH_USERNAME       | Basic auth username   |
| AUTH_PASSWORD       | Basic auth password   |

---

# Security Considerations

SafeFetch includes safeguards against common networking risks:

• SSRF protection
• Auth cache invalidation on unauthorized responses
• Header sanitization utilities
• Request timeout enforcement
• Retry-storm prevention

---

# License

BSD 3-Clause License

Copyright © 2025 Bharathi4real

---

# Author

Bharathi
https://github.com/Bharathi4real/safe-fetch

---

⭐ If this utility helps your project, consider starring the repository.
