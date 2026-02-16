# 🛡️ SafeFetch

> **Optimized Typed Fetch utility for Next.js 16, Node & Bun.**  
> A memory-efficient, concurrency-aware HTTP client with priority pooling, adaptive rate limiting, stable request deduplication, and typed endpoint factories.

---

## ✨ Overview

SafeFetch is a drop-in replacement for `fetch()` designed for modern server runtimes:

- ✅ Next.js 16 App Router (Server Actions & Route Handlers)
- ✅ Node.js
- ✅ Bun (auto-optimized concurrency)
- ✅ Typed end-to-end responses
- ✅ Production-safe retry + rate limiting
- ✅ Dev-only recursive type inference

---

## 🚀 Core Capabilities

### 🔁 Priority-Based Concurrency Pool

Internal queue executes requests based on priority:

- `high` → critical system calls
- `normal` → default
- `low` → background telemetry

Automatically scales:
- **20 concurrent tasks on Bun**
- **10 concurrent tasks on Node**

---

### 🧠 Stable Request Deduplication

If identical requests are in-flight, SafeFetch reuses the same Promise.

Prevents:
- Duplicate API calls
- Race conditions
- Wasted bandwidth

---

### ⏱ Smart Retries (Exponential Backoff + Jitter)

Automatically retries on:

```
408, 429, 500, 502, 503, 504
```

With exponential jittered backoff:

```
100ms → 200ms → 400ms → ... (max 10s)
```

---

### 🚦 Adaptive Rate Limiting

Sliding window limiter:

- Default: **100 requests / minute**
- Requests exceeding limit are intelligently queued

---

### 🔐 Unified Auth Injection (TTL Cached)

Supports:

- `Bearer <API_TOKEN>`
- `Basic <username:password>`

Credentials are cached for **5 minutes** to avoid repeated environment resolution.

---

### 🧪 Dev-Only Recursive Type Inference

When `logTypes: true` (development only), SafeFetch logs a copy-pasteable TypeScript structure inferred from the API response.

---

# 📦 Installation

Place `safe-fetch.ts` inside:

```
/lib/safe-fetch.ts
```

Then import:

```ts
import apiRequest from '@/lib/safe-fetch';
```

---

# ⚡ Quick Start

```typescript
import apiRequest from '@/lib/safe-fetch';

interface User {
  id: string;
  name: string;
}

const response = await apiRequest<User>('GET', '/api/user/1');

if (apiRequest.isSuccess(response)) {
  console.log(response.data.name);
}
```

---

# 🧩 RequestOptions — Complete Usage Guide

All available options in SafeFetch v2.

---

## 1️⃣ `data` — Request Body

Supports:

- JSON object
- `FormData`
- `string`
- `Blob`
- `ArrayBuffer`
- `URLSearchParams`

### JSON

```typescript
await apiRequest('POST', '/users', {
  data: { name: 'John Doe', role: 'admin' }
});
```

### FormData (File Upload)

```typescript
const form = new FormData();
form.append('avatar', fileBlob);

await apiRequest('POST', '/upload', {
  data: form
});
```

### Raw String

```typescript
await apiRequest('POST', '/raw-endpoint', {
  data: JSON.stringify({ raw: true })
});
```

---

## 2️⃣ `params` — Query Parameters

Automatically serializes & removes `null`/`undefined`.

```typescript
await apiRequest('GET', '/posts', {
  params: {
    page: 1,
    limit: 10,
    search: 'NextJS',
    archived: false
  }
});

// → /posts?page=1&limit=10&search=NextJS&archived=false
```

---

## 3️⃣ `priority` — Queue Weight

```typescript
await apiRequest('GET', '/critical-config', {
  priority: 'high'
});

await apiRequest('POST', '/telemetry', {
  priority: 'low'
});
```

---

## 4️⃣ `dedupeKey` — Manual Request Merging

```typescript
await apiRequest('GET', '/settings', {
  dedupeKey: 'global-settings'
});
```

If multiple components call this simultaneously → only one network call executes.

---

## 5️⃣ `pathParams` — Dynamic Route Interpolation

```typescript
await apiRequest('GET', '/users/:id', {
  pathParams: { id: 42 }
});

// → /users/42
```

---

## 6️⃣ `logTypes` — Dev Type Inspector

```typescript
await apiRequest('GET', '/api/user/profile', {
  logTypes: true
});
```

Only works when:

```
process.env.NODE_ENV === 'development'
```

---

## 7️⃣ `timeout` — Fixed or Adaptive

### Fixed

```typescript
await apiRequest('GET', '/slow-api', {
  timeout: 15000
});
```

### Adaptive

```typescript
await apiRequest('GET', '/unstable-api', {
  timeout: (attempt) => attempt * 5000
});
```

Attempt 1 → 5s  
Attempt 2 → 10s  
Attempt 3 → 15s  

---

## 8️⃣ `retries` — Override Retry Count

Default = 2 retries

```typescript
await apiRequest('GET', '/vital-resource', {
  retries: 5
});
```

---

## 9️⃣ `transform` — Post-Processing Hook

Modify data before returning to caller.

```typescript
await apiRequest<User>('GET', '/user/1', {
  transform: (data) => ({
    ...data,
    displayName: data.nickname || data.name
  })
});
```

---

## 🔟 `headers` — Custom Headers

```typescript
await apiRequest('GET', '/data', {
  headers: {
    'X-Project-ID': '99',
    'Accept-Encoding': 'gzip'
  }
});
```

Merged with:

- `Accept: application/json`
- Auth headers
- `Content-Type` (if needed)

---

## 1️⃣1️⃣ `cache` & `next` — Next.js 16 Integration

Fully compatible with extended `fetch()`.

```typescript
await apiRequest('GET', '/products', {
  cache: 'force-cache',
  next: {
    revalidate: 3600,
    tags: ['product-list', 'inventory']
  }
});
```

---

## 1️⃣2️⃣ `signal` — Manual Cancellation

```typescript
const controller = new AbortController();

const request = apiRequest('GET', '/huge-payload', {
  signal: controller.signal
});

controller.abort();
```

---

# 🏭 Typed Endpoint Factory

Create reusable, strongly-typed endpoints.

```typescript
import { createEndpoint } from '@/lib/safe-fetch';

const getUser = await createEndpoint<
  'GET',
  '/users/:id',
  null,
  { id: string; name: string }
>({
  method: 'GET',
  path: '/users/:id'
});

// Usage
const response = await getUser(null, {
  pathParams: { id: '42' }
});
```

---

# 🧾 Response Handling

SafeFetch returns a discriminated union.

```typescript
const res = await apiRequest<User>('GET', '/me');

if (apiRequest.isSuccess(res)) {
  console.log(res.data);     // typed
  console.log(res.status);   // number
  console.log(res.headers);  // Record<string,string>
} else {
  console.error(res.error.name);
  console.error(res.error.retryable);
}
```

---

# 📊 Runtime Monitoring

```typescript
const stats = apiRequest.utils.getStats();

console.log(stats.pool);
// { active: number, queued: number }

console.log(stats.rateLimit);
// { current: number }

console.log(stats.runtime);
// "bun" | "node"
```

---

# 🔐 Header Sanitization Utility

```typescript
const safeHeaders = apiRequest.utils.sanitizeHeaders({
  Authorization: 'Bearer secret',
  Cookie: 'session=abc'
});

// → values replaced with "[REDACTED]"
```

---

# 🌍 Environment Variables

| Variable | Description |
|-----------|-------------|
| `NEXT_PUBLIC_API_URL` | Base URL for relative endpoints |
| `API_URL` | Alternative base URL |
| `API_TOKEN` | Injected as `Authorization: Bearer <token>` |
| `AUTH_USERNAME` | Basic auth username |
| `AUTH_PASSWORD` | Basic auth password |
| `NODE_ENV` | Enables dev-only features |

---

# 🧠 Internal Flow

1. Resolve environment config  
2. Build URL (LRU cached)  
3. Generate dedupe key  
4. Enter priority concurrency pool  
5. Check rate limiter  
6. Execute fetch  
7. Retry if eligible  
8. Transform response  
9. Return discriminated result  

---

# 🏗 Guarantees

- No unhandled promise states  
- No data access without success check  
- No duplicated in-flight calls  
- No uncontrolled concurrency  
- No infinite retry loops  
- Memory-safe URL caching  
- TTL-based auth caching  

---

# 🛠 Ideal Use Cases

- Large Next.js App Router apps  
- Microservices gateways  
- Internal admin panels  
- Server actions  
- High-concurrency dashboards  
- Bun-powered APIs  

---

# 📄 License

BSD 3-Clause License  
© 2026 Bharathi4real
