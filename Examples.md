# Examples

This section demonstrates practical usage patterns for SafeFetch.

---

# Basic Request

```ts
import apiRequest from "@/lib/safe-fetch";

interface User {
  id: string;
  name: string;
}

const response = await apiRequest<User>("GET", "/users/1");

if (apiRequest.isSuccess(response)) {
  console.log(response.data.name);
} else {
  console.error(response.error.message);
}
```

---

# Using REST Helpers

```ts
import { api } from "@/lib/safe-fetch";

const res = await api.get<{ id: string; name: string }>("/users/1");

if (res.success) {
  console.log(res.data);
}
```

---

# Sending JSON Data

```ts
await api.post("/users", {
  data: {
    name: "Bharathi",
    role: "developer"
  }
});
```

---

# Uploading Files (FormData)

SafeFetch automatically detects `FormData`.

```ts
const form = new FormData();
form.append("avatar", file);

await api.post("/upload", {
  data: form
});
```

---

# Sending Raw Payloads

Binary or string payloads are also supported.

```ts
await api.post("/binary", {
  data: new ArrayBuffer(1024)
});
```

---

# Query Parameters

```ts
await api.get("/posts", {
  params: {
    page: 1,
    limit: 10,
    search: "nextjs"
  }
});
```

Resulting URL:

```
/posts?page=1&limit=10&search=nextjs
```

---

# Custom Headers

```ts
await api.get("/projects", {
  headers: {
    "X-Project-ID": "42"
  }
});
```

---

# Skip Authentication

Disable automatic auth headers.

Useful when calling external APIs.

```ts
await api.get("https://api.github.com/zen", {
  skipAuth: true
});
```

---

# Request Deduplication

Prevent duplicate concurrent calls.

```ts
await api.get("/settings", {
  dedupeKey: "global-settings"
});
```

Multiple calls using the same key will reuse the same promise.

---

# Priority Requests

Execute critical requests first.

```ts
await api.get("/config", {
  priority: "high"
});
```

Available priorities:

```
high
normal
low
```

---

# Retry Configuration

Override default retry attempts.

```ts
await api.get("/important-data", {
  retries: 5
});
```

---

# Adaptive Timeout

Timeout can be dynamic.

```ts
await api.get("/slow-endpoint", {
  timeout: attempt => attempt * 4000
});
```

Example behavior:

```
Attempt 1 → 4s
Attempt 2 → 8s
Attempt 3 → 12s
```

---

# Transform Response Data

Modify data before returning it.

```ts
await api.get("/user/1", {
  transform(data) {
    return {
      ...data,
      displayName: data.nickname ?? data.name
    };
  }
});
```

---

# Zod Schema Validation

Validate responses before returning them.

```ts
import { z } from "zod";

const UserSchema = z.object({
  id: z.string(),
  name: z.string()
});

const res = await api.get("/user/1", {
  schema: UserSchema
});

if (res.success) {
  console.log(res.data);
}
```

---

# Abort / Cancel Requests

```ts
const controller = new AbortController();

const request = api.get("/large-data", {
  signal: controller.signal
});

controller.abort();
```

---

# Next.js Fetch Cache

SafeFetch supports the extended Next.js `fetch` API.

```ts
await api.get("/products", {
  cache: "force-cache",
  next: {
    revalidate: 3600,
    tags: ["products"]
  }
});
```

---

# Development Type Logging

Logs inferred response types in development mode.

```ts
await api.get("/user/profile", {
  logTypes: true
});
```

Example output:

```
🔍 [SafeFetch] GET /user/profile (38ms)

Type:
{
  id: string
  name: string
  email: string
}
```

---

# Custom SafeFetch Instance

Create a separate API client.

```ts
import { createSafeFetch } from "@/lib/safe-fetch";

const { api } = createSafeFetch({
  baseUrl: "https://api.example.com",
  retries: 3,
  timeout: 30000,
  maxConcurrent: 15
});

await api.get("/users");
```

---

# Restrict Allowed Hosts (SSRF Protection)

```ts
const { api } = createSafeFetch({
  allowedHosts: ["api.mycompany.com"]
});
```

Requests to other hosts will throw an error.

---

# Inspect Runtime Statistics

```ts
const stats = apiRequest.utils.getStats();

console.log(stats);
```

Example output:

```ts
{
  pool: { active: 1, queued: 2 },
  rateLimit: { current: 3 },
  runtime: "node"
}
```

---

# Sanitize Headers Before Logging

```ts
const headers = {
  Authorization: "Bearer secret",
  Cookie: "session=abc"
};

const safe = apiRequest.utils.sanitizeHeaders(headers);

console.log(safe);
```

Output:

```
{
  Authorization: "[REDACTED]",
  Cookie: "[REDACTED]"
}
```

---

# Handling Errors

SafeFetch returns a safe union response.

```ts
const res = await api.get("/users");

if (apiRequest.isError(res)) {
  console.error(res.error.name);
  console.error(res.error.message);
}
```

Error object:

```
{
  name: string
  message: string
  status: number
  retryable?: boolean
  url?: string
  method?: string
}
```

---

# Manual Auth Cache Invalidation

```ts
import { invalidateAuthCache } from "@/lib/safe-fetch";

invalidateAuthCache();
```

Useful after refreshing credentials.
