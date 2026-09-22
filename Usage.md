# Real-World Usage Patterns

These examples demonstrate how SafeFetch fits into common application architectures such as **Next.js server components, Edge Middleware, React client components, service layers, and backend APIs**.

> **Edge Runtime note:** SafeFetch has no Node-only static imports (no `node:crypto`, no `node:buffer`), so every pattern below — including the server component and route handler examples — also works unmodified in `middleware.ts` and in Route Handlers with `export const runtime = "edge"`. See [Using SafeFetch in Edge Middleware](#using-safefetch-in-edge-middleware).

---

# Using SafeFetch in a Next.js Server Component

SafeFetch works naturally inside **React Server Components** because it is built on top of the native `fetch` API.

```ts
// app/dashboard/page.tsx

import { api } from "@/lib/safe-fetch";

interface Stats {
  users: number;
  revenue: number;
}

export default async function DashboardPage() {
  const res = await api.get<Stats>("/stats", {
    next: { revalidate: 60 }
  });

  if (!res.success) {
    throw new Error(res.error.message);
  }

  return (
    <div>
      <h1>Dashboard</h1>
      <p>Users: {res.data.users}</p>
      <p>Revenue: {res.data.revenue}</p>
    </div>
  );
}
```

> Since Next.js 15, `fetch` is **uncached by default** — you now opt in to caching explicitly rather than opting out. Pass `next: { revalidate }` (as above) or `cache: "force-cache"` when you want a cached response; omit both for always-fresh data.

Benefits in server components:

* explicit, typed Next.js caching support (`next.revalidate` / `next.tags`, `cache`)
* typed responses
* controlled retries

---

# Using SafeFetch in Edge Middleware

Because SafeFetch avoids Node-only APIs, it runs as-is in Edge Middleware and edge Route Handlers — no separate "edge build" needed.

```ts
// middleware.ts
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { api } from "@/lib/safe-fetch";

interface FeatureFlags {
  maintenanceMode: boolean;
}

export async function middleware(req: NextRequest) {
  const res = await api.get<FeatureFlags>("/feature-flags", {
    // Middleware runs on every request — keep it fast and non-blocking.
    timeout: 2000,
    retries: 0
  });

  if (res.success && res.data.maintenanceMode) {
    return NextResponse.redirect(new URL("/maintenance", req.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: "/((?!maintenance|_next/static|_next/image|favicon.ico).*)"
};
```

```ts
// app/api/edge-example/route.ts
import { api } from "@/lib/safe-fetch";

export const runtime = "edge";

export async function GET() {
  const res = await api.get("/ping");
  return Response.json(res);
}
```

---

# Using SafeFetch in a React Client Component

Client-side fetching works exactly the same.

```ts
"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/safe-fetch";

interface User {
  id: string;
  name: string;
}

export default function Profile() {
  const [user, setUser] = useState<User | null>(null);

  useEffect(() => {
    async function load() {
      const res = await api.get<User>("/user/me");

      if (res.success) {
        setUser(res.data);
      }
    }

    load();
  }, []);

  if (!user) return <p>Loading...</p>;

  return <div>{user.name}</div>;
}
```

Typical client use cases:

* profile data
* dashboard widgets
* user settings

---

# Service Layer Pattern

In larger applications it is best to centralize API logic in a **service layer**.

```ts
// services/user-service.ts

import { api } from "@/lib/safe-fetch";

export interface User {
  id: string;
  name: string;
  email: string;
}

export async function getUser(id: string) {
  return api.get<User>(`/users/${id}`);
}

export async function updateUser(id: string, data: Partial<User>) {
  return api.put<User>(`/users/${id}`, {
    data
  });
}
```

Usage:

```ts
const res = await getUser("123");

if (res.success) {
  console.log(res.data);
}
```

Advantages:

* central API contracts
* reusable logic
* cleaner components

---

# Backend API Usage (Node.js)

SafeFetch can also be used inside backend services.

```ts
// services/payment-service.ts

import { api } from "@/lib/safe-fetch";

interface Payment {
  id: string;
  status: "pending" | "paid" | "failed";
}

export async function verifyPayment(sessionId: string) {
  const res = await api.get<Payment>(`/payments/${sessionId}`);

  if (!res.success) {
    throw new Error(res.error.message);
  }

  return res.data;
}
```

Example route:

```ts
import { verifyPayment } from "@/services/payment-service";

export async function POST(req: Request) {
  const { sessionId } = await req.json();

  const payment = await verifyPayment(sessionId);

  return Response.json(payment);
}
```

---

# Multiple API Clients

Applications often interact with multiple services.

Create dedicated SafeFetch instances.

```ts
// lib/apis.ts

import { createSafeFetch } from "@/lib/safe-fetch";

export const coreApi = createSafeFetch({
  baseUrl: "https://api.myapp.com"
});

export const analyticsApi = createSafeFetch({
  baseUrl: "https://analytics.myapp.com",
  retries: 1,
  timeout: 15000
});
```

Usage:

```ts
const res = await coreApi.api.get("/users");

const analytics = await analyticsApi.api.post("/events", {
  data: { type: "page_view" }
});
```

Each instance gets its own connection pool, rate limiter, URL cache, and auth-header cache — they never share state, so `analyticsApi`'s stricter `retries`/`timeout` can't affect `coreApi` calls.

---

# Using SafeFetch in Redux Toolkit

SafeFetch integrates well with Redux async logic.

```ts
// store/user-thunks.ts

import { createAsyncThunk } from "@reduxjs/toolkit";
import { api } from "@/lib/safe-fetch";
import type { User } from "@/services/user-service";

export const fetchUser = createAsyncThunk(
  "user/fetch",
  async (id: string) => {
    const res = await api.get<User>(`/users/${id}`);

    if (!res.success) {
      throw new Error(res.error.message);
    }

    return res.data;
  }
);
```

---

# Handling Global API Errors

You can standardize error handling with a small typed helper.

```ts
import type { ApiResponse } from "@/lib/safe-fetch";

export async function safeCall<T>(promise: Promise<ApiResponse<T>>): Promise<T> {
  const res = await promise;

  if (!res.success) {
    console.error("API Error:", res.error);
    throw new Error(res.error.message);
  }

  return res.data;
}
```

Usage:

```ts
const user = await safeCall(api.get<User>("/users/me"));
```

Typing the promise as `ApiResponse<T>` (instead of `any`) keeps `res.data` — and the returned value — fully typed end to end.

---

# Optimizing Concurrent Requests

SafeFetch handles concurrent requests efficiently using its internal priority pool and rate limiter.

```ts
const [users, posts, stats] = await Promise.all([
  api.get("/users"),
  api.get("/posts"),
  api.get("/stats", { priority: "high" })
]);
```

`priority` only affects queueing once the pool's `maxConcurrent` limit is hit — a `"high"`-priority call jumps ahead of queued `"normal"`/`"low"` ones, it doesn't bypass the rate limiter itself.

---

# Preloading Data in Layouts

Next.js layouts can preload shared data.

```tsx
// app/layout.tsx

import { api } from "@/lib/safe-fetch";

export default async function RootLayout({
  children
}: {
  children: React.ReactNode;
}) {
  const res = await api.get("/app-config", {
    priority: "high"
  });

  return (
    <html>
      <body>{children}</body>
    </html>
  );
}
```

---

# Combining Zod Validation with Transform

```ts
import { z } from "zod";

const ProductSchema = z.object({
  id: z.string(),
  price: z.number()
});

const res = await api.get("/product/1", {
  schema: ProductSchema,
  transform(data) {
    return {
      ...data,
      formattedPrice: `$${data.price}`
    };
  }
});
```

`transform` runs **before** `schema` validation, so validate against the shape your `transform` returns, not the raw response shape.

---

# Logging Types During Development

```ts
await api.get("/users", {
  logTypes: true
});
```

Console output example:

```
🔍 [SafeFetch] GET /users (41ms)

Type:
{
  id: string
  name: string
  email: string
}
```

This helps generate TypeScript interfaces quickly during development. `logTypes` is a no-op in production builds (`NODE_ENV === "production"`), so it's safe to leave on `true` in shared service-layer code without a manual `if (dev)` guard.
