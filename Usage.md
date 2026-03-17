# Real-World Usage Patterns

These examples demonstrate how SafeFetch fits into common application architectures such as **Next.js server components, React client components, service layers, and backend APIs**.

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

Benefits in server components:

* automatic Next.js caching support
* typed responses
* controlled retries

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
  return api.put(`/users/${id}`, {
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

export async function verifyPayment(sessionId: string) {
  const res = await api.get(`/payments/${sessionId}`);

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

---

# Using SafeFetch in Redux Toolkit

SafeFetch integrates well with Redux async logic.

```ts
// store/user-thunks.ts

import { createAsyncThunk } from "@reduxjs/toolkit";
import { api } from "@/lib/safe-fetch";

export const fetchUser = createAsyncThunk(
  "user/fetch",
  async (id: string) => {
    const res = await api.get(`/users/${id}`);

    if (!res.success) {
      throw new Error(res.error.message);
    }

    return res.data;
  }
);
```

---

# Handling Global API Errors

You can standardize error handling.

```ts
export async function safeCall<T>(promise: Promise<any>) {
  const res = await promise;

  if (!res.success) {
    console.error("API Error:", res.error);
    throw new Error(res.error.message);
  }

  return res.data as T;
}
```

Usage:

```ts
const user = await safeCall(api.get("/users/me"));
```

---

# Optimizing Concurrent Requests

SafeFetch handles concurrent requests efficiently using its internal pool.

```ts
const [users, posts, stats] = await Promise.all([
  api.get("/users"),
  api.get("/posts"),
  api.get("/stats")
]);
```

The internal connection pool ensures requests are executed within safe limits.

---

# Preloading Data in Layouts

Next.js layouts can preload shared data.

```ts
// app/layout.tsx

import { api } from "@/lib/safe-fetch";

export default async function RootLayout({ children }) {
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

This helps generate TypeScript interfaces quickly during development.

---
