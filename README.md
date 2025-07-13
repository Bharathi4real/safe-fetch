# 🛡️ SafeFetch

> A TypeScript-first Fetch API wrapper with built-in retry logic, timeout handling, and enterprise-grade security features designed for modern server-side environments.

[![TypeScript](https://img.shields.io/badge/TypeScript-First-blue.svg)](https://www.typescriptlang.org/) [![Next.js](https://img.shields.io/badge/Next.js-Compatible-black.svg)](https://nextjs.org/) [![Security](https://img.shields.io/badge/Security-SSRF%20Protected-green.svg)](#security-features)

## 🚀 Quick Start

```typescript
import apiRequest from './lib/api';

interface User {
  id: number;
  name: string;
  email: string;
}

// Simple GET request with full type safety
const result = await apiRequest<User[]>('GET', '/users');
if (result.success) {
  console.log(result.data); // Fully typed as User[]
} else {
  console.error(result.error.message);
}
```

## ✨ Key Features

### 🔄 **Smart Retry Logic**
Automatic retries for idempotent HTTP methods (GET, PUT, DELETE, HEAD, OPTIONS) with exponential backoff on transient errors.

### ⏱️ **Timeout Protection**
Configurable request timeouts using `AbortController` with sensible defaults and limits.

### 🔒 **Enterprise Security**
- **SSRF Protection**: Built-in validation against Server-Side Request Forgery attacks
- **Size Limits**: Configurable request/response size limits to prevent abuse
- **Host Allowlisting**: Granular control over allowed destinations

### 🧾 **TypeScript Excellence**
- Full type inference and safety
- Excellent IntelliSense support
- Development-time type logging
- JSDoc documentation

### 🧠 **Next.js Optimized**
Seamless integration with App Router, including `revalidate`, `cache`, and `tags` for ISR and caching strategies.

### 🔐 **Flexible Authentication**
Environment-based Basic Auth or Bearer token authentication with secure defaults.

## 📦 Installation

No npm package needed! Simply copy the SafeFetch TypeScript file into your project:

```
# Copy to your project

./lib/safe-fetch.ts or ./utils/safe-fetch.ts
```

## ⚙️ Configuration

### Environment Variables

Create a `.env.local` file in your project root:

```bash
# API Configuration
BASE_URL=https://api.your-domain.com

# Authentication (Choose one)
AUTH_USERNAME=your_username    # Basic Auth
AUTH_PASSWORD=your_password    # Basic Auth
# OR
AUTH_TOKEN=your_bearer_token   # Bearer Token
# OR
API_TOKEN=your_api_token       # Alternative Bearer Token

# Security (Optional)
ALLOWED_HOSTS=api.example.com,cdn.example.com
```

## 📖 Usage Guide

### Basic Requests

```typescript
import apiRequest from './lib/api';

// GET request
const users = await apiRequest<User[]>('GET', '/users');

// POST with data
const newUser = await apiRequest<User, CreateUserData>('POST', '/users', {
  data: {
    name: 'John Doe',
    email: 'john@example.com'
  }
});

// PUT with query parameters
const updated = await apiRequest<User>('PUT', '/users/123', {
  params: { notify: true },
  data: { name: 'Jane Doe' }
});

// DELETE
const deleted = await apiRequest('DELETE', '/users/123');
```

### Advanced Configuration

```typescript
const result = await apiRequest<Product[]>('GET', '/products', {
  // Query parameters
  params: {
    category: 'electronics',
    limit: 10,
    sort: 'price_desc'
  },

  // Retry configuration
  retries: 3,
  timeout: 15000,

  // Next.js caching
  cache: 'force-cache',
  revalidate: 3600,
  tags: ['products', 'catalog'],

  // Security
  allowedHosts: ['cdn.example.com'],
  maxResponseSize: 2 * 1024 * 1024, // 2MB
  maxRequestBodySize: 1024 * 1024,   // 1MB

  // Custom headers
  headers: {
    'X-API-Version': '2.0',
    'Accept-Language': 'en-US'
  }
});
```

### Response Transformation

Transform API responses to match your application's data structure:

```typescript
interface ApiProduct {
  product_id: string;
  product_name: string;
  item_price: number;
  created_at: string;
}

interface AppProduct {
  id: string;
  name: string;
  price: number;
  createdAt: Date;
}

const result = await apiRequest<ApiProduct, undefined, AppProduct>(
  'GET',
  '/products/123',
  {
    transform: (data) => ({
      id: data.product_id,
      name: data.product_name,
      price: data.item_price,
      createdAt: new Date(data.created_at)
    }),
    logTypes: true // Development-only type logging
  }
);
```

### File Upload

```typescript
async function uploadFile(file: File) {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('category', 'documents');

  const result = await apiRequest<{ url: string; id: string }>(
    'POST',
    '/upload',
    {
      data: formData,
      timeout: 60000, // 60 seconds for large files
      maxRequestBodySize: 10 * 1024 * 1024 // 10MB limit
    }
  );

  if (result.success) {
    return { url: result.data.url, id: result.data.id };
  }

  throw new Error(`Upload failed: ${result.error.message}`);
}
```

### Error Handling

```typescript
const result = await apiRequest<User[]>('GET', '/users');

// Method 1: Direct checking
if (result.success) {
  console.log('Users:', result.data);
} else {
  console.error('Error:', result.error.message);
  console.error('Status:', result.status);
}

// Method 2: Type guards
if (apiRequest.isSuccess(result)) {
  // result.data is properly typed
  result.data.forEach(user => console.log(user.name));
} else {
  // result.error is properly typed
  console.error(result.error.message);
}

// Method 3: Custom error handling
const users = await apiRequest<User[]>('GET', '/users', {
  onError: (error, attempt) => {
    console.log(`Attempt ${attempt + 1} failed:`, error.message);
  },
  shouldRetry: (error, attempt) => {
    return attempt < 2 && error.status >= 500;
  }
});
```

## 🧠 Next.js Integration

### Server Components

```typescript
// app/posts/page.tsx
import apiRequest from '@/lib/api';

interface Post {
  id: number;
  title: string;
  content: string;
  publishedAt: string;
}

export default async function PostsPage() {
  const postsResult = await apiRequest<Post[]>('GET', '/posts', {
    revalidate: 300, // Revalidate every 5 minutes
    tags: ['posts'],
    cache: 'force-cache'
  });

  if (!postsResult.success) {
    return (
      <div className="error">
        <h1>Error Loading Posts</h1>
        <p>{postsResult.error.message}</p>
      </div>
    );
  }

  return (
    <div>
      <h1>Blog Posts</h1>
      <div className="posts">
        {postsResult.data.map((post) => (
          <article key={post.id}>
            <h2>{post.title}</h2>
            <p>{post.content.substring(0, 150)}...</p>
            <time>{new Date(post.publishedAt).toLocaleDateString()}</time>
          </article>
        ))}
      </div>
    </div>
  );
}
```

### Server Actions

```typescript
// app/actions.ts
'use server';

import apiRequest from '@/lib/api';
import { revalidateTag } from 'next/cache';
import { redirect } from 'next/navigation';

interface CreatePostData {
  title: string;
  content: string;
}

export async function createPost(formData: FormData) {
  const title = formData.get('title')?.toString();
  const content = formData.get('content')?.toString();

  if (!title || !content) {
    return { success: false, error: 'Title and content are required' };
  }

  const result = await apiRequest<Post, CreatePostData>('POST', '/posts', {
    data: { title, content }
  });

  if (result.success) {
    revalidateTag('posts');
    redirect('/posts');
  }

  return {
    success: false,
    error: result.error.message
  };
}
```

### Client Components

```typescript
// components/PostForm.tsx
'use client';

import { useTransition } from 'react';
import { createPost } from '@/app/actions';

export function PostForm() {
  const [isPending, startTransition] = useTransition();

  const handleSubmit = (formData: FormData) => {
    startTransition(async () => {
      const result = await createPost(formData);
      if (!result.success) {
        alert(`Error: ${result.error}`);
      }
    });
  };

  return (
    <form action={handleSubmit}>
      <div>
        <label htmlFor="title">Title</label>
        <input
          type="text"
          id="title"
          name="title"
          required
          disabled={isPending}
        />
      </div>
      <div>
        <label htmlFor="content">Content</label>
        <textarea
          id="content"
          name="content"
          required
          disabled={isPending}
        />
      </div>
      <button type="submit" disabled={isPending}>
        {isPending ? 'Creating...' : 'Create Post'}
      </button>
    </form>
  );
}
```

## 🔧 API Reference

### `apiRequest<TResponse, TBody, TTransformedResponse>`

The main function for making HTTP requests.

#### Type Parameters

- `TResponse`: Expected raw response type from API
- `TBody`: Request body type (extends `RequestBody`)
- `TTransformedResponse`: Response type after transformation (defaults to `TResponse`)

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `method` | `HttpMethod` | HTTP method (`GET`, `POST`, `PUT`, `DELETE`, etc.) |
| `endpoint` | `string` | API endpoint path or full URL |
| `options?` | `RequestOptions` | Configuration object (see interface below) |

#### `RequestOptions` Properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `data` | `TBody` | `undefined` | Request body - auto-serialized to JSON unless FormData/Blob/ArrayBuffer |
| `params` | `QueryParams` | `undefined` | Query parameters appended to URL |
| `retries` | `number` | `1` | Max retry attempts for idempotent methods |
| `timeout` | `number` | `30000` | Request timeout in milliseconds |
| `cache` | `RequestCache` | `'default'` | Fetch cache strategy |
| `revalidate` | `number \| false` | `undefined` | Next.js ISR revalidation time in seconds |
| `tags` | `string[]` | `undefined` | Next.js cache tags for on-demand revalidation |
| `headers` | `Record<string, string>` | `{}` | Custom headers merged with defaults |
| `logTypes` | `boolean` | `false` | Log inferred TypeScript types (dev only) |
| `transform` | `<T>(data: T) => TTransformedResponse` | `undefined` | Transform response data before returning |
| `onError` | `(error: ApiError, attempt: number) => void` | `undefined` | Custom error handler |
| `shouldRetry` | `(error: ApiError, attempt: number) => boolean` | `undefined` | Custom retry condition |
| `allowedHosts` | `string[]` | `undefined` | Allowed hosts for SSRF protection (merged with ALLOWED_HOSTS env var) |
| `maxResponseSize` | `number` | `10MB` | Maximum response size in bytes |
| `maxRequestBodySize` | `number` | `10MB` | Maximum request body size in bytes |

#### `RequestOptions` Interface

```typescript
interface RequestOptions<
  TBody extends RequestBody = RequestBody,
  TTransformedResponse = unknown,
> {
  /** Request body - auto-serialized to JSON unless FormData/Blob/ArrayBuffer */
  data?: TBody;
  /** Query parameters appended to URL */
  params?: QueryParams;
  /** Max retry attempts for idempotent methods (default: 1) */
  retries?: number;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Fetch cache strategy (default: 'default') */
  cache?: RequestCache;
  /** Next.js ISR revalidation time in seconds */
  revalidate?: number | false;
  /** Next.js cache tags for on-demand revalidation */
  tags?: string[];
  /** Custom headers merged with defaults */
  headers?: Record<string, string>;
  /** Log inferred TypeScript types (dev only) */
  logTypes?: boolean;
  /** Transform response data before returning */
  transform?<T>(data: T): TTransformedResponse; // Allows type transformation
  /** Custom error handler */
  onError?: (error: ApiError, attempt: number) => void;
  /** Custom retry condition */
  shouldRetry?: (error: ApiError, attempt: number) => boolean;
  /** Allowed hosts for SSRF protection (merged with ALLOWED_HOSTS env var) */
  allowedHosts?: string[];
  /** Maximum response size in bytes (default: 10MB) */
  maxResponseSize?: number;
  /** Maximum request body size in bytes (default: 10MB) */
  maxRequestBodySize?: number;
}
```

#### Return Type

```typescript
type ApiResponse<T = unknown> =
  | { success: true; status: number; data: T; headers: Headers }
  | { success: false; status: number; error: ApiError; data: null };
```

#### `ApiError` Interface

```typescript
interface ApiError {
  readonly name: string;        // Error type: 'HttpError', 'TimeoutError', etc.
  readonly message: string;     // User-friendly error message
  readonly status: number;      // HTTP status code
  readonly attempt?: number;    // Retry attempt number (0-indexed)
  readonly data?: unknown;      // Raw error response data
  readonly devMessage?: string; // Developer-focused message (dev only)
}
```

### Type Guards

```typescript
// Type-safe success checking
if (apiRequest.isSuccess(result)) {
  // result.data is properly typed
  console.log(result.data);
}

// Type-safe error checking
if (apiRequest.isError(result)) {
  // result.error is properly typed
  console.error(result.error.message);
}
```

## 🛡️ Security Features

### SSRF Protection

SafeFetch includes built-in protection against Server-Side Request Forgery attacks:

```typescript
// Blocked by default
const blocked = await apiRequest('GET', 'http://localhost:3000/admin');
const blocked2 = await apiRequest('GET', 'http://169.254.169.254/metadata');

// Allow specific hosts
const allowed = await apiRequest('GET', 'https://api.partner.com/data', {
  allowedHosts: ['api.partner.com']
});
```

### Size Limits

Prevent resource exhaustion with configurable size limits:

```typescript
const result = await apiRequest('POST', '/upload', {
  data: largeFile,
  maxRequestBodySize: 5 * 1024 * 1024,  // 5MB request limit
  maxResponseSize: 1024 * 1024           // 1MB response limit
});
```

### Environment Variables

Secure credential management:

```typescript
// Automatically uses environment variables
// No hardcoded credentials in source code
const result = await apiRequest('GET', '/protected-endpoint');
```

## 🎯 Best Practices

### 1. Type Safety

```typescript
// ✅ Good: Explicit typing
interface User {
  id: number;
  email: string;
}

const users = await apiRequest<User[]>('GET', '/users');

// ❌ Avoid: Implicit any
const users = await apiRequest('GET', '/users');
```

### 2. Error Handling

```typescript
// ✅ Good: Comprehensive error handling
const result = await apiRequest<User[]>('GET', '/users');

if (result.success) {
  return result.data;
} else {
  // Log for debugging
  console.error('API Error:', result.error);

  // Handle specific errors
  if (result.status === 404) {
    return [];
  }

  // Re-throw for upstream handling
  throw new Error(`Failed to fetch users: ${result.error.message}`);
}
```

### 3. Next.js Caching

```typescript
// ✅ Good: Strategic caching
const posts = await apiRequest<Post[]>('GET', '/posts', {
  revalidate: 300,      // 5 minutes
  tags: ['posts'],      // For on-demand revalidation
  cache: 'force-cache'  // Aggressive caching
});

// ✅ Good: Dynamic data
const user = await apiRequest<User>('GET', '/user/profile', {
  cache: 'no-store'     // Always fresh
});
```

### 4. Security

```typescript
// ✅ Good: Explicit allowed hosts
const external = await apiRequest('GET', 'https://partner-api.com/data', {
  allowedHosts: ['partner-api.com'],
  maxResponseSize: 1024 * 1024 // 1MB limit
});

// ✅ Good: Size limits for uploads
const upload = await apiRequest('POST', '/upload', {
  data: formData,
  maxRequestBodySize: 10 * 1024 * 1024, // 10MB
  timeout: 60000 // 60 seconds
});
```

## 🔍 Troubleshooting

### Common Issues

#### 1. TypeScript Errors

```typescript
// Error: Type 'unknown' is not assignable to type 'User[]'
// Solution: Provide explicit type parameter
const users = await apiRequest<User[]>('GET', '/users');
```

#### 2. SSRF Blocks

```typescript
// Error: Request blocked by SSRF protection
// Solution: Add to allowed hosts
const result = await apiRequest('GET', 'https://external-api.com', {
  allowedHosts: ['external-api.com']
});
```

#### 3. Timeout Issues

```typescript
// Error: Request timeout
// Solution: Increase timeout for slow endpoints
const result = await apiRequest('GET', '/slow-endpoint', {
  timeout: 60000 // 60 seconds
});
```

### Debug Mode

Enable detailed logging in development:

```typescript
const result = await apiRequest<User[]>('GET', '/users', {
  logTypes: true,
  onError: (error, attempt) => {
    console.log(`Attempt ${attempt + 1}:`, error.devMessage);
  }
});
```

## 📊 Performance Tips

### 1. Caching Strategy

```typescript
// Static data - aggressive caching
const config = await apiRequest('GET', '/config', {
  revalidate: 3600 // 1 hour
});

// Dynamic data - minimal caching
const notifications = await apiRequest('GET', '/notifications', {
  cache: 'no-store'
});

// User-specific data - short cache
const profile = await apiRequest('GET', '/profile', {
  revalidate: 60 // 1 minute
});
```

### 2. Request Optimization

```typescript
// Batch requests when possible
const [users, posts, comments] = await Promise.all([
  apiRequest<User[]>('GET', '/users'),
  apiRequest<Post[]>('GET', '/posts'),
  apiRequest<Comment[]>('GET', '/comments')
]);

// Use pagination for large datasets
const posts = await apiRequest<Post[]>('GET', '/posts', {
  params: {
    page: 1,
    limit: 20,
    sort: 'created_at:desc'
  }
});
```

## 🌍 Compatibility

### Environment Support

- **Node.js**: 18.0.0+
- **Next.js**: 13.0.0+ (App Router)
- **React**: 18.0.0+
- **TypeScript**: 4.5.0+

### Browser Support

- **Chrome**: 90+
- **Firefox**: 90+
- **Safari**: 14+
- **Edge**: 90+

### Runtime Requirements

- Fetch API support
- AbortController support
- Promise support
- URL constructor support

## 📄 License

This project is licensed under the **BSD 3-Clause License**.

**Attribution Required**: Attribution to Bharathi4real is required for all uses.

---

**Made with ❤️ by [Bharathi4real](https://github.com/bharathi4real)**

**⭐ Star this project if you find it useful!**
