# 🛡️ SafeFetch

> A TypeScript-first Fetch API wrapper with built-in retry logic, timeout handling, and enterprise-grade security features designed for modern server-side environments.

[![TypeScript](https://img.shields.io/badge/TypeScript-First-blue.svg)](https://www.typescriptlang.org/) [![Next.js](https://img.shields.io/badge/Next.js-Compatible-black.svg)](https://nextjs.org/) [![Security](https://img.shields.io/badge/Security-SSRF%20Protected-green.svg)](#security-features)

**Optimized Typed Fetch utility for Next.js 16**

SafeFetch is a production-ready, memory-optimized HTTP client with built-in retry logic, request pooling, rate limiting, and full Next.js 16 cache integration.

## Installation

Copy the `safefetch.ts` file into your project (e.g., `lib/safefetch.ts`).

## Quick Start

```typescript
import apiRequest from '@/lib/safefetch';

// Simple GET request
const response = await apiRequest('GET', '/api/users');

if (apiRequest.isSuccess(response)) {
  console.log(response.data);
} else {
  console.error(response.error.message);
}

// POST with data
const result = await apiRequest('POST', '/api/users', {
  data: { name: 'John Doe', email: 'john@example.com' }
});
```

## Core Features

- **TypeScript-first**: Full type safety with generic support
- **Smart Retries**: Automatic retry with exponential backoff for failed requests
- **Request Pooling**: Concurrent request management with priority queuing
- **Rate Limiting**: Built-in rate limiter (100 requests/60s by default)
- **Request Deduplication**: Prevents duplicate simultaneous requests
- **Next.js 16 Integration**: Full support for cache tags and revalidation
- **Timeout Management**: Configurable per-request or adaptive timeouts
- **Development Tools**: Automatic TypeScript type inference logging

## API Reference

### Main Function

```typescript
apiRequest<TResponse, TBody>(
  method: HttpMethod,
  endpoint: string,
  options?: RequestOptions<TBody, TResponse>
): Promise<ApiResponse<TResponse>>
```

#### Parameters

**method**: `'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH'`

**endpoint**: URL endpoint (absolute or relative)

**options**: Configuration object (optional)

### Request Options

```typescript
interface RequestOptions<TBody, TResponse> {
  // Request body (JSON, FormData, or string)
  data?: TBody;
  
  // Query parameters
  params?: Record<string, string | number | boolean | null | undefined>;
  
  // Number of retry attempts (default: 2)
  retries?: number;
  
  // Timeout in milliseconds or adaptive function (default: 60000)
  timeout?: number | ((attempt: number) => number);
  
  // Custom headers
  headers?: Record<string, string>;
  
  // Transform response data
  transform?(data: TResponse): TResponse;
  
  // Request priority in queue
  priority?: 'high' | 'normal' | 'low';
  
  // AbortSignal for manual cancellation
  signal?: AbortSignal;
  
  // Log inferred TypeScript types in development
  logTypes?: boolean;
  
  // Fetch cache option
  cache?: RequestCache;
  
  // Next.js 16 cache configuration
  next?: {
    revalidate?: number | false;
    tags?: string[];
  };
  
  // Deduplication key (empty string for auto-generated)
  dedupeKey?: string;
}
```

### Response Types

```typescript
type ApiResponse<T> =
  | {
      success: true;
      status: number;
      data: T;
      headers: Record<string, string>;
    }
  | {
      success: false;
      status: number;
      error: ApiError;
      data: null;
    };

interface ApiError {
  readonly name: string;
  readonly message: string;
  readonly status: number;
  readonly retryable?: boolean;
  readonly url?: string;
  readonly method?: string;
}
```

## Usage Examples

### Basic Requests

```typescript
// GET with query parameters
const users = await apiRequest('GET', '/api/users', {
  params: { page: 1, limit: 10 }
});

// POST with JSON data
const newUser = await apiRequest('POST', '/api/users', {
  data: { name: 'Jane', email: 'jane@example.com' }
});

// PUT to update
const updated = await apiRequest('PUT', '/api/users/123', {
  data: { name: 'Jane Smith' }
});

// DELETE
const deleted = await apiRequest('DELETE', '/api/users/123');
```

### Advanced Features

#### Custom Retry and Timeout

```typescript
const response = await apiRequest('GET', '/api/slow-endpoint', {
  retries: 5,
  timeout: 30000 // 30 seconds
});

// Adaptive timeout based on attempt number
const adaptive = await apiRequest('GET', '/api/endpoint', {
  timeout: (attempt) => 5000 * attempt // Increases each retry
});
```

#### Request Priority

```typescript
// High priority request (processed first)
const critical = await apiRequest('GET', '/api/critical', {
  priority: 'high'
});

// Low priority background task
const background = await apiRequest('GET', '/api/analytics', {
  priority: 'low'
});
```

#### Request Deduplication

```typescript
// Automatically deduplicate identical concurrent requests
const [result1, result2] = await Promise.all([
  apiRequest('GET', '/api/users', { dedupeKey: '' }),
  apiRequest('GET', '/api/users', { dedupeKey: '' })
]);
// Only one network request is made

// Custom deduplication key
const data = await apiRequest('GET', '/api/users', {
  params: { id: 123 },
  dedupeKey: 'user-123'
});
```

#### Response Transformation

```typescript
interface RawUser {
  id: number;
  full_name: string;
}

interface User {
  id: number;
  name: string;
}

const response = await apiRequest<RawUser>('GET', '/api/user/1', {
  transform: (data) => ({
    id: data.id,
    name: data.full_name
  } as User)
});
```

#### Manual Cancellation

```typescript
const controller = new AbortController();

const request = apiRequest('GET', '/api/large-file', {
  signal: controller.signal
});

// Cancel after 5 seconds
setTimeout(() => controller.abort(), 5000);

const result = await request;
if (!apiRequest.isSuccess(result)) {
  console.log(result.error.name); // 'AbortError'
}
```

### Next.js 16 Integration

#### Server-Side Caching

```typescript
// Cache for 1 hour
const users = await apiRequest('GET', '/api/users', {
  next: { revalidate: 3600 }
});

// Tag-based revalidation
const posts = await apiRequest('GET', '/api/posts', {
  next: { 
    tags: ['posts'],
    revalidate: 60 
  }
});

// Never cache
const realtime = await apiRequest('GET', '/api/realtime', {
  next: { revalidate: false }
});
```

#### Cache Revalidation

```typescript
import apiRequest from '@/lib/safefetch';

// Revalidate by tag (Server Actions/Route Handlers)
await apiRequest.utils.revalidateTag('posts');

// With expiration profile
await apiRequest.utils.revalidateTag('users', 'max');
await apiRequest.utils.revalidateTag('products', { expire: 3600 });

// Revalidate entire path
await apiRequest.utils.revalidatePath('/blog');
await apiRequest.utils.revalidatePath('/blog', 'layout');
```

### Type Safety and Development

#### Type Inference Logging

```typescript
// Enable in development to see TypeScript types
const response = await apiRequest('GET', '/api/complex-data', {
  logTypes: true
});

// Console output:
// 🔍 [SafeFetch] GET "/api/complex-data"
// type complex_dataResponse = {
//   id: number;
//   name: string;
//   items: {
//     title: string;
//     count: number;
//   }[];
// };
// ⏱️ 234ms
```

#### Type Guards

```typescript
const response = await apiRequest<User[]>('GET', '/api/users');

if (apiRequest.isSuccess(response)) {
  // TypeScript knows response.data is User[]
  response.data.forEach(user => console.log(user.name));
} else {
  // TypeScript knows response.error is ApiError
  console.error(response.error.message);
}
```

### Error Handling

```typescript
const response = await apiRequest('POST', '/api/users', {
  data: { email: 'invalid' }
});

if (apiRequest.isError(response)) {
  const { error } = response;
  
  console.log(error.name);      // 'HttpError', 'TimeoutError', etc.
  console.log(error.message);   // Human-readable error
  console.log(error.status);    // HTTP status code
  console.log(error.retryable); // Whether automatic retry occurred
  console.log(error.url);       // Full request URL
  console.log(error.method);    // HTTP method
}
```

## Utility Functions

### Get System Stats

```typescript
const stats = apiRequest.utils.getStats();

console.log(stats);
// {
//   pool: { active: 3, queued: 5, max: 10, pending: 2 },
//   rateLimit: { current: 45, limit: 100, windowMs: 60000 },
//   runtime: 'node' // or 'bun'
// }
```

### Create Timeout Signal

```typescript
// Create an AbortSignal that fires after 5 seconds
const timeoutSignal = apiRequest.utils.timeout(5000);

const response = await apiRequest('GET', '/api/endpoint', {
  signal: timeoutSignal
});
```

### Sanitize Headers for Logging

```typescript
const headers = {
  'Content-Type': 'application/json',
  'Authorization': 'Bearer secret-token',
  'X-API-Key': 'api-key-123'
};

const safe = apiRequest.utils.sanitizeHeaders(headers);
// {
//   'Content-Type': 'application/json',
//   'Authorization': '[REDACTED]',
//   'X-API-Key': '[REDACTED]'
// }
```

## Configuration

### Environment Variables

```bash
# API base URL
NEXT_PUBLIC_API_URL=https://api.example.com
# or
BASE_URL=https://api.example.com

# Basic Authentication
AUTH_USERNAME=your-username
AUTH_PASSWORD=your-password

# Bearer Token Authentication
API_TOKEN=your-api-token

# Environment
NODE_ENV=development
```

### Default Configuration

```typescript
const CFG = {
  API_URL: '',              // Base URL from env
  TIMEOUT: 60000,           // 60 seconds
  RETRIES: 2,               // 2 retry attempts
  MAX_CONCURRENT: 10,       // 10 concurrent requests (20 on Bun)
  LOG_LIMIT: 50000,         // Max chars for type inference logs
  RATE_MAX: 100,            // 100 requests
  RATE_WINDOW: 60000,       // per 60 seconds
};
```

## How It Works

### Retry Logic

- Automatic retry for network errors, timeouts, and specific HTTP status codes (408, 429, 500, 502, 503, 504)
- Only idempotent methods (GET, PUT, DELETE) retry on HTTP errors
- POST and PATCH only retry on network/timeout errors
- Exponential backoff with jitter: `min(1000ms, 100ms * 2^(attempt-1) + random(0-100ms))`

### Request Pooling

- Limits concurrent requests to prevent overwhelming servers
- Priority queue system (high > normal > low)
- Request deduplication to avoid redundant network calls
- Automatic queue processing as requests complete

### Rate Limiting

- Sliding window rate limiter
- Default: 100 requests per 60 seconds
- Automatically delays requests when limit reached
- Per-instance limiting (not shared across processes)

### Authentication

- Automatic header injection from environment variables
- Supports Basic Auth and Bearer tokens
- Headers cached for 5 minutes to avoid repeated processing
- Sensitive headers automatically redacted in logs

## Best Practices

### Use Type Parameters

```typescript
interface User {
  id: number;
  name: string;
  email: string;
}

const response = await apiRequest<User>('GET', '/api/user/1');
// response.data is strongly typed as User
```

### Handle Errors Gracefully

```typescript
const response = await apiRequest('GET', '/api/data');

if (!apiRequest.isSuccess(response)) {
  // Log error details
  console.error('Request failed:', response.error);
  
  // Show user-friendly message
  if (response.error.status === 404) {
    return 'Resource not found';
  }
  
  return 'An error occurred. Please try again.';
}

return response.data;
```

### Use Deduplication for Repeated Calls

```typescript
// In a React component that might re-render
const fetchUser = (id: number) =>
  apiRequest('GET', `/api/users/${id}`, {
    dedupeKey: `user-${id}`
  });
```

### Leverage Next.js Caching

```typescript
// Static data that rarely changes
const countries = await apiRequest('GET', '/api/countries', {
  next: { revalidate: 86400 } // Cache for 24 hours
});

// User-specific data
const profile = await apiRequest('GET', '/api/profile', {
  cache: 'no-store' // Never cache
});
```

### Monitor Performance in Development

```typescript
// Enable type logging to understand response shapes
const response = await apiRequest('GET', '/api/complex', {
  logTypes: true
});

// Check system stats
console.log(apiRequest.utils.getStats());
```

## License

BSD 3-Clause License © 2025 Bharathi4real

## Troubleshooting

### Requests Timing Out

Increase the timeout or use adaptive timeouts:

```typescript
const response = await apiRequest('GET', '/api/slow', {
  timeout: 120000, // 2 minutes
  retries: 3
});
```

### Rate Limit Errors

Adjust the rate limiter configuration or implement backoff in your application logic.

### Type Inference Not Working

Explicitly provide type parameters:

```typescript
const response = await apiRequest<MyType>('GET', '/api/data');
```

### Deduplication Not Working

Ensure you're using the same deduplication key for identical requests:

```typescript
const key = `user-${userId}`;
const r1 = await apiRequest('GET', '/api/user', { dedupeKey: key });
const r2 = await apiRequest('GET', '/api/user', { dedupeKey: key });
```
