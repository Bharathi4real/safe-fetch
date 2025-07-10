# SafeFetch Usage Guide

A comprehensive guide for using SafeFetch - a typed fetch utility with retry, timeout, and Next.js support.

## Table of Contents

1. [Installation & Setup](#installation--setup)
2. [Basic Usage](#basic-usage)
3. [Configuration Options](#configuration-options)
4. [Request Types](#request-types)
5. [Response Handling](#response-handling)
6. [Error Handling](#error-handling)
7. [Advanced Features](#advanced-features)
8. [Next.js Integration](#nextjs-integration)
9. [Security Features](#security-features)
10. [Environment Configuration](#environment-configuration)
11. [Best Practices](#best-practices)
12. [Troubleshooting](#troubleshooting)
13. [Browser Compatibility](#browser-compatibility)

## Installation & Setup

Copy the SafeFetch code into your project (e.g., `lib/api.ts` or `utils/safe-fetch.ts`).

Set optional environment variables:

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

## Basic Usage

### Simple GET Request

```typescript
// Basic GET request
const response = await apiRequest('GET', '/users');

if (apiRequest.isSuccess(response)) {
  console.log(response.data); // Response data
  console.log(response.status); // HTTP status code
  console.log(response.headers); // Response headers
} else {
  console.error(response.error); // Error details
}
```

### POST Request with Data

```typescript
interface CreateUserData {
  name: string;
  email: string;
}

const userData: CreateUserData = {
  name: 'John Doe',
  email: 'john@example.com'
};

const response = await apiRequest<any, CreateUserData>('POST', '/users', {
  data: userData
});

if (apiRequest.isSuccess(response)) {
  console.log('User created:', response.data);
}
```

## Configuration Options

### Complete Configuration Example

```typescript
interface User {
  id: string;
  name: string;
  email: string;
}

interface CreateUserResponse {
  success: boolean;
  user: User;
  message: string;
}

interface TransformedResponse {
  userId: string;
  userName: string;
  timestamp: number;
}

const response = await apiRequest<CreateUserResponse, CreateUserData, TransformedResponse>(
  'POST',
  '/users',
  {
    // Request body
    data: { name: 'John', email: 'john@example.com' },

    // Query parameters
    params: {
      source: 'web',
      version: 'v1',
      debug: true
    },

    // Retry configuration
    retries: 3,
    timeout: 10000, // 10 seconds

    // Caching
    cache: 'force-cache',
    revalidate: 3600, // 1 hour
    tags: ['users', 'create'],

    // Custom headers
    headers: {
      'X-Custom-Header': 'my-value',
      'X-Request-ID': '12345'
    },

    // Security limits
    maxResponseSize: 5 * 1024 * 1024, // 5MB
    maxRequestBodySize: 2 * 1024 * 1024, // 2MB
    allowedHosts: ['api.example.com', 'cdn.example.com'],

    // Response transformation
    transform: (data) => ({
      userId: data.user.id,
      userName: data.user.name,
      timestamp: Date.now()
    }),

    // Error handling
    onError: (error, attempt) => {
      console.warn(`Attempt ${attempt + 1} failed:`, error.message);
    },

    // Custom retry logic
    shouldRetry: (error, attempt) => {
      return error.status === 503 && attempt < 2;
    },

    // Development helpers
    logTypes: true // Logs inferred TypeScript types
  }
);
```

## Request Types

### GET Requests

```typescript
// Simple GET
const users = await apiRequest<User[]>('GET', '/users');

// GET with query parameters
const filteredUsers = await apiRequest<User[]>('GET', '/users', {
  params: {
    page: 1,
    limit: 10,
    active: true,
    status: null // Null/undefined values are ignored
  }
});

// GET with custom headers
const userDetails = await apiRequest<User>('GET', '/users/123', {
  headers: {
    'Accept': 'application/json',
    'X-API-Version': '2.0'
  }
});
```

### POST Requests

```typescript
// JSON POST
const newUser = await apiRequest<User, CreateUserData>('POST', '/users', {
  data: {
    name: 'Jane Doe',
    email: 'jane@example.com'
  }
});

// Form data POST
const formData = new FormData();
formData.append('name', 'John');
formData.append('avatar', fileInput.files[0]);

const uploadResponse = await apiRequest<UploadResponse>('POST', '/upload', {
  data: formData
});

// Raw string POST
const textResponse = await apiRequest<string>('POST', '/webhook', {
  data: JSON.stringify({ event: 'user.created' }),
  headers: {
    'Content-Type': 'application/json'
  }
});
```

### PUT/PATCH Requests

```typescript
// Update user
const updatedUser = await apiRequest<User, Partial<User>>('PUT', '/users/123', {
  data: {
    name: 'Updated Name',
    email: 'updated@example.com'
  }
});

// Partial update
const patchedUser = await apiRequest<User, Partial<User>>('PATCH', '/users/123', {
  data: {
    name: 'New Name Only'
  }
});
```

### DELETE Requests

```typescript
// Delete user
const deleteResponse = await apiRequest<{ success: boolean }>('DELETE', '/users/123');

// Delete with confirmation
const deleteWithConfirm = await apiRequest<DeleteResponse>('DELETE', '/users/123', {
  params: {
    confirm: true
  }
});
```

## Response Handling

### Type Guards

```typescript
const response = await apiRequest<User[]>('GET', '/users');

// Success check
if (apiRequest.isSuccess(response)) {
  // TypeScript knows response.data is User[]
  response.data.forEach(user => console.log(user.name));
  console.log(`Status: ${response.status}`);
  console.log(`Headers:`, response.headers);
}

// Error check
if (apiRequest.isError(response)) {
  // TypeScript knows response.error is ApiError
  console.error(`Error: ${response.error.message}`);
  console.error(`Status: ${response.error.status}`);
  console.error(`Attempt: ${response.error.attempt}`);
}
```

### Response Transformation

```typescript
interface ApiResponse {
  data: User[];
  meta: {
    total: number;
    page: number;
  };
}

interface TransformedResponse {
  users: User[];
  totalCount: number;
  currentPage: number;
}

const response = await apiRequest<ApiResponse, any, TransformedResponse>('GET', '/users', {
  transform: (data) => ({
    users: data.data,
    totalCount: data.meta.total,
    currentPage: data.meta.page
  })
});

if (apiRequest.isSuccess(response)) {
  // response.data is now TransformedResponse
  console.log(`Found ${response.data.totalCount} users`);
}
```

## Error Handling

### Built-in Error Types

```typescript
const response = await apiRequest('GET', '/users');

if (apiRequest.isError(response)) {
  switch (response.error.name) {
    case 'TimeoutError':
      console.error('Request timed out');
      break;
    case 'NetworkError':
      console.error('Network connection failed');
      break;
    case 'HttpError':
      console.error(`HTTP ${response.error.status}: ${response.error.message}`);
      break;
    case 'ParseError':
      console.error('Failed to parse response');
      break;
    case 'SecurityError':
      console.error('Request blocked for security reasons');
      break;
    case 'ValidationError':
      console.error('Request validation failed');
      break;
    default:
      console.error('Unknown error:', response.error.message);
  }
}
```

### Custom Error Handling

```typescript
const response = await apiRequest('GET', '/users', {
  onError: (error, attempt) => {
    console.warn(`Attempt ${attempt + 1} failed:`, error.message);

    // Log to external service
    if (error.status >= 500) {
      logToErrorService(error);
    }

    // Show user-friendly message
    if (error.name === 'NetworkError') {
      showNotification('Please check your internet connection');
    }
  },

  shouldRetry: (error, attempt) => {
    // Retry on server errors, but not client errors
    if (error.status >= 500) return attempt < 2;

    // Retry on specific timeout errors
    if (error.name === 'TimeoutError') return attempt < 1;

    // Don't retry on authentication errors
    if (error.status === 401) return false;

    return false;
  }
});
```

## Advanced Features

### Retry Configuration

```typescript
// Custom retry logic
const response = await apiRequest('GET', '/api/data', {
  retries: 3,
  timeout: 5000,
  shouldRetry: (error, attempt) => {
    // Retry on 5xx errors or network issues
    if (error.status >= 500) return true;
    if (error.name === 'NetworkError') return true;
    if (error.name === 'TimeoutError') return attempt < 2;
    return false;
  },
  onError: (error, attempt) => {
    console.log(`Retry ${attempt + 1}: ${error.message}`);
  }
});
```

### Type Inference and Debugging

```typescript
const response = await apiRequest('GET', '/users', {
  logTypes: true // Only works in development
});

// Console output:
// 🔍 Inferred Type for "/users"
// type _usersType = {
//   "id": string;
//   "name": string;
//   "email": string;
// }[];
```

### Full URL Support

```typescript
// Use full URLs (with SSRF protection)
const externalData = await apiRequest('GET', 'https://api.example.com/data', {
  allowedHosts: ['api.example.com']
});

// Mix of base URL and endpoints
const response = await apiRequest('GET', '/users'); // Uses BASE_URL
const external = await apiRequest('GET', 'https://external.com/api'); // Full URL
```

## Next.js Integration

### Server Actions

```typescript
'use server';

import apiRequest from '@/lib/safe-fetch';

export async function createUser(formData: FormData) {
  const response = await apiRequest<User, CreateUserData>('POST', '/users', {
    data: {
      name: formData.get('name') as string,
      email: formData.get('email') as string
    },
    // Next.js specific options
    revalidate: 60, // Revalidate every minute
    tags: ['users'], // Cache tag for on-demand revalidation
  });

  if (apiRequest.isSuccess(response)) {
    return { success: true, user: response.data };
  } else {
    return { success: false, error: response.error.message };
  }
}
```

### Static Generation with ISR

```typescript
// app/users/page.tsx
import apiRequest from '@/lib/safe-fetch';

export default async function UsersPage() {
  const response = await apiRequest<User[]>('GET', '/users', {
    revalidate: 3600, // Revalidate every hour
    tags: ['users'],
    cache: 'force-cache'
  });

  if (apiRequest.isError(response)) {
    return <div>Error loading users</div>;
  }

  return (
    <div>
      {response.data.map(user => (
        <div key={user.id}>{user.name}</div>
      ))}
    </div>
  );
}
```

### Cache Revalidation

```typescript
'use server';

import apiRequest from '@/lib/safe-fetch';
import { revalidateTag } from 'next/cache';

export async function createProduct(formData: FormData) {
  const newProductData = Object.fromEntries(formData);
  const response = await apiRequest('POST', '/products', {
    data: newProductData,
    tags: ['products-list', 'new-arrivals']
  });

  if (apiRequest.isSuccess(response)) {
    // After creating a product, revalidate the cache
    revalidateTag('products-list');
    console.log('Product created and cache revalidated!');
  } else {
    console.error('Failed to create product:', response.error);
  }

  return response;
}
```

## Security Features

### SSRF Protection

```typescript
// Allowed hosts configuration
const response = await apiRequest('GET', 'https://api.example.com/data', {
  allowedHosts: [
    'api.example.com',
    'cdn.example.com',
    '*.trusted-domain.com' // Wildcards supported
  ]
});

// Blocked URLs (automatically protected):
// - localhost, 127.0.0.1, private IPs
// - Metadata endpoints (169.254.169.254)
// - Non-standard ports
// - URLs with credentials
```

### Size Limits

```typescript
const response = await apiRequest('POST', '/upload', {
  data: largeFile,
  maxRequestBodySize: 50 * 1024 * 1024, // 50MB request limit
  maxResponseSize: 10 * 1024 * 1024, // 10MB response limit
});
```

### Header Sanitization

```typescript
// Headers are automatically sanitized
const response = await apiRequest('GET', '/api', {
  headers: {
    'X-Custom': 'safe-value',
    'Invalid\r\nHeader': 'blocked', // Automatically filtered
    'X-Large-Header': 'x'.repeat(10000) // Truncated to maxHeaderLength
  }
});
```

## Environment Configuration

### Environment Variables

```bash
# .env.local
BASE_URL=https://api.example.com
NEXT_PUBLIC_API_URL=https://api.example.com

# Authentication
AUTH_TOKEN=your-bearer-token
# or
AUTH_USERNAME=username
AUTH_PASSWORD=password
# or
API_TOKEN=your-api-token

# Security
ALLOWED_HOSTS=api.example.com,cdn.example.com
SAFEFETCH_ALLOWED_HOSTS=secure-api.com,trusted.com

# Node.js environment
NODE_ENV=production
```

### Configuration Priority

1. Options passed to `apiRequest()`
2. Environment variables
3. Default values

## Best Practices

### 1. Type Safety First

```typescript
// Define interfaces for better type safety
interface User {
  id: string;
  name: string;
  email: string;
  createdAt: string;
}

interface CreateUserRequest {
  name: string;
  email: string;
}

interface CreateUserResponse {
  user: User;
  message: string;
}

// Use generic types
const response = await apiRequest<CreateUserResponse, CreateUserRequest>(
  'POST',
  '/users',
  { data: { name: 'John', email: 'john@example.com' } }
);
```

### 2. Comprehensive Error Handling

```typescript
// Always handle errors
const response = await apiRequest<User[]>('GET', '/users');

if (apiRequest.isError(response)) {
  // Handle different error types
  switch (response.error.name) {
    case 'NetworkError':
      showOfflineMessage();
      break;
    case 'TimeoutError':
      showRetryButton();
      break;
    default:
      showGenericError(response.error.message);
  }
  return;
}

// Safe to use response.data
processUsers(response.data);
```

### 3. Smart Retry Strategy

```typescript
// Configure retries based on operation type
const response = await apiRequest('GET', '/users', {
  retries: 3, // Safe for GET requests
  shouldRetry: (error, attempt) => {
    // Retry server errors and network issues
    return error.status >= 500 || error.name === 'NetworkError';
  }
});

// Be cautious with non-idempotent operations
const createResponse = await apiRequest('POST', '/users', {
  data: userData,
  retries: 0 // Don't retry POST by default
});
```

### 4. Performance Optimization

```typescript
// Use appropriate cache strategies
const staticData = await apiRequest('GET', '/config', {
  cache: 'force-cache',
  revalidate: 86400 // 24 hours
});

const dynamicData = await apiRequest('GET', '/user/notifications', {
  cache: 'no-cache'
});
```

### 5. Security Best Practices

```typescript
// Always specify allowed hosts for external APIs
const externalData = await apiRequest('GET', 'https://api.third-party.com/data', {
  allowedHosts: ['api.third-party.com'],
  maxResponseSize: 1024 * 1024 // Limit response size
});
```

### 6. Development Tips

- **Always Check Response Success**: Use `apiRequest.isSuccess()` before accessing `response.data`
- **Explicitly Type Responses**: Define `TResponse` types for better IntelliSense
- **Use `logTypes: true` in Development**: Automatically generate TypeScript interfaces
- **Understand Retry Behavior**: Retries are enabled by default for idempotent methods
- **Adjust Timeouts Appropriately**: Default 30 seconds may need adjustment for your use case
- **Leverage Next.js Features**: Use `revalidate` and `tags` for efficient caching
- **Implement Error Analytics**: Use `onError` callback for monitoring and alerts

## Troubleshooting

### Common Issues and Solutions

#### SSRF Protection Blocking Valid Requests

```typescript
// Problem: Request blocked by SSRF protection
const response = await apiRequest('GET', 'https://api.example.com/data');
// Error: "URL not allowed: potential SSRF risk"

// Solution: Add to allowed hosts
const response = await apiRequest('GET', 'https://api.example.com/data', {
  allowedHosts: ['api.example.com']
});

// Or use environment variable
// ALLOWED_HOSTS=api.example.com,cdn.example.com
```

#### Request Body Too Large

```typescript
// Problem: Large request body rejected
const response = await apiRequest('POST', '/upload', {
  data: largeFile
});
// Error: "Request body too large"

// Solution: Increase size limit
const response = await apiRequest('POST', '/upload', {
  data: largeFile,
  maxRequestBodySize: 50 * 1024 * 1024 // 50MB
});
```

#### Timeout Issues

```typescript
// Problem: Requests timing out
const response = await apiRequest('GET', '/slow-endpoint');
// Error: "Request timeout after 30000ms"

// Solution: Increase timeout
const response = await apiRequest('GET', '/slow-endpoint', {
  timeout: 60000 // 60 seconds
});
```

#### TypeScript Errors

```typescript
// Problem: Type mismatches
interface User { id: string; name: string; }
const response = await apiRequest<User[]>('GET', '/users');
// Error: Property 'email' does not exist on type 'User'

// Solution: Update interface or use transformation
interface ApiUser { id: string; name: string; email: string; }
const response = await apiRequest<ApiUser[]>('GET', '/users');
```

#### Authentication Issues

```typescript
// Problem: 401 Unauthorized
const response = await apiRequest('GET', '/protected');
// Error: HTTP 401 Error

// Solution: Check environment variables
// AUTH_TOKEN=your-token
// or
// AUTH_USERNAME=user
// AUTH_PASSWORD=pass

// Or pass custom headers
const response = await apiRequest('GET', '/protected', {
  headers: {
    'Authorization': 'Bearer your-token'
  }
});
```

### Debug Mode

```typescript
// Enable detailed logging in development
const response = await apiRequest('GET', '/users', {
  logTypes: true, // Log inferred types
  onError: (error, attempt) => {
    console.log('Debug info:', {
      error: error.devMessage || error.message,
      attempt,
      status: error.status,
      data: error.data
    });
  }
});
```

## Browser Compatibility

SafeFetch is designed to be highly compatible with modern JavaScript environments.

### Requirements

SafeFetch requires support for:
- Fetch API
- AbortController
- Promises
- URL constructor
- TextDecoder (for response parsing)
- Buffer (Node.js for auth header, typically polyfilled in modern bundlers)

### Compatible Environments

- ✅ Next.js 13+ (App Router)
- ✅ React 18+
- ✅ Node.js 18+
- ✅ All modern browsers (Chrome, Firefox, Safari, Edge)

## Summary

SafeFetch provides a robust, type-safe HTTP client with comprehensive error handling, retry logic, and security features. It's designed to work seamlessly with Next.js while providing excellent developer experience through TypeScript support and detailed error information.

### Key Benefits

- **Full TypeScript Support**: Generic types and automatic inference
- **Automatic Retry Logic**: Exponential backoff with customizable strategies
- **SSRF Protection**: Built-in security features and request validation
- **Next.js Integration**: ISR, caching, and revalidation support
- **Comprehensive Error Handling**: Detailed error types and custom handlers
- **Response Transformation**: Transform API responses to match your needs
- **Development Tools**: Type debugging and detailed logging

For more advanced use cases or custom configurations, refer to the source code and adapt the examples to your specific needs.

---

**SafeFetch** - Simple, typed, reliable HTTP requests for modern TypeScript applications.
