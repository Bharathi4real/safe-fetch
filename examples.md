# SafeFetch Usage Guide

A typed fetch utility with retry, timeout & Next.js support. Simply copy and paste the code into your project.

## 🚀 Available Features

- ✅ **TypeScript Support** - Full type safety with inference helpers
- ✅ **Automatic Retries** - Smart retry logic for failed requests
- ✅ **Timeout Control** - Configurable request timeouts
- ✅ **Next.js Integration** - ISR, cache tags, and server actions
- ✅ **Query Parameters** - Easy URL parameter handling
- ✅ **File Uploads** - FormData support with proper headers
- ✅ **Authentication** - Built-in Basic Auth from environment
- ✅ **Error Handling** - Consistent response format
- ✅ **Cache Control** - Full fetch cache API support
- ✅ **Development Tools** - Type inference logging

## 📋 Quick Navigation

- [Setup](#setup) - Environment and installation
- [Basic Usage](#basic-usage) - Simple GET/POST examples
- [TypeScript Support](#typescript-support) - Type safety and inference
- [Query Parameters](#query-parameters) - URL parameter handling
- [Advanced Features](#advanced-features) - Retries, headers, uploads
- [Next.js Features](#nextjs-specific-features) - ISR, cache tags, SSR
- [Error Handling](#error-handling) - Comprehensive error management
- [Complete Examples](#complete-examples) - Real-world usage patterns
- [Environment Variables](#environment-variables) - Configuration options
- [Tips & Best Practices](#tips) - Development recommendations

## Setup

1. Copy the SafeFetch code into your project (e.g., `lib/api.ts`)
2. Set optional environment variables:
   ```env
   BASE_URL=https://api.example.com
   AUTH_USERNAME=your_username
   AUTH_PASSWORD=your_password
   ```

## Basic Usage

### Simple GET Request
```typescript
import apiRequest from './lib/api';

// Basic GET request
const response = await apiRequest('GET', '/users');

if (response.success) {
  console.log('Users:', response.data);
} else {
  console.error('Error:', response.error);
}
```

### POST Request with Data
```typescript
// Create a new user
const newUser = { name: 'John Doe', email: 'john@example.com' };

const response = await apiRequest('POST', '/users', {
  data: newUser
});

if (response.success) {
  console.log('Created user:', response.data);
}
```

## TypeScript Support

### Explicit Types
```typescript
interface User {
  id: number;
  name: string;
  email: string;
}

// Specify response type
const response = await apiRequest<User[]>('GET', '/users');

if (response.success) {
  // response.data is now typed as User[]
  response.data.forEach(user => {
    console.log(user.name); // TypeScript knows this is a string
  });
}
```

### Type Inference Helper
```typescript
// Log inferred types to console (development only)
const response = await apiRequest('GET', '/users', {
  logTypes: true
});

// This will log the TypeScript interface to console:
// export type Users = {
//   id: number;
//   name: string;
//   email: string;
// }[];
```

## Query Parameters

```typescript
// GET /users?page=1&limit=10&active=true
const response = await apiRequest('GET', '/users', {
  params: {
    page: 1,
    limit: 10,
    active: true
  }
});
```

## Advanced Features

### Retry Configuration
```typescript
// Retry failed requests (only for GET and PUT)
const response = await apiRequest('GET', '/unstable-endpoint', {
  retries: 3, // Will retry up to 3 times
  timeout: 5000 // 5 second timeout
});
```

### Custom Headers
```typescript
const response = await apiRequest('POST', '/protected', {
  data: { message: 'Hello' },
  headers: {
    'X-Custom-Header': 'value',
    'Authorization': 'Bearer your-token'
  }
});
```

### File Upload with FormData
```typescript
const formData = new FormData();
formData.append('file', fileInput.files[0]);
formData.append('description', 'Profile picture');

const response = await apiRequest('POST', '/upload', {
  data: formData // Automatically sets correct Content-Type
});
```

## Next.js Specific Features

### ISR (Incremental Static Regeneration)
```typescript
// Revalidate cache every 60 seconds
const response = await apiRequest('GET', '/posts', {
  revalidate: 60
});

// Disable ISR
const response = await apiRequest('GET', '/posts', {
  revalidate: false
});
```

### Cache Tags
```typescript
// Tag cache for selective revalidation
const response = await apiRequest('GET', '/posts', {
  tags: ['posts', 'blog'],
  revalidate: 3600 // 1 hour
});

// Later, revalidate specific tags:
// revalidateTag('posts')
```

### Fetch Cache Control
```typescript
// Control fetch caching behavior
const response = await apiRequest('GET', '/data', {
  cache: 'no-store' // Always fetch fresh data
});

// Other options: 'default', 'force-cache', 'only-if-cached', etc.
```

## Error Handling

### Comprehensive Error Handling
```typescript
const response = await apiRequest('GET', '/users');

if (!response.success) {
  switch (response.status) {
    case 404:
      console.log('Users not found');
      break;
    case 500:
      console.log('Server error');
      break;
    case 408:
      console.log('Request timeout');
      break;
    default:
      console.log('Error:', response.error);
  }
}
```

### Automatic Retry Conditions
The utility automatically retries requests when:
- Request times out (AbortError)
- Server returns 408, 429, 500, 502, 503, or 504
- Network errors occur
- Only for GET and PUT methods (safe to retry)

## Complete Examples

### CRUD Operations
```typescript
interface Todo {
  id: number;
  title: string;
  completed: boolean;
}

class TodoService {
  // Get all todos
  static async getAll() {
    return apiRequest<Todo[]>('GET', '/todos');
  }

  // Get single todo
  static async getById(id: number) {
    return apiRequest<Todo>('GET', `/todos/${id}`);
  }

  // Create todo
  static async create(todo: Omit<Todo, 'id'>) {
    return apiRequest<Todo>('POST', '/todos', { data: todo });
  }

  // Update todo
  static async update(id: number, todo: Partial<Todo>) {
    return apiRequest<Todo>('PUT', `/todos/${id}`, { data: todo });
  }

  // Delete todo
  static async delete(id: number) {
    return apiRequest('DELETE', `/todos/${id}`);
  }
}
```

### Search with Pagination
```typescript
interface SearchParams {
  query: string;
  page: number;
  limit: number;
}

interface SearchResponse {
  results: any[];
  total: number;
  page: number;
}

async function search(params: SearchParams) {
  return apiRequest<SearchResponse>('GET', '/search', {
    params,
    timeout: 10000, // 10 second timeout for search
    retries: 2
  });
}

// Usage
const results = await search({
  query: 'javascript',
  page: 1,
  limit: 20
});
```

## Environment Variables

```env
# Optional base URL (defaults to empty string)
BASE_URL=https://api.example.com

# Optional basic authentication
AUTH_USERNAME=your_username
AUTH_PASSWORD=your_password
```

## Response Format

All requests return a consistent response format:

```typescript
// Success response
{
  success: true,
  status: 200,
  data: T // Your typed data
}

// Error response
{
  success: false,
  status: 400,
  error: "Error message",
  data: null
}
```

## Tips

1. **Type Safety**: Always specify response types for better TypeScript support
2. **Development**: Use `logTypes: true` to generate TypeScript interfaces
3. **Retries**: Only GET and PUT requests are retried automatically
4. **Timeouts**: Default timeout is 30 seconds, adjust as needed
5. **Next.js**: Use ISR features for better performance in Next.js apps
6. **Error Handling**: Always check `response.success` before using data

## Browser Compatibility

Works in all modern browsers and Node.js environments that support:
- Fetch API
- AbortController
- Promises
- URL constructor
