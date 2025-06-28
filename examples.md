# 🛡️ SafeFetch Usage Guide

A typed fetch utility with retry, timeout & Next.js support. Simply copy and paste the code into your project.

## 🚀 Available Features

- ✅ **TypeScript Support** - Full type safety with inference helpers
- ✅ **Automatic Retries** - Smart retry logic for failed requests
- ✅ **Timeout Control** - Configurable request timeouts
- ✅ **Next.js Integration** - ISR, cache tags, and server actions
- ✅ **Query Parameters** - Easy URL parameter handling
- ✅ **File Uploads** - FormData support with proper headers
- ✅ **Authentication** - Built-in Basic Auth from environment
- ✅ **Error Handling** - Consistent response format with detailed API errors
- ✅ **Cache Control** - Full fetch cache API support
- ✅ **Development Tools** - Type inference logging
- ✅ **SSRF Protection** - Configurable allowed hosts and blocked IP ranges
- ✅ **Response Transformation** - Custom function to transform successful response data
- ✅ **Custom Error Handling/Retry Conditions** - Optional callbacks for fine-grained control
- ✅ **Max Response Size** - Prevents large/malicious responses

## 📋 Quick Navigation

- [Setup](#setup) - Environment and installation
- [Basic Usage](#basic-usage) - Simple GET/POST examples
- [TypeScript Support](#typescript-support) - Type safety and inference
- [Query Parameters](#query-parameters) - URL parameter handling
- [Advanced Features](#advanced-features) - Retries, headers, uploads, transformations, error callbacks
- [Next.js Specific Features](#nextjs-specific-features) - ISR, cache tags, SSR
- [Error Handling](#error-handling) - Comprehensive error management
- [Complete Examples](#complete-examples) - Real-world usage patterns
- [Environment Variables](#environment-variables) - Configuration options
- [Response Format](#response-format) - Consistent success and error response structure
- [Tips & Best Practices](#tips--best-practices) - Development recommendations
- [Browser Compatibility](#browser-compatibility) - Supported environments

## Setup

Copy the SafeFetch code into your project (e.g., `lib/api.ts` or `utils/safe-fetch.ts`).

Set optional environment variables:

```bash
BASE_URL=https://api.your-domain.com
AUTH_USERNAME=your_username
AUTH_PASSWORD=your_password
ALLOWED_HOSTS=api.your-domain.com,another.allowed.host.com
SAFEFETCH_ALLOWED_HOSTS=additional-security-hosts.com
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
  console.error('Error:', response.error); // response.error is an ApiError object
}
```

### POST Request with Data

```typescript
import apiRequest from './lib/api';

// Create a new user
const newUser = { name: 'John Doe', email: 'john@example.com' };

const response = await apiRequest('POST', '/users', {
  data: newUser
});

if (response.success) {
  console.log('Created user:', response.data);
} else {
  console.error('Error creating user:', response.error);
}
```

## TypeScript Support

### Explicit Types

```typescript
import apiRequest from './lib/api';

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
import apiRequest from './lib/api';

// Log inferred types to console (development only)
// Note: This logs the *inferred* type of the *response data*
const response = await apiRequest('GET', '/users', {
  logTypes: true
});

// This will log a TypeScript interface to the console (example):
// 🔍 Inferred Type for "/users"
// type usersType = {
//    id: number;
//    name: string;
//    email: string;
// }[];
```

## Query Parameters

```typescript
import apiRequest from './lib/api';

// GET /users?page=1&limit=10&active=true
const response = await apiRequest('GET', '/users', {
  params: {
    page: 1,
    limit: 10,
    active: true,
    status: null // Null/undefined values are ignored
  }
});
```

## Advanced Features

### Retry Configuration

```typescript
import apiRequest from './lib/api';

// Retry failed requests (only for GET and PUT by default, configurable)
const response = await apiRequest('GET', '/unstable-endpoint', {
  retries: 3,   // Will retry up to 3 times
  timeout: 5000 // 5 second timeout for each attempt
});

if (!response.success) {
  console.error(`Request failed after ${response.error.attempt} attempts:`, response.error);
}
```

### Custom Headers

```typescript
import apiRequest from './lib/api';

const response = await apiRequest('POST', '/protected', {
  data: { message: 'Hello' },
  headers: {
    'X-Custom-Header': 'my-value',
    'Authorization': 'Bearer your-custom-token' // Overrides environment AUTH_HEADER if set
  }
});
```

### File Upload with FormData

```typescript
import apiRequest from './lib/api';

// Assuming fileInput is an HTMLInputElement like <input type="file" id="fileInput">
const fileInput = document.getElementById('fileInput') as HTMLInputElement;
const selectedFile = fileInput?.files?.[0];

if (selectedFile) {
  const formData = new FormData();
  formData.append('file', selectedFile);
  formData.append('description', 'User profile picture');

  const response = await apiRequest<{ url: string }>('POST', '/upload', {
    data: formData, // Automatically sets 'Content-Type': 'multipart/form-data'
    timeout: 60000  // Longer timeout for uploads
  });

  if (response.success) {
    console.log('File uploaded:', response.data.url);
  } else {
    console.error('File upload failed:', response.error);
  }
}
```

### Response Transformation

```typescript
import apiRequest from './lib/api';

interface RawItem {
  id: number;
  name: string;
  created_at: string; // ISO string
}

interface TransformedItem {
  itemId: number;
  itemName: string;
  createdAtDate: Date;
}

const response = await apiRequest<RawItem[], RawItem[]>('GET', '/items', {
  transform: (data) => {
    // Transform data after successful fetch, before returning
    return data.map(item => ({
      itemId: item.id,
      itemName: item.name,
      createdAtDate: new Date(item.created_at)
    }));
  }
});

if (response.success) {
  response.data.forEach(item => {
    console.log(item.createdAtDate.getFullYear()); // Transformed type
  });
}
```

### Custom Error Handler (onError)

```typescript
import apiRequest from './lib/api';

const response = await apiRequest('GET', '/sensitive-data', {
  onError: (error, attempt) => {
    console.error(`Attempt ${attempt} failed for /sensitive-data:`, error.message);
    // You could send this to an external error monitoring service
    // if (error.status === 401) logoutUser();
  }
});
```

### Custom Retry Condition (shouldRetry)

```typescript
import apiRequest from './lib/api';

const response = await apiRequest('POST', '/process-task', {
  data: { taskId: 'abc-123' },
  retries: 5,
  shouldRetry: (error, attempt) => {
    // Only retry for 503 Service Unavailable, and only up to 3 times
    return error.status === 503 && attempt < 3;
  },
  onError: (error, attempt) => console.warn(`Retry attempt ${attempt} for /process-task:`, error.message)
});

if (!response.success) {
  console.error('Task processing failed after all retries:', response.error);
}
```

### Maximum Response Size

```typescript
import apiRequest from './lib/api';

// Limit response size to 2MB
const response = await apiRequest('GET', '/large-report', {
  maxResponseSize: 2 * 1024 * 1024 // 2MB
});

if (!response.success && response.error.name === 'PayloadTooLargeError') {
  console.error('Response exceeded maximum allowed size.');
}
```

## Next.js Specific Features

SafeFetch is designed to seamlessly integrate with the Next.js App Router's extended fetch options.

### ISR (Incremental Static Regeneration)

```typescript
// pages/api/products.ts or app/products/page.tsx
import apiRequest from '../../lib/api'; // Adjust path as needed

// Revalidate cache every 60 seconds
export default async function ProductsPage() {
  const response = await apiRequest('GET', '/products', {
    revalidate: 60 // Revalidate data every 60 seconds
  });

  if (response.success) {
    return (
      <div>
        <h1>Products</h1>
        {/* Render products */}
      </div>
    );
  } else {
    return <div>Error loading products: {response.error.message}</div>;
  }
}

// You can also disable ISR (dynamic rendering)
async function fetchDynamicData() {
  const response = await apiRequest('GET', '/dynamic-data', {
    revalidate: false // Opt-out of caching for this fetch
  });
  // ...
}
```

### Cache Tags

```typescript
// app/actions/productActions.ts (Server Action)
'use server';
import apiRequest from '../../lib/api'; // Adjust path as needed
import { revalidateTag } from 'next/cache'; // Import from Next.js

export async function createProduct(formData: FormData) {
  const newProductData = Object.fromEntries(formData);
  const response = await apiRequest('POST', '/products', {
    data: newProductData,
    // Tag this fetch for selective revalidation if needed elsewhere
    tags: ['products-list', 'new-arrivals']
  });

  if (response.success) {
    // After creating a product, revalidate the 'products-list' tag to get fresh data
    revalidateTag('products-list');
    console.log('Product created and cache revalidated!');
  } else {
    console.error('Failed to create product:', response.error);
  }

  return response;
}
```

### Fetch Cache Control

```typescript
import apiRequest from './lib/api';

// Control fetch caching behavior
const responseNoStore = await apiRequest('GET', '/realtime-data', {
  cache: 'no-store' // Always fetch fresh data, never cache
});

// Other common options:
const responseForceCache = await apiRequest('GET', '/static-content', {
  cache: 'force-cache' // Always use cache, even if stale (unless revalidated)
});

const responseDefaultCache = await apiRequest('GET', '/default-data', {
  cache: 'default' // Standard browser cache behavior (default for SafeFetch)
});
```

## Error Handling

SafeFetch provides a consistent ApiResponse structure, allowing you to easily handle both successful responses and detailed errors.

### Comprehensive Error Handling

```typescript
import apiRequest from './lib/api';

const response = await apiRequest('GET', '/non-existent-resource');

if (!response.success) {
  console.error('API Request Failed!');
  console.error('Status:', response.status);
  console.error('Error Name:', response.error.name);
  console.error('Error Message:', response.error.message);
  console.error('Attempt:', response.error.attempt); // Only present if retries were attempted

  // Handle specific error types or statuses
  switch (response.error.name) {
    case 'HttpError':
      if (response.status === 404) {
        console.log('Resource not found!');
      } else if (response.status === 401) {
        console.log('Authentication required!');
        // Redirect to login page or refresh token
      }
      break;
    case 'TimeoutError':
      console.log('The request took too long to respond.');
      break;
    case 'NetworkError':
      console.log('A network issue prevented the request (e.g., no internet).');
      break;
    case 'PayloadTooLargeError':
      console.log('The response or request body was too large.');
      break;
    case 'SecurityError':
      console.log('The request was blocked due to SSRF protection.');
      break;
    case 'TransformError':
      console.log('Failed to transform the response data.');
      break;
    default:
      console.log('An unexpected error occurred.');
  }
}
```

### Automatic Retry Conditions

The utility automatically retries requests when:

- Request times out (TimeoutError or AbortError).
- Server returns 408 (Request Timeout), 429 (Too Many Requests), 500 (Internal Server Error), 502 (Bad Gateway), 503 (Service Unavailable), or 504 (Gateway Timeout) status codes.
- Underlying network errors occur (e.g., NetworkError related messages).

**Important:** Retries only apply to idempotent HTTP methods: GET, PUT, DELETE, HEAD, and OPTIONS. POST and PATCH are not retried by default as they may not be idempotent. You can override this using the `shouldRetry` option.

## Complete Examples

### CRUD Operations

```typescript
import apiRequest from './lib/api';

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

// Example Usage:
async function runTodoExamples() {
  console.log('Fetching all todos...');
  const allTodos = await TodoService.getAll();
  if (allTodos.success) {
    console.log('Todos:', allTodos.data);
  } else {
    console.error('Failed to fetch todos:', allTodos.error);
  }

  console.log('\nCreating a new todo...');
  const newTodo = await TodoService.create({ title: 'Learn SafeFetch', completed: false });
  if (newTodo.success) {
    console.log('New Todo created:', newTodo.data);
    const todoId = newTodo.data.id;

    console.log(`\nUpdating todo ${todoId}...`);
    const updatedTodo = await TodoService.update(todoId, { completed: true });
    if (updatedTodo.success) {
      console.log('Updated Todo:', updatedTodo.data);
    } else {
      console.error('Failed to update todo:', updatedTodo.error);
    }

    console.log(`\nDeleting todo ${todoId}...`);
    const deleteResult = await TodoService.delete(todoId);
    if (deleteResult.success) {
      console.log(`Todo ${todoId} deleted successfully!`);
    } else {
      console.error('Failed to delete todo:', deleteResult.error);
    }

  } else {
    console.error('Failed to create todo:', newTodo.error);
  }
}

// Uncomment to run:
// runTodoExamples();
```

### Search with Pagination

```typescript
import apiRequest from './lib/api';

interface SearchParams {
  query: string;
  page?: number; // Optional, defaults to 1
  limit?: number; // Optional, defaults to 10
}

interface SearchResultItem {
  id: string;
  title: string;
  description: string;
  url: string;
}

interface SearchResponse {
  results: SearchResultItem[];
  total: number;
  page: number;
  limit: number;
}

async function search(params: SearchParams) {
  return apiRequest<SearchResponse>('GET', '/search', {
    params,
    timeout: 10000, // 10 second timeout for search
    retries: 2,     // Retry search up to 2 times
    // Example of a custom transform:
    transform: (data) => ({
      ...data,
      results: data.results.map(item => ({
        ...item,
        title: item.title.toUpperCase() // Convert titles to uppercase
      }))
    })
  });
}

// Usage
async function runSearchExample() {
  console.log('Searching for "javascript" on page 1...');
  const results = await search({
    query: 'javascript',
    page: 1,
    limit: 5
  });

  if (results.success) {
    console.log('Search Results (transformed titles):', results.data.results);
    console.log(`Total results: ${results.data.total}`);
    console.log(`Current page: ${results.data.page}`);
  } else {
    console.error('Search failed:', results.error);
  }

  console.log('\nSearching for "python" on page 2...');
  const resultsPage2 = await search({
    query: 'python',
    page: 2,
    limit: 3
  });

  if (resultsPage2.success) {
    console.log('Search Results (page 2):', resultsPage2.data.results);
  } else {
    console.error('Search failed on page 2:', resultsPage2.error);
  }
}

// Uncomment to run:
// runSearchExample();
```

## Environment Variables

These environment variables can be set in your `.env.local` file (for Next.js) or as system environment variables in other Node.js projects.

```bash
# Optional base URL for API requests.
# If not set, you must use absolute URLs (e.g., 'https://api.example.com/data').
# If set, relative URLs (e.g., '/users') will be appended to this BASE_URL.
BASE_URL=https://api.example.com

# Optional Basic Authentication credentials.
# If both are provided, SafeFetch will include a 'Basic' Authorization header.
AUTH_USERNAME=your_username
AUTH_PASSWORD=your_password

# Optional Bearer Token Authentication.
# If AUTH_USERNAME and AUTH_PASSWORD are not set, SafeFetch will check for these.
# It will include a 'Bearer' Authorization header if a valid token is found.
AUTH_TOKEN=your_bearer_token_here
API_TOKEN=your_api_key_or_token_here

# Optional: Comma-separated list of allowed hostnames for SSRF protection.
# Requests to hosts not in this list (or not BASE_URL) will be blocked.
# Merged with 'SAFEFETCH_ALLOWED_HOSTS'.
ALLOWED_HOSTS=api.example.com,cdn.example.com

# Additional environment variable for allowed hosts (merged with ALLOWED_HOSTS).
# Useful for adding more hosts without modifying the primary ALLOWED_HOSTS var.
SAFEFETCH_ALLOWED_HOSTS=secure-api.com,analytics.domain.org
```

## Response Format

All `apiRequest` calls return a consistent `Promise<ApiResponse<T>>`. This type provides clear discrimination between success and error states using a `success` boolean.

### Success Response (ApiResponse<T> where success is true)

```typescript
{
  success: true,
  status: 200,   // HTTP status code (e.g., 200, 201)
  data: T,       // Your typed response data (e.g., User[], Product)
  headers: Headers // The full Headers object from the successful response
}
```

### Error Response (ApiResponse<T> where success is false)

```typescript
{
  success: false,
  status: 400, // HTTP status code (e.g., 400, 404, 500)
  error: {
    name: string;    // Category of the error (e.g., "HttpError", "NetworkError", "TimeoutError", "ValidationError", "PayloadTooLargeError", "SecurityError", "TransformError", "UnknownError")
    message: string; // Detailed error message (from API or internal)
    status: number;  // The HTTP status code (same as the top-level 'status')
    attempt?: number;// The retry attempt number at which the error occurred (if retries were used)
  },
  data: null // Data is always null on error
}
```

## Tips & Best Practices

1. **Always Check `response.success`**: Before attempting to access `response.data`, always check the `response.success` property. This ensures type safety and prevents runtime errors.

2. **Explicitly Type Responses**: While SafeFetch offers some inference, explicitly defining `TResponse` (e.g., `apiRequest<User[]>`) provides the best type safety and IntelliSense.

3. **Use `logTypes: true` in Dev**: For complex API responses, `logTypes: true` can be incredibly helpful for automatically generating a TypeScript interface or type that matches your API's response structure.

4. **Understand Retry Behavior**: Remember that retries are enabled by default for GET, PUT, DELETE, HEAD, and OPTIONS methods. For POST or PATCH (which are generally not idempotent), set `retries: 0` or provide a custom `shouldRetry` function if you need to retry them.

5. **Adjust `timeout` Appropriately**: The default 30-second timeout is a general starting point. Adjust it based on your API's expected response times, especially for long-running operations or large file uploads.

6. **Leverage Next.js Features**: If you're in a Next.js App Router environment, make full use of `revalidate` and `tags` for efficient caching and on-demand revalidation.

7. **Implement `onError` for Analytics**: Use the `onError` callback to log errors to your monitoring systems, trigger alerts, or handle specific error scenarios (e.g., force logout on a 401 Unauthorized).

8. **SSRF Protection**: Configure `ALLOWED_HOSTS` environment variables to prevent Server-Side Request Forgery vulnerabilities, especially when making requests to dynamic URLs.

## Browser Compatibility

SafeFetch is designed to be highly compatible with modern JavaScript environments.

**Works in all modern environments that support:**
- Fetch API
- AbortController
- Promises
- URL constructor
- TextDecoder (for response parsing)
- Buffer (Node.js for auth header, typically polyfilled in modern bundlers for browser environments if needed)

**Compatible with:**
- ✅ Next.js 13+ (App Router)
- ✅ React 18+
- ✅ Node.js 18+
- ✅ All evergreen modern browsers (Chrome, Firefox, Safari, Edge)

---

**SafeFetch** - Simple, typed, reliable HTTP requests for modern TypeScript applications.
