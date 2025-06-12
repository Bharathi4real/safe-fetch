# 🛡️ SafeFetch

**SafeFetch** is a TypeScript-first HTTP client with built-in retry logic, timeout handling, and Next.js App Router support.

## ✨ Features

- ⚙️ **Retry logic** for safe HTTP methods (GET, PUT)
- ⏱️ **Timeout protection** with AbortController
- 🧾 **Full TypeScript support** with excellent IntelliSense
- 🔁 **JSON & FormData support**
- 🧠 **Next.js App Router compatible** - `revalidate`, `cache`, `tags`
- 🔐 **Optional Basic Auth** from environment variables

## ⚙️ Setup

### Environment Variables (Optional)

```bash
# .env.local
BASE_URL=https://api.your-domain.com
AUTH_USERNAME=your_username
AUTH_PASSWORD=your_password
```

## 📖 Usage

### Basic Example

```typescript
import apiRequest from 'safe-fetch';

interface User {
  id: number;
  name: string;
  email: string;
}

// GET request
const result = await apiRequest<User[]>('GET', '/users');

if (result.success) {
  console.log(result.data); // Full TypeScript intellisense
} else {
  console.error(result.error);
}
```

### POST with Data

```typescript
const newUser = await apiRequest<User>('POST', '/users', {
  data: {
    name: 'John Doe',
    email: 'john@example.com'
  }
});
```

### Advanced Options

```typescript
const result = await apiRequest<Product[]>('GET', '/products', {
  params: { category: 'electronics', limit: 10 },
  retries: 3,
  timeout: 15000,
  cache: 'force-cache',
  revalidate: 3600,
  tags: ['products']
});
```

### File Upload

```typescript
const formData = new FormData();
formData.append('file', file);

const result = await apiRequest<{url: string}>('POST', '/upload', {
  data: formData,
  timeout: 60000
});
```

## 🧠 TypeScript Support

SafeFetch provides excellent IntelliSense with:

- **Response type inference** - `result.data` is automatically typed
- **Request body validation** - TypeScript validates your data structure
- **Options autocomplete** - Full IDE support for configuration options

```typescript
// TypeScript knows result.data is User[] when success is true
const users = await apiRequest<User[]>('GET', '/users');
```

## 🔧 API Reference

```typescript
apiRequest<ResponseType, RequestType>(method, endpoint, options?)
```

**Options:**
```typescript
interface RequestOptions<T> {
  data?: T;                    // Request body
  params?: Record<string, string | number | boolean>;
  retries?: number;            // Default: 1
  timeout?: number;            // Default: 30000ms
  cache?: RequestCache;
  revalidate?: number | false; // Next.js ISR
  tags?: string[];            // Next.js cache tags
  headers?: Record<string, string>;
}
```

**Returns:**
```typescript
type ApiResponse<T> = 
  | { success: true; status: number; data: T }
  | { success: false; status: number; error: string; data: null };
```

## 🏗️ Next.js Integration

```typescript
// Server Component
export default async function Page() {
  const products = await apiRequest<Product[]>('GET', '/products', {
    revalidate: 300,
    tags: ['products']
  });
  
  return <div>{/* render products */}</div>;
}

// Server Action
'use server';
export async function createProduct(formData: FormData) {
  const result = await apiRequest('POST', '/products', {
    data: Object.fromEntries(formData)
  });
  
  if (result.success) {
    revalidateTag('products');
  }
  
  return result;
}
```
## Detailed Usage Examples

See [Examples](./examples.md) for more details and usage examples.

## 📄 License

This project is licensed under the **BSD 3-Clause License**. Attribution to **Bharathi4real** is required.

See [LICENSE](./LICENSE) for details.
