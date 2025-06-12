# SafeFetch Usage Examples

SafeFetch is a typed fetch utility with retry logic, timeout handling, and Next.js support. Here are practical examples showing how to use it in real applications.

## Setup

First, set up your environment variables:

```bash
# .env.local
BASE_URL=https://api.example.com
AUTH_USERNAME=your_username
AUTH_PASSWORD=your_password
```

## Basic Usage Examples

### 1. User Management System

```typescript
import apiRequest from './safe-fetch';

// Define user types
interface User {
  id: number;
  name: string;
  email: string;
  role: 'admin' | 'user';
}

interface CreateUserRequest {
  name: string;
  email: string;
  role: 'admin' | 'user';
}

// Get all users
export async function getUsers() {
  const result = await apiRequest<User[]>('GET', '/users');
  
  if (result.success) {
    return result.data;
  } else {
    throw new Error(`Failed to fetch users: ${result.error}`);
  }
}

// Create a new user
export async function createUser(userData: CreateUserRequest) {
  const result = await apiRequest<User, CreateUserRequest>('POST', '/users', {
    data: userData,
    retries: 2, // Retry up to 2 times for POST requests
  });
  
  if (result.success) {
    return result.data;
  } else {
    throw new Error(`Failed to create user: ${result.error}`);
  }
}

// Update user with optimistic retry
export async function updateUser(id: number, updates: Partial<User>) {
  const result = await apiRequest<User, Partial<User>>('PUT', `/users/${id}`, {
    data: updates,
    retries: 3, // PUT is idempotent, safe to retry
    timeout: 10000, // 10 second timeout
  });
  
  return result;
}
```

### 2. E-commerce Product Catalog

```typescript
interface Product {
  id: string;
  name: string;
  price: number;
  category: string;
  inStock: boolean;
}

interface ProductFilters {
  category?: string;
  minPrice?: number;
  maxPrice?: number;
  inStock?: boolean;
}

// Search products with filters
export async function searchProducts(filters: ProductFilters) {
  const result = await apiRequest<Product[]>('GET', '/products', {
    params: {
      ...(filters.category && { category: filters.category }),
      ...(filters.minPrice && { min_price: filters.minPrice }),
      ...(filters.maxPrice && { max_price: filters.maxPrice }),
      ...(filters.inStock !== undefined && { in_stock: filters.inStock }),
    },
    // Cache for 5 minutes
    revalidate: 300,
    tags: ['products'],
  });
  
  if (result.success) {
    return result.data;
  } else {
    console.error('Product search failed:', result.error);
    return [];
  }
}

// Get product details with aggressive caching
export async function getProduct(id: string) {
  const result = await apiRequest<Product>('GET', `/products/${id}`, {
    cache: 'force-cache',
    revalidate: 3600, // Cache for 1 hour
    tags: ['products', `product-${id}`],
    retries: 3,
  });
  
  return result;
}
```

### 3. File Upload with Progress Tracking

```typescript
interface UploadResponse {
  fileId: string;
  url: string;
  size: number;
}

// Upload file with FormData
export async function uploadFile(file: File, folder: string = 'uploads') {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('folder', folder);
  
  const result = await apiRequest<UploadResponse, FormData>('POST', '/upload', {
    data: formData,
    timeout: 60000, // 60 seconds for large files
    retries: 1, // Don't retry file uploads aggressively
    headers: {
      // Don't set Content-Type for FormData - browser handles it
    },
  });
  
  if (result.success) {
    return result.data;
  } else {
    throw new Error(`Upload failed: ${result.error}`);
  }
}
```

### 4. Real-time Dashboard Data

```typescript
interface DashboardStats {
  totalUsers: number;
  activeUsers: number;
  revenue: number;
  orders: number;
}

// Get dashboard stats with no caching (always fresh)
export async function getDashboardStats() {
  const result = await apiRequest<DashboardStats>('GET', '/dashboard/stats', {
    cache: 'no-store', // Always fetch fresh data
    timeout: 5000, // Quick timeout for dashboard
    retries: 2,
  });
  
  if (result.success) {
    return result.data;
  } else {
    // Return default values on error for better UX
    return {
      totalUsers: 0,
      activeUsers: 0,
      revenue: 0,
      orders: 0,
    };
  }
}
```

### 5. Error Handling Patterns

```typescript
// Centralized error handling
export async function safeApiCall<T>(
  method: Parameters<typeof apiRequest>[0],
  endpoint: Parameters<typeof apiRequest>[1],
  options?: Parameters<typeof apiRequest>[2]
) {
  try {
    const result = await apiRequest<T>(method, endpoint, options);
    
    if (result.success) {
      return { data: result.data, error: null };
    } else {
      // Log error for monitoring
      console.error(`API Error: ${method} ${endpoint}`, {
        status: result.status,
        error: result.error,
      });
      
      return { data: null, error: result.error };
    }
  } catch (error) {
    console.error(`Unexpected error: ${method} ${endpoint}`, error);
    return { data: null, error: 'Network error occurred' };
  }
}

// Usage with error handling
export async function getUserProfile(userId: string) {
  const { data, error } = await safeApiCall<User>('GET', `/users/${userId}`, {
    retries: 3,
    timeout: 10000,
  });
  
  if (error) {
    // Handle error appropriately
    throw new Error(`Failed to load user profile: ${error}`);
  }
  
  return data;
}
```

## Next.js App Router Integration

### 6. Server Component with ISR

```typescript
// app/products/page.tsx
import { searchProducts } from '@/lib/api';

export default async function ProductsPage() {
  // This will use ISR with 5-minute revalidation
  const products = await searchProducts({});
  
  return (
    <div>
      <h1>Products</h1>
      <div className="grid grid-cols-3 gap-4">
        {products.map(product => (
          <ProductCard key={product.id} product={product} />
        ))}
      </div>
    </div>
  );
}
```

### 7. Server Actions with Revalidation

```typescript
// app/actions.ts
'use server';

import { revalidateTag } from 'next/cache';
import apiRequest from '@/lib/safe-fetch';

export async function createProduct(formData: FormData) {
  const productData = {
    name: formData.get('name') as string,
    price: Number(formData.get('price')),
    category: formData.get('category') as string,
  };
  
  const result = await apiRequest('POST', '/products', {
    data: productData,
    retries: 2,
  });
  
  if (result.success) {
    // Revalidate the products cache
    revalidateTag('products');
    return { success: true, product: result.data };
  } else {
    return { success: false, error: result.error };
  }
}
```

## Advanced Usage Patterns

### 8. Paginated Data Fetching

```typescript
interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    hasNext: boolean;
  };
}

export async function getPaginatedUsers(page: number = 1, limit: number = 20) {
  const result = await apiRequest<PaginatedResponse<User>>('GET', '/users', {
    params: { page, limit },
    cache: 'default',
    revalidate: 300, // 5 minutes
    tags: ['users', `users-page-${page}`],
  });
  
  return result;
}
```

### 9. Batch Operations

```typescript
interface BatchUpdateRequest {
  updates: Array<{ id: string; data: Partial<User> }>;
}

export async function batchUpdateUsers(updates: BatchUpdateRequest['updates']) {
  const result = await apiRequest<{ updated: number }, BatchUpdateRequest>('POST', '/users/batch', {
    data: { updates },
    timeout: 45000, // Longer timeout for batch operations
    retries: 1, // Be careful with retries on batch operations
  });
  
  if (result.success) {
    // Invalidate user-related caches
    revalidateTag('users');
    return result.data;
  } else {
    throw new Error(`Batch update failed: ${result.error}`);
  }
}
```

### 10. Real-time Polling Pattern

```typescript
export class DataPoller {
  private intervalId: NodeJS.Timeout | null = null;
  
  startPolling(callback: (data: DashboardStats) => void, interval: number = 30000) {
    this.intervalId = setInterval(async () => {
      try {
        const result = await apiRequest<DashboardStats>('GET', '/dashboard/stats', {
          cache: 'no-store',
          timeout: 5000,
          retries: 1,
        });
        
        if (result.success) {
          callback(result.data);
        }
      } catch (error) {
        console.error('Polling error:', error);
      }
    }, interval);
  }
  
  stopPolling() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }
}

// Usage
const poller = new DataPoller();
poller.startPolling((stats) => {
  console.log('Updated stats:', stats);
}, 15000); // Poll every 15 seconds
```

## Best Practices

1. **Type Safety**: Always define interfaces for your API responses
2. **Error Handling**: Handle both success and error cases appropriately
3. **Caching**: Use appropriate cache strategies for your data freshness needs
4. **Retries**: Be conservative with retries for non-idempotent operations
5. **Timeouts**: Set appropriate timeouts based on operation complexity
6. **Monitoring**: Log errors for debugging and monitoring
7. **Fallbacks**: Provide sensible fallback values for better UX
