# SafeFetch: Areas for Improvement

## 1. **Simpler Setup & Configuration**

### Current Pain Points
```typescript
// Too much ceremony for basic usage
const clientConfig = createClientConfig({
  allowedDomains: ['api.myapp.com'],
  envConfig: { baseUrl: 'MY_API_URL' }
});

// Client-side requires passing config everywhere
const response = await get('/users', { clientConfig });
```

### Proposed Solutions

#### A. Auto-Configuration Pattern
```typescript
// New: Auto-configure from environment
import { safeFetch } from './safefetch';

// Automatically reads process.env.NEXT_PUBLIC_API_URL, etc.
const api = safeFetch.auto(); 

// Usage becomes much simpler
const users = await api.get<User[]>('/users');
const created = await api.post<User>('/users', { data: newUser });
```

#### B. Global Instance Pattern
```typescript
// Configure once in layout.tsx or middleware
safeFetch.configure({
  baseUrl: process.env.NEXT_PUBLIC_API_URL,
  auth: 'auto', // Auto-detect from env
});

// Use anywhere without passing config
import { get, post } from 'safefetch';
const users = await get<User[]>('/users'); // Just works
```

#### C. Smart Defaults
```typescript
// New: Reasonable defaults for common scenarios
export const createSafeFetch = (config: Partial<SafeFetchConfig> = {}) => {
  const defaults = {
    // Auto-detect common environment variables
    envConfig: {
      baseUrl: 'NEXT_PUBLIC_API_URL', // Standard Next.js convention
      authToken: 'NEXT_PUBLIC_API_TOKEN',
    },
    // Allow localhost in development
    allowedDomains: process.env.NODE_ENV === 'development' 
      ? ['localhost', '127.0.0.1', ...config.allowedDomains || []]
      : config.allowedDomains,
    defaults: {
      timeout: 15000, // More reasonable default
      retryAttempts: 2, // Less aggressive
      cache: 'no-store', // Safe default
      ...config.defaults
    }
  };
  
  return { ...defaults, ...config };
};
```

## 2. **Better Development Experience**

### Current Issues
- HTTPS-only breaks local development
- Domain validation too restrictive
- No development mode conveniences

### Proposed Solutions

#### A. Development Mode Support
```typescript
const isDev = process.env.NODE_ENV === 'development';

// Auto-allow localhost and disable strict validation in dev
const createClientConfig = (config: SafeFetchConfig = {}) => {
  const env = createEnv(config.envConfig);
  
  // New: Allow HTTP in development
  if (isDev && env.BASE_URL?.startsWith('http://localhost')) {
    // Allow HTTP for local development
  }
  
  // New: Skip domain validation in development
  if (isDev || config.skipDomainValidation) {
    // Skip production domain checks
  }
};
```

#### B. Better Error Messages
```typescript
// Current: Cryptic error
throw new Error('BASE_URL must be one of the allowed production domains');

// Better: Actionable error with suggestions
throw new Error(`
❌ BASE_URL "${env.BASE_URL}" not allowed in production.

💡 Add to allowedDomains: createClientConfig({ 
  allowedDomains: ['${new URL(env.BASE_URL).hostname}'] 
})

🔧 Or set NODE_ENV=development for local testing
`);
```

#### C. Development Tools
```typescript
// New: Built-in request/response logging
export const createSafeFetch = (config: SafeFetchConfig = {}) => ({
  // ... existing code
  
  // New: Development helpers
  debug: process.env.NODE_ENV === 'development' ? {
    logRequests: true,
    logResponses: true,
    logTypes: true,
    // Visual request/response inspector
    inspector: () => console.table(getRequestStats())
  } : undefined
});
```

## 3. **Enhanced Flexibility**

### Current Limitations
```typescript
// Too rigid - what if I need HTTP for internal services?
if (fullUrl.protocol !== 'https:') {
  throw new Error('HTTPS required');
}

// What about custom auth schemes?
// Only supports Bearer and Basic
```

### Proposed Solutions

#### A. Configurable Validation
```typescript
export interface SafeFetchConfig {
  // New: Configurable security policies
  security?: {
    requireHttps?: boolean; // Default: true in production
    allowedProtocols?: string[]; // ['https:', 'http:']
    validateDomains?: boolean; // Default: true in production
    requireAuth?: boolean; // Default: false
  };
  
  // New: Custom auth strategies
  auth?: {
    strategy: 'bearer' | 'basic' | 'custom';
    customHeader?: (env: EnvConfig) => string;
  };
}
```

#### B. Middleware Pattern
```typescript
// New: Request/Response middleware
export interface Middleware {
  request?: (request: RequestInit) => RequestInit | Promise<RequestInit>;
  response?: (response: Response) => Response | Promise<Response>;
  error?: (error: ApiError) => ApiError | Promise<ApiError>;
}

const api = createSafeFetch({
  middleware: [
    // Custom auth middleware
    {
      request: (req) => ({
        ...req,
        headers: { ...req.headers, 'X-Custom-Auth': getCustomToken() }
      })
    },
    // Request logging middleware
    {
      request: (req) => {
        console.log('📤', req.method, req.url);
        return req;
      },
      response: (res) => {
        console.log('📥', res.status, res.url);
        return res;
      }
    }
  ]
});
```

## 4. **Missing Features**

### A. Request/Response Interceptors
```typescript
// New: Axios-style interceptors
const api = createSafeFetch();

api.interceptors.request.use((config) => {
  // Add auth token, logging, etc.
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    // Handle token refresh, redirect to login, etc.
    return Promise.reject(error);
  }
);
```

### B. Built-in Pagination
```typescript
// New: Pagination helpers
export interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    hasNext: boolean;
    hasPrev: boolean;
  };
}

// Built-in pagination support
const response = await api.getPaginated<User>('/users', {
  page: 1,
  limit: 20,
  // Auto-handles query params and response parsing
});

// Iterator support
for await (const page of api.paginate<User>('/users', { limit: 100 })) {
  console.log(`Page ${page.pagination.page}:`, page.data);
}
```

### C. Streaming Support
```typescript
// New: Streaming responses
const stream = await api.getStream('/large-dataset');

for await (const chunk of stream) {
  // Process data as it arrives
  processChunk(chunk);
}

// Or with React Suspense
const { data, loading } = useStreamingQuery('/real-time-data');
```

### D. File Upload Improvements
```typescript
// Current: Basic FormData support
const formData = new FormData();
formData.append('file', file);
await post('/upload', { data: formData });

// Better: Built-in upload helpers
await api.upload('/files', {
  file: file,
  metadata: { description: 'User avatar' },
  onProgress: (percent) => setProgress(percent),
  resumable: true, // Support resumable uploads
});
```

## 5. **Performance Optimizations**

### A. Request Deduplication
```typescript
// New: Automatic request deduplication
const api = createSafeFetch({
  deduplication: {
    enabled: true,
    window: 1000, // 1 second window
    keyGenerator: (method, url, options) => `${method}:${url}:${hash(options)}`
  }
});

// These concurrent requests will be deduplicated
const [user1, user2] = await Promise.all([
  api.get<User>('/users/123'),
  api.get<User>('/users/123') // Same request, will reuse first
]);
```

### B. Background Refetch
```typescript
// New: SWR-style background updates
const response = await api.get<User[]>('/users', {
  cache: 'force-cache',
  revalidate: 3600,
  backgroundRefetch: true, // Fetch fresh data in background
  onBackgroundUpdate: (freshData) => {
    // Update UI when fresh data arrives
    setUsers(freshData);
  }
});
```

### C. Prefetching
```typescript
// New: Route-based prefetching
const api = createSafeFetch({
  prefetch: {
    '/users': ['/users/profile', '/users/settings'], // Prefetch related routes
  }
});

// Prefetch on hover (like Next.js Link)
<button 
  onMouseEnter={() => api.prefetch('/users/123')}
  onClick={() => router.push('/users/123')}
>
  View User
</button>
```

## 6. **Developer Tools Integration**

### A. Next.js DevTools Support
```typescript
// New: Integration with React DevTools
if (process.env.NODE_ENV === 'development') {
  // Add SafeFetch panel to React DevTools
  window.__SAFEFETCH_DEVTOOLS__ = {
    requests: getAllRequests(),
    cache: getCacheState(),
    errors: getErrorHistory()
  };
}
```

### B. Better Debugging
```typescript
// New: Request replay and inspection
const api = createSafeFetch({
  debug: {
    enabled: process.env.NODE_ENV === 'development',
    features: ['replay', 'inspect', 'timeline', 'performance']
  }
});

// In browser console:
// safeFetch.debug.replay('req_123') - Replay specific request
// safeFetch.debug.timeline() - Show request timeline
// safeFetch.debug.performance() - Performance metrics
```

## 7. **Documentation & Examples**

### A. Real-World Examples
```typescript
// Current: Basic examples in JSDoc
// Better: Comprehensive example patterns

// examples/auth.ts
export const authPatterns = {
  // JWT with refresh
  jwtWithRefresh: () => { /* implementation */ },
  
  // OAuth flow
  oauth: () => { /* implementation */ },
  
  // API key rotation
  apiKeyRotation: () => { /* implementation */ }
};

// examples/caching.ts
export const cachingPatterns = {
  // SWR pattern
  staleWhileRevalidate: () => { /* implementation */ },
  
  // Optimistic updates
  optimisticUpdates: () => { /* implementation */ },
  
  // Cache invalidation strategies
  invalidationStrategies: () => { /* implementation */ }
};
```

### B. Migration Guides
```markdown
# Migration from fetch/axios to SafeFetch

## From fetch
```typescript
// Before
const response = await fetch('/api/users');
const users = await response.json();

// After
const response = await get<User[]>('/users');
if (response.success) {
  const users = response.data; // Fully typed!
}
```

## From axios
```typescript
// Before
try {
  const response = await axios.get<User[]>('/users');
  return response.data;
} catch (error) {
  // Manual error handling
}

// After
const response = await get<User[]>('/users');
return response.success ? response.data : null;
// Errors are standardized and typed
```
```

## Implementation Priority

1. **High Priority** (Core DX improvements)
   - Auto-configuration pattern
   - Development mode support
   - Better error messages

2. **Medium Priority** (Enhanced features)
   - Request/Response interceptors
   - Built-in pagination helpers
   - Request deduplication

3. **Low Priority** (Nice-to-have)
   - Streaming support
   - DevTools integration
   - Advanced caching strategies

These improvements would transform SafeFetch from a solid library into an exceptional Next.js HTTP client that developers actively choose over alternatives.