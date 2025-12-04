# SafeFetch - Single Server Setup & Usage Guide

A memory-optimized typed fetch utility for React + Bun + Vite with secure server-side authentication - all running on a single server!

## 📁 Project Structure

```
project/
├── src/
│   ├── lib/
│   │   └── safeFetch.ts        # Client-side utility (no credentials)
│   ├── App.tsx
│   └── main.tsx
├── server.ts                    # Single server: Vite dev + API proxy
├── .env                         # Server secrets (NEVER commit)
├── .gitignore
├── package.json
├── vite.config.ts
└── tsconfig.json
```

## 🔐 Environment Configuration

### Single `.env` File

**⚠️ IMPORTANT: Add `.env` to your `.gitignore` - NEVER commit this file!**

```env
# External API configuration (credentials stored here)
API_URL=https://api.example.com
AUTH_USERNAME=your_username
AUTH_PASSWORD=your_secure_password
# OR use token instead of username/password
# API_TOKEN=your_secret_token

# Server configuration
PORT=3000
```

### `.gitignore`

```gitignore
# Environment variables
.env
.env.local
.env.*.local

# Dependencies
node_modules/

# Build output
dist/
```

## 🚀 Installation

```bash
# Install dependencies
bun install

# Install Vite if not already installed
bun add -D vite
```

## 📦 Package.json Scripts

```json
{
  "scripts": {
    "dev": "bun run server.ts",
    "build": "vite build",
    "preview": "bun run server.ts"
  }
}
```

## 🎯 Usage

### 1. Start the Single Server

```bash
bun run dev
```

You should see:
```
🚀 SafeFetch Single Server (Vite + API Proxy)
   API URL: https://api.example.com
   Auth: Basic Auth
   Port: 3000

✅ Server running at http://localhost:3000
   Frontend: http://localhost:3000
   API Proxy: http://localhost:3000/api/*
```

### 2. How It Works

- **Frontend requests** → Vite dev server serves your React app
- **API requests to `/api/*`** → Proxied to external API with credentials
- **Everything runs on port 3000** 🎉

### 3. Use in Your React Application

#### Basic GET Request

```typescript
import apiRequest from './lib/safeFetch'

function UsersList() {
  const [users, setUsers] = useState([])

  useEffect(() => {
    async function fetchUsers() {
      // Automatically proxied to API_URL/users with credentials
      const response = await apiRequest('GET', '/users')
      
      if (apiRequest.isSuccess(response)) {
        setUsers(response.data)
      } else {
        console.error('Error:', response.error.message)
      }
    }
    
    fetchUsers()
  }, [])

  return <div>{/* Render users */}</div>
}
```

#### POST Request with Data

```typescript
async function createUser(userData: { name: string; email: string }) {
  const response = await apiRequest('POST', '/users', {
    data: userData
  })

  if (apiRequest.isSuccess(response)) {
    console.log('User created:', response.data)
    return response.data
  } else {
    throw new Error(response.error.message)
  }
}

// Usage
await createUser({ name: 'John Doe', email: 'john@example.com' })
```

#### With Query Parameters

```typescript
const response = await apiRequest('GET', '/users', {
  params: {
    page: 1,
    limit: 10,
    status: 'active'
  }
})
// Requests: /api/users?page=1&limit=10&status=active
// Proxied to: API_URL/users?page=1&limit=10&status=active (with auth)
```

#### With Custom Headers

```typescript
const response = await apiRequest('POST', '/upload', {
  data: formData,
  headers: {
    'X-Custom-Header': 'value'
  }
})
```

#### With Retry Configuration

```typescript
const response = await apiRequest('GET', '/unstable-endpoint', {
  retries: 5,
  timeout: 30000, // 30 seconds
  priority: 'high'
})
```

#### With Dynamic Timeout

```typescript
const response = await apiRequest('GET', '/data', {
  timeout: (attempt) => 1000 * attempt, // 1s, 2s, 3s...
  retries: 3
})
```

#### With Transform Function

```typescript
interface ApiUser {
  id: number
  name: string
  created_at: string
}

interface User {
  id: number
  name: string
  createdAt: Date
}

const response = await apiRequest<User[], never>('GET', '/users', {
  transform: (data: ApiUser[]) => 
    data.map(user => ({
      id: user.id,
      name: user.name,
      createdAt: new Date(user.created_at)
    }))
})

if (apiRequest.isSuccess(response)) {
  // response.data is now User[] with Date objects
  console.log(response.data[0].createdAt.toISOString())
}
```

#### With AbortSignal

```typescript
const controller = new AbortController()

const response = await apiRequest('GET', '/long-request', {
  signal: controller.signal
})

// Cancel the request
controller.abort()
```

#### With Type Logging (Development)

```typescript
const response = await apiRequest('GET', '/users', {
  logTypes: true // Only works in development
})

// Console output:
// 🔍 [SafeFetch] "/users"
// type usersResponse = {
//   id: number;
//   name: string;
//   email: string;
// }[];
// ⏱️ 245ms
```

#### FormData Upload

```typescript
const formData = new FormData()
formData.append('file', file)
formData.append('description', 'Profile picture')

const response = await apiRequest('POST', '/upload', {
  data: formData
})
```

#### Type-Safe Response Handling

```typescript
interface User {
  id: number
  name: string
  email: string
}

const response = await apiRequest<User>('GET', '/users/123')

if (apiRequest.isSuccess(response)) {
  // TypeScript knows response.data is User
  console.log(response.data.name)
} else {
  // TypeScript knows response.error is ApiError
  console.error(response.error.message)
  console.error(response.error.status)
}
```

## 🛠️ Advanced Features

### Priority Queue

```typescript
// High priority request (processed first)
await apiRequest('GET', '/critical-data', {
  priority: 'high'
})

// Normal priority (default)
await apiRequest('GET', '/data', {
  priority: 'normal'
})

// Low priority (processed last)
await apiRequest('GET', '/analytics', {
  priority: 'low'
})
```

### Get Pool Statistics

```typescript
const stats = apiRequest.utils.getStats()
console.log(stats)
// {
//   pool: { active: 3, queued: 5, maxConcurrent: 20 },
//   runtime: 'bun'
// }
```

### Create Timeout Signal

```typescript
const response = await apiRequest('GET', '/data', {
  signal: apiRequest.utils.timeout(5000) // 5 second timeout
})
```

### Cache Control

```typescript
// Force cache
const response = await apiRequest('GET', '/static-data', {
  cache: 'force-cache'
})

// No cache
const response = await apiRequest('GET', '/realtime-data', {
  cache: 'no-store'
})
```

## 🔄 React Hooks Example

### Custom Hook for API Calls

```typescript
import { useState, useEffect } from 'react'
import apiRequest, { ApiResponse } from './lib/safeFetch'

function useApi<T>(endpoint: string, options = {}) {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false

    async function fetchData() {
      setLoading(true)
      setError(null)

      const response = await apiRequest<T>('GET', endpoint, options)

      if (cancelled) return

      if (apiRequest.isSuccess(response)) {
        setData(response.data)
      } else {
        setError(response.error.message)
      }

      setLoading(false)
    }

    fetchData()

    return () => {
      cancelled = true
    }
  }, [endpoint])

  return { data, loading, error }
}

// Usage
function UserProfile({ userId }: { userId: number }) {
  const { data, loading, error } = useApi(`/users/${userId}`)

  if (loading) return <div>Loading...</div>
  if (error) return <div>Error: {error}</div>
  if (!data) return null

  return <div>{data.name}</div>
}
```

## 🏭 Production Deployment

### Option 1: Deploy with Bun Server

**Build frontend:**
```bash
bun run build
```

**Update server.ts for production:**
```typescript
import { serveStatic } from "bun";

// ... existing imports ...

const isProduction = process.env.NODE_ENV === "production";

const server = Bun.serve({
  port: PORT,
  
  async fetch(req) {
    const url = new URL(req.url);
    
    // API proxy (same as before)
    if (url.pathname.startsWith("/api/")) {
      // ... existing API proxy code ...
    }

    // Serve static files in production
    if (isProduction) {
      return serveStatic({
        root: "./dist",
        path: url.pathname,
      });
    }

    // Use Vite dev server in development
    // ... existing Vite code ...
  },
});
```

**Run in production:**
```bash
NODE_ENV=production bun run server.ts
```

### Option 2: Deploy Frontend Separately

**Build frontend:**
```bash
bun run build
# Deploy dist/ to Vercel, Netlify, etc.
```

**Deploy backend separately:**
- Keep server.ts for API proxy only
- Point frontend `VITE_API_URL` to your deployed backend

### Environment Variables

Set these in your production environment:

```env
API_URL=https://production-api.example.com
AUTH_USERNAME=prod_username
AUTH_PASSWORD=prod_secure_password
PORT=3000
NODE_ENV=production
```

## 🔒 Security Best Practices

1. **Never expose credentials in frontend code**
   - ✅ Store in backend `.env`
   - ❌ Never use `VITE_` prefix for secrets
   - ✅ All API calls go through `/api/*` proxy

2. **Use HTTPS in production**
   - Always use `https://` for API_URL

3. **Rate limiting**
   - Add rate limiting to your server.ts

4. **Validate requests**
   - Add request validation middleware

5. **Audit dependencies**
   ```bash
   bun audit
   ```

## 📊 Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `data` | `RequestBody` | `null` | Request body |
| `params` | `QueryParams` | `undefined` | URL query parameters |
| `retries` | `number` | `2` | Number of retry attempts |
| `timeout` | `number \| function` | `60000` | Request timeout in ms |
| `headers` | `Record<string, string>` | `{}` | Custom headers |
| `transform` | `function` | `undefined` | Transform response data |
| `priority` | `'high' \| 'normal' \| 'low'` | `'normal'` | Request priority |
| `signal` | `AbortSignal` | `undefined` | Abort signal |
| `logTypes` | `boolean` | `false` | Log TypeScript types (dev only) |
| `cache` | `RequestCache` | `undefined` | Cache control |
| `token` | `string` | `undefined` | Bearer token (user sessions) |

## 🐛 Troubleshooting

### Port Already in Use

Change the port in `.env`:
```env
PORT=3001
```

### API Requests Failing

Check that your endpoints start with `/` (they'll be proxied to `/api/`):
```typescript
// ✅ Correct
await apiRequest('GET', '/users')

// ❌ Wrong
await apiRequest('GET', 'users')
```

### CORS Errors

The single server setup eliminates most CORS issues since frontend and API are on the same origin!

### 502 Proxy Error

Verify your `API_URL` in `.env` is correct and accessible.

## 🎉 Benefits of Single Server

✅ **Simpler setup** - One server to run  
✅ **No CORS issues** - Same origin for frontend and API  
✅ **Easy development** - Single `bun run dev` command  
✅ **Secure by default** - Credentials never exposed to client  
✅ **Production ready** - Easy to deploy as a single unit

## 📝 Architecture

```
Client Browser
    ↓
http://localhost:3000
    ↓
Single Bun Server
    ├─→ /api/* ──→ API Proxy ──→ External API (with credentials)
    └─→ /* ─────→ Vite Dev Server / Static Files
```

## 📝 License

BSD 3-Clause License - (c) 2025 Bharathi4real

## 🤝 Contributing

Issues and pull requests welcome!

---

Made with ❤️ using Bun, React, and TypeScript
