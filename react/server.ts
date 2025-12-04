/**
 * SafeFetch Single Server
 * Serves both Vite frontend AND handles API proxy with authentication
 * Run with: bun run server.ts
 */

import { createServer } from "vite";

// Environment variables
const API_URL = process.env.API_URL || "";
const AUTH_USERNAME = process.env.AUTH_USERNAME;
const AUTH_PASSWORD = process.env.AUTH_PASSWORD;
const API_TOKEN = process.env.API_TOKEN;
const PORT = parseInt(process.env.PORT || "3000", 10);

// Generate auth header once on startup
let AUTH_HEADER = "";
if (AUTH_USERNAME && AUTH_PASSWORD) {
  AUTH_HEADER = `Basic ${btoa(`${AUTH_USERNAME}:${AUTH_PASSWORD}`)}`;
} else if (API_TOKEN) {
  AUTH_HEADER = `Bearer ${API_TOKEN}`;
}

console.log("🚀 SafeFetch Single Server (Vite + API Proxy)");
console.log(`   API URL: ${API_URL}`);
console.log(`   Auth: ${AUTH_USERNAME ? "Basic Auth" : API_TOKEN ? "Bearer Token" : "None"}`);
console.log(`   Port: ${PORT}\n`);

// Create Vite dev server
const vite = await createServer({
  server: {
    middlewareMode: true,
    port: PORT,
  },
  appType: "spa",
});

// Main server
const server = Bun.serve({
  port: PORT,
  
  async fetch(req) {
    const url = new URL(req.url);
    
    // API proxy route - handle all /api/* requests
    if (url.pathname.startsWith("/api/")) {
      try {
        // Remove /api prefix and build target URL
        const apiPath = url.pathname.replace(/^\/api/, "");
        const targetUrl = `${API_URL}${apiPath}${url.search}`;
        
        console.log(`→ API ${req.method} ${apiPath}${url.search}`);

        // Forward headers with authentication
        const headers = new Headers();
        
        for (const [key, value] of req.headers.entries()) {
          if (!["host", "connection", "origin"].includes(key.toLowerCase())) {
            headers.set(key, value);
          }
        }

        // Add server-side authentication
        if (AUTH_HEADER) {
          headers.set("Authorization", AUTH_HEADER);
        }

        // Proxy the request
        const response = await fetch(targetUrl, {
          method: req.method,
          headers,
          body: req.body,
        });

        const contentType = response.headers.get("content-type");
        const isJson = contentType?.includes("application/json");
        const body = isJson ? await response.json() : await response.text();

        console.log(`← API ${response.status} ${apiPath}`);

        return new Response(
          isJson ? JSON.stringify(body) : body,
          {
            status: response.status,
            headers: {
              "Content-Type": contentType || "application/json",
              "Access-Control-Allow-Origin": "*",
              "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
              "Access-Control-Allow-Headers": "Content-Type, Authorization",
            },
          }
        );

      } catch (error) {
        console.error("❌ API Proxy error:", error);
        
        return new Response(
          JSON.stringify({
            error: "Proxy error",
            message: error instanceof Error ? error.message : "Unknown error",
          }),
          {
            status: 502,
            headers: { "Content-Type": "application/json" },
          }
        );
      }
    }

    // Handle Vite dev server for all other requests (frontend)
    try {
      // Convert Bun Request to Node Request-like object
      const nodeReq = {
        url: url.pathname + url.search,
        method: req.method,
        headers: Object.fromEntries(req.headers.entries()),
      };

      const nodeRes = {
        statusCode: 200,
        headers: {} as Record<string, string>,
        setHeader(key: string, value: string) {
          this.headers[key] = value;
        },
        end(body?: string) {
          this._body = body;
        },
        write(chunk: string) {
          this._body = (this._body || "") + chunk;
        },
        _body: "",
      };

      // Let Vite handle the request
      await vite.middlewares(nodeReq as any, nodeRes as any, () => {});

      return new Response(nodeRes._body, {
        status: nodeRes.statusCode,
        headers: nodeRes.headers,
      });
    } catch (error) {
      console.error("❌ Vite error:", error);
      return new Response("Internal Server Error", { status: 500 });
    }
  },
});

console.log(`✅ Server running at http://localhost:${server.port}`);
console.log(`   Frontend: http://localhost:${server.port}`);
console.log(`   API Proxy: http://localhost:${server.port}/api/*\n`);
console.log(`   Press Ctrl+C to stop\n`);
