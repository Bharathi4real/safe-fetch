/**
 * SafeFetch Backend Proxy Server
 * Handles authentication and proxies requests to the actual API
 * Credentials stored securely on server, never exposed to client
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 */

// Load environment variables (NOT prefixed with VITE_)
const API_URL = process.env.API_URL || "";
const AUTH_USERNAME = process.env.AUTH_USERNAME;
const AUTH_PASSWORD = process.env.AUTH_PASSWORD;
const API_TOKEN = process.env.API_TOKEN;
const PORT = process.env.PORT || 3001;
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";

// Generate auth header once on startup
let AUTH_HEADER = "";
if (AUTH_USERNAME && AUTH_PASSWORD) {
  AUTH_HEADER = `Basic ${btoa(`${AUTH_USERNAME}:${AUTH_PASSWORD}`)}`;
} else if (API_TOKEN) {
  AUTH_HEADER = `Bearer ${API_TOKEN}`;
}

console.log("🚀 SafeFetch Backend Proxy");
console.log(`   API URL: ${API_URL}`);
console.log(`   Auth Method: ${AUTH_USERNAME ? "Basic Auth" : API_TOKEN ? "Bearer Token" : "None"}`);
console.log(`   Port: ${PORT}`);
console.log(`   Frontend: ${FRONTEND_URL}\n`);

const server = Bun.serve({
  port: PORT,
  
  async fetch(req) {
    const url = new URL(req.url);
    
    // CORS headers
    const corsHeaders = {
      "Access-Control-Allow-Origin": FRONTEND_URL,
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Credentials": "true",
    };

    // Handle preflight requests
    if (req.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders,
      });
    }

    // Health check endpoint
    if (url.pathname === "/health") {
      return new Response(
        JSON.stringify({ status: "ok", timestamp: new Date().toISOString() }),
        {
          status: 200,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/json",
          },
        }
      );
    }

    try {
      // Build target URL
      const targetUrl = `${API_URL}${url.pathname}${url.search}`;
      
      console.log(`→ ${req.method} ${url.pathname}${url.search}`);

      // Forward headers, but add authentication
      const headers = new Headers();
      
      // Copy relevant headers from client
      for (const [key, value] of req.headers.entries()) {
        // Skip host and connection headers
        if (!["host", "connection", "origin"].includes(key.toLowerCase())) {
          headers.set(key, value);
        }
      }

      // Add server-side authentication
      if (AUTH_HEADER) {
        headers.set("Authorization", AUTH_HEADER);
      }

      // Make the proxied request
      const response = await fetch(targetUrl, {
        method: req.method,
        headers,
        body: req.body,
      });

      // Get response body
      const contentType = response.headers.get("content-type");
      const isJson = contentType?.includes("application/json");
      const body = isJson ? await response.json() : await response.text();

      console.log(`← ${response.status} ${url.pathname}`);

      // Return response to client
      return new Response(
        isJson ? JSON.stringify(body) : body,
        {
          status: response.status,
          headers: {
            ...corsHeaders,
            "Content-Type": contentType || "application/json",
          },
        }
      );

    } catch (error) {
      console.error("❌ Proxy error:", error);
      
      return new Response(
        JSON.stringify({
          error: "Proxy error",
          message: error instanceof Error ? error.message : "Unknown error",
        }),
        {
          status: 502,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/json",
          },
        }
      );
    }
  },
});

console.log(`✅ Server running at http://localhost:${server.port}`);
console.log(`   Ready to proxy requests to ${API_URL}\n`);
