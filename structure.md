# DIRECTORY STRUCTURE

```
/safe-fetch/
├── index.ts                # Main entry point exporting apiRequest
├── types.ts               # Core types and interfaces
├── plugins/
│   ├── url-validation.ts   # URL validation and SSRF protection
│   ├── headers.ts         # Headers construction
│   ├── timeout.ts         # Timeout handling
│   ├── retry.ts           # Retry logic with exponential backoff
│   ├── response-parser.ts # Response parsing based on content type
│   ├── transform.ts       # Response transformation
│   ├── type-logging.ts    # TypeScript type logging for development
│   ├── next-js.ts         # Next.js-specific options
├── utils/
│   ├── create-api-error.ts # Utility to create ApiError objects
│   ├── url-safety.ts       # URL safety checks for SSRF protection
│   ├── parse-response.ts   # Response parsing logic
│   ├── prepare-body.ts     # Request body preparation
│   ├── retry-utils.ts      # Retry-related utilities (delay, shouldRetryRequest)
│   ├── type-logging-utils.ts # Type inference and logging utilities
```
