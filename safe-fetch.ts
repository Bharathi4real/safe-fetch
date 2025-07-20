/**
 * SafeFetch – Typed fetch utility with retry, timeout & Next.js support
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 * https://github.com/Bharathi4real/safe-fetch
 */

'use server'; // Next.js server action

/** HTTP methods */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS';

/** Request body types */
export type RequestBody = Record<string, unknown> | FormData | string | ArrayBuffer | Blob | null;

/** Query parameter types */
export type QueryParams = Record<string, string | number | boolean | null | undefined>;

export type ErrorData =
	| string
	| number
	| boolean
	| null
	| undefined
	| Record<string, unknown>
	| Array<unknown>
	| Blob
	| ArrayBuffer
	| FormData
	| ReadableStream
	| bigint
	| symbol;

/** Next.js specific options */
export interface NextOptions {
	revalidate?: number | false;
	tags?: string[];
}

/** Type inference logging options */
export interface LogTypesOptions {
	/** Maximum depth for nested object type inference (default: 10) */
	maxDepth?: number;
	/** Maximum number of properties to show per object (default: 50) */
	maxProperties?: number;
	/** Maximum number of array items to sample for type inference (default: 5) */
	maxArrayItems?: number;
	/** Show counts for truncated properties/arrays (default: false) */
	showPropertyCount?: boolean;
}

/**
 * Request options with comprehensive JSDoc for perfect IntelliSense
 * @template TBody - Request body type
 * @template TTransformedResponse - Transformed response data type
 */
export interface RequestOptions<
	TBody extends RequestBody = RequestBody,
	TTransformedResponse = unknown,
> {
	/** Request body - auto-serialized to JSON unless FormData/Blob/ArrayBuffer */
	data?: TBody;
	/** Query parameters appended to URL */
	params?: QueryParams;
	/** Max retry attempts for idempotent methods (default: 1) */
	retries?: number;
	/** Request timeout in milliseconds (default: 30000) */
	timeout?: number;
	/** Fetch cache strategy (default: 'default') */
	cache?: RequestCache;
	/** Next.js ISR revalidation time in seconds */
	revalidate?: number | false;
	/** Next.js cache tags for on-demand revalidation */
	tags?: string[];
	/** Custom headers merged with defaults */
	headers?: Record<string, string>;
	/** Log inferred TypeScript types (dev only) - boolean or options object */
	logTypes?: boolean | LogTypesOptions;
	/** Transform response data before returning */
	transform?<T>(data: T): TTransformedResponse;
	/** Custom error handler */
	onError?: (error: ApiError, attempt: number) => void;
	/** Custom retry condition */
	shouldRetry?: (error: ApiError, attempt: number) => boolean;
	/** Allowed hosts for SSRF protection (merged with ALLOWED_HOSTS env var) */
	allowedHosts?: string[];
	/** Maximum response size in bytes (default: 10MB) */
	maxResponseSize?: number;
	/** Maximum request body size in bytes (default: 10MB) */
	maxRequestBodySize?: number;
}
/** Structured error information */
export interface ApiError {
	readonly name: string;
	readonly message: string;
	readonly status: number;
	readonly attempt?: number;
	readonly data?: ErrorData;
	readonly devMessage?: string;
	readonly originalError?: Error;
	readonly contentType?: string;
	readonly dataType?: string;
	readonly dataSizeBytes?: number;
}

/** Type-safe API response with success/error discrimination */
export type ApiResponse<T = unknown> =
	| { success: true; status: number; data: T; headers: Headers }
	| { success: false; status: number; error: ApiError; data: null };

/** Timeout controller with cleanup */
interface TimeoutController {
	controller: AbortController;
	cleanup: () => void;
}

/** Fetch execution result */
type FetchResult<T> =
	| { success: true; data: T; status: number; headers: Headers }
	| { success: false; error: ApiError };

// Environment and security configuration
const BASE_URL = process.env.BASE_URL || process.env.NEXT_PUBLIC_API_URL || '';
const IS_DEV = process.env.NODE_ENV === 'development';
const MAX_RESPONSE_SIZE_DEFAULT = 10 * 1024 * 1024; // 10MB
const MAX_REQUEST_BODY_SIZE_DEFAULT = 10 * 1024 * 1024; // 10MB

// Parse allowed hosts from environment (comma-separated)
const ENV_ALLOWED_HOSTS = (() => {
	const hostsEnv = process.env.ALLOWED_HOSTS || process.env.SAFEFETCH_ALLOWED_HOSTS;
	return (
		hostsEnv
			?.split(',')
			.map((h) => h.trim().toLowerCase())
			.filter((h) => h && /^[a-z0-9.-]+$/.test(h)) || []
	);
})();

// Consolidated configuration
const CONFIG = {
	security: {
		allowedProtocols: new Set(['http:', 'https:']),
		blockedHosts: new Set([
			'localhost',
			'127.0.0.1',
			'0.0.0.0',
			'169.254.169.254',
			'100.100.100.200',
			'metadata.google.internal',
			'metadata',
		]),
		blockedIpRanges: [
			/^10\./,
			/^172\.(1[6-9]|2[0-9]|3[01])\./,
			/^192\.168\./,
			/^::1$/,
			/^fe80:/,
			/^fc00:/,
		],
		maxUrlLength: 2048,
		maxHeaderLength: 8192,
		maxRedirects: 5, // Limit the number of redirects to prevent loops
	},
	retry: {
		codes: new Set([408, 429, 500, 502, 503, 504]),
		idempotentMethods: new Set<HttpMethod>(['GET', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']),
	},
} as const;

// Safe authentication setup
const AUTH_HEADER = (() => {
	try {
		const { AUTH_USERNAME, AUTH_PASSWORD, AUTH_TOKEN, API_TOKEN } = process.env;
		if (AUTH_USERNAME && AUTH_PASSWORD) {
			return `Basic ${Buffer.from(`${AUTH_USERNAME}:${AUTH_PASSWORD}`, 'utf8').toString('base64')}`;
		}
		const token = AUTH_TOKEN || API_TOKEN;
		return token && /^[A-Za-z0-9\-._~+/]+=*$/.test(token) ? `Bearer ${token}` : null;
	} catch (e) {
		if (IS_DEV) {
			console.warn('Failed to set AUTH_HEADER:', e);
		}
		return null;
	}
})();

/** Helper for creating ApiError to reduce repetition and control verbosity */
const createApiError = (
	name: string,
	message: string,
	status: number,
	attempt?: number,
	data?: unknown,
	devMessage?: string,
	originalError?: Error,
	contentType?: string,
): ApiError => {
	// Safely determine data type and size
	const getDataInfo = (data: unknown): { dataType: string; dataSizeBytes?: number } => {
		if (data === null) return { dataType: 'null' };
		if (data === undefined) return { dataType: 'undefined' };
		if (typeof data === 'string')
			return { dataType: 'string', dataSizeBytes: new TextEncoder().encode(data).length };
		if (typeof data === 'number') return { dataType: 'number' };
		if (typeof data === 'boolean') return { dataType: 'boolean' };
		if (typeof data === 'bigint') return { dataType: 'bigint' };
		if (typeof data === 'symbol') return { dataType: 'symbol' };
		if (data instanceof Blob) return { dataType: 'Blob', dataSizeBytes: data.size };
		if (data instanceof ArrayBuffer)
			return { dataType: 'ArrayBuffer', dataSizeBytes: data.byteLength };
		if (data instanceof FormData) return { dataType: 'FormData' };
		if (data instanceof ReadableStream) return { dataType: 'ReadableStream' };
		if (Array.isArray(data))
			return { dataType: 'Array', dataSizeBytes: JSON.stringify(data).length };
		if (typeof data === 'object')
			return { dataType: 'Object', dataSizeBytes: JSON.stringify(data).length };
		return { dataType: 'unknown' };
	};

	const { dataType, dataSizeBytes } = getDataInfo(data);

	return {
		name,
		message: IS_DEV && devMessage ? devMessage : message,
		status,
		attempt,
		data: data as ErrorData,
		...(IS_DEV && devMessage && { devMessage }),
		...(originalError && { originalError }),
		...(contentType && { contentType }),
		dataType,
		...(dataSizeBytes && { dataSizeBytes }),
	};
};

/**
 * Validates a URL for SSRF protection by checking protocols, blocked hosts/IPs,
 * allowed hosts, and URL structure.
 * @param url The URL string to validate.
 * @param allowedHosts Optional array of additional allowed host patterns.
 * @returns true if the URL is safe, false otherwise.
 */
const isUrlSafe = (url: string, allowedHosts?: string[]): boolean => {
	try {
		if (url.length > CONFIG.security.maxUrlLength) {
			if (IS_DEV) console.warn(`URL too long: ${url.length} > ${CONFIG.security.maxUrlLength}`);
			return false;
		}

		const parsed = new URL(url);
		const hostname = parsed.hostname.toLowerCase();

		// Protocol check
		if (!CONFIG.security.allowedProtocols.has(parsed.protocol)) {
			if (IS_DEV) console.warn(`Blocked protocol: ${parsed.protocol}`);
			return false;
		}

		// Direct blocked hosts check
		if (CONFIG.security.blockedHosts.has(hostname)) {
			if (IS_DEV) console.warn(`Blocked hostname: ${hostname}`);
			return false;
		}

		// IP address parsing and blocking (handles IPv4/IPv6 literals and their various forms)
		// Node.js URL parser normalizes IP addresses.
		// Example: new URL('http://0x7f000001').hostname === '127.0.0.1'
		// Example: new URL('http://[::1]').hostname === '::1'
		const isIpAddress =
			/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^\[(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\]$|^[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7}$/.test(
				hostname,
			) || hostname.includes(':'); // Simple check for IPv4/IPv6 format

		if (isIpAddress && CONFIG.security.blockedIpRanges.some((range) => range.test(hostname))) {
			if (IS_DEV) console.warn(`Blocked IP range: ${hostname}`);
			return false;
		}

		// Allowed hosts check
		const allAllowed = [...ENV_ALLOWED_HOSTS, ...(allowedHosts?.map((h) => h.toLowerCase()) || [])];

		// If allowedHosts are specified, ensure the hostname matches one of them
		if (
			allAllowed.length > 0 &&
			!allAllowed.some((h) => hostname === h || hostname.endsWith(`.${h}`))
		) {
			if (IS_DEV) console.warn(`Hostname not in allowed list: ${hostname}`);
			return false;
		}

		// No credentials, standard ports only
		const isSafePort = !parsed.port || ['80', '443', ''].includes(parsed.port);
		if (!isSafePort) {
			if (IS_DEV) console.warn(`Blocked port: ${parsed.port}`);
			return false;
		}

		if (parsed.username || parsed.password) {
			if (IS_DEV) console.warn('URL contains credentials');
			return false;
		}

		return true;
	} catch (e) {
		if (IS_DEV) console.warn('isUrlSafe validation failed:', e);
		return false;
	}
};

/**
 * Builds a secure URL, validates it for SSRF, and appends query parameters.
 * @param endpoint The API endpoint or full URL.
 * @param params Optional query parameters.
 * @param allowedHosts Optional list of additional allowed hosts for SSRF protection.
 * @returns The fully constructed and validated URL string.
 * @throws Error if the URL is unsafe or BASE_URL is missing for relative paths.
 */
const buildUrl = (endpoint: string, params?: QueryParams, allowedHosts?: string[]): string => {
	let finalUrl: URL;

	if (endpoint.startsWith('http://') || endpoint.startsWith('https://')) {
		if (!isUrlSafe(endpoint, allowedHosts)) throw new Error('URL not allowed: potential SSRF risk');
		finalUrl = new URL(endpoint);
	} else {
		if (!BASE_URL) throw new Error('BASE_URL required for relative paths');
		const basePath = BASE_URL.endsWith('/') ? BASE_URL : `${BASE_URL}/`;
		const fullUrl = endpoint.startsWith('/')
			? new URL(endpoint, BASE_URL).toString()
			: new URL(endpoint, basePath).toString();

		if (!isUrlSafe(fullUrl, allowedHosts)) throw new Error('URL not allowed: potential SSRF risk');
		finalUrl = endpoint.startsWith('/') ? new URL(endpoint, BASE_URL) : new URL(endpoint, basePath);
	}

	// Add sanitized query parameters using URLSearchParams
	if (params) {
		Object.entries(params).forEach(([key, value]) => {
			if (value != null) {
				// Sanitize key and value to prevent injection/oversized params
				const sanitizedKey = key.replace(/[^\w\-_.]/g, '').substring(0, 100);
				const sanitizedValue = String(value)
					.substring(0, 1000)
					// biome-ignore lint/suspicious/noControlCharactersInRegex: <needed>
					.replace(/[\x00-\x1f\x7f-\x9f]/g, ''); // Remove control characters

				if (sanitizedKey && sanitizedValue) {
					finalUrl.searchParams.append(sanitizedKey, sanitizedValue);
				} else if (IS_DEV && (!sanitizedKey || !sanitizedValue)) {
					console.warn(`Skipping malformed query parameter: ${key}=${value}`);
				}
			}
		});
	}

	return finalUrl.toString();
};

/**
 * Builds request headers, applying default content types, authorization,
 * and sanitizing custom headers to prevent injection.
 * @param data The request body, used to infer Content-Type.
 * @param custom Custom headers provided by the user.
 * @returns HeadersInit object ready for fetch.
 */
const buildHeaders = (data?: RequestBody, custom?: Record<string, string>): HeadersInit => {
	const headers: Record<string, string> = {};

	// Sanitize custom headers
	if (custom) {
		Object.entries(custom).forEach(([key, value]) => {
			// Validate header key against RFC 7230 (field-name)
			if (/^[!#$%&'*+\-.0-9A-Z^_`a-z|~]+$/.test(key)) {
				// Sanitize header value: remove control characters including CR/LF

				const sanitizedValue = value
					// biome-ignore lint/suspicious/noControlCharactersInRegex: <needed>
					.replace(/[\x00-\x1f\x7f-\xff\r\n]/g, '') // Explicitly remove CR/LF
					.substring(0, CONFIG.security.maxHeaderLength);
				if (sanitizedValue) headers[key] = sanitizedValue;
				else if (IS_DEV) console.warn(`Skipping empty or invalid header value for key: ${key}`);
			} else if (IS_DEV) {
				console.warn(`Skipping invalid header key: ${key}`);
			}
		});
	}

	if (AUTH_HEADER) headers.Authorization = AUTH_HEADER;
	if (
		data &&
		!(data instanceof FormData) &&
		!(data instanceof Blob) &&
		!(data instanceof ArrayBuffer)
	) {
		headers['Content-Type'] = 'application/json';
	}
	if (!headers.Accept) headers.Accept = 'application/json, text/plain, */*';

	return headers;
};

/**
 * Parses the response body, applying size limits and intelligently handling
 * different content types (JSON, text).
 * @template T The expected type of the response data.
 * @param response The raw Response object from fetch.
 * @param maxSize The maximum allowed response size in bytes.
 * @returns A Promise resolving to the parsed response data.
 * @throws Error if response is too large, or JSON parsing fails.
 */
const parseResponse = async <T>(response: Response, maxSize: number): Promise<T> => {
	const contentType = response.headers.get('content-type') || '';
	const contentLength = response.headers.get('content-length');

	if (contentLength && parseInt(contentLength, 10) > maxSize) {
		throw new Error(`Response too large: ${contentLength} bytes (max: ${maxSize})`, {
			cause: 'PayloadTooLarge',
		});
	}

	// Handle different content types appropriately
	if (contentType.includes('application/json')) {
		const text = await response.text();
		if (text.length > maxSize) {
			throw new Error(`Response too large: ${text.length} bytes (max: ${maxSize})`, {
				cause: 'PayloadTooLarge',
			});
		}
		try {
			return JSON.parse(text) as T;
		} catch (error) {
			throw new Error(
				`Invalid JSON response: ${error instanceof Error ? error.message : String(error)}`,
				{ cause: 'InvalidJson' },
			);
		}
	}

	if (contentType.includes('application/octet-stream') || contentType.includes('application/pdf')) {
		return response.arrayBuffer() as Promise<T>;
	}

	if (contentType.includes('multipart/form-data')) {
		return response.formData() as Promise<T>;
	}

	if (
		contentType.includes('image/') ||
		contentType.includes('video/') ||
		contentType.includes('audio/')
	) {
		return response.blob() as Promise<T>;
	}

	// Default to text for other content types
	const reader = response.body?.getReader();
	if (!reader) return '' as T;

	const chunks: Uint8Array[] = [];
	let totalSize = 0;

	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;

			totalSize += value.length;
			if (totalSize > maxSize)
				throw new Error(`Response too large: exceeded ${maxSize} bytes`, {
					cause: 'PayloadTooLarge',
				});
			chunks.push(value);
		}

		const combined = new Uint8Array(totalSize);
		let offset = 0;
		for (const chunk of chunks) {
			combined.set(chunk, offset);
			offset += chunk.length;
		}

		const text = new TextDecoder('utf-8', { fatal: false }).decode(combined);

		// Try to parse as JSON if it looks like JSON
		if (/^\s*[{[]/.test(text.trim())) {
			try {
				return JSON.parse(text) as T;
			} catch {
				// If JSON parsing fails, return as text
				return text as T;
			}
		}

		return text as T;
	} catch (error) {
		if (
			error instanceof Error &&
			(error.message.includes('too large') || error.cause === 'PayloadTooLarge')
		) {
			throw error;
		}
		if (error instanceof Error && error.cause === 'InvalidJson') {
			throw error;
		}
		throw new Error('Failed to read or parse response body', { cause: error });
	}
};

/**
 * Creates an AbortController with a timeout and a cleanup function.
 * @param ms The timeout duration in milliseconds.
 * @returns A TimeoutController object.
 */
const createTimeout = (ms: number): TimeoutController => {
	const controller = new AbortController();
	let cleaned = false;
	const id = setTimeout(() => {
		if (!cleaned) controller.abort();
	}, ms);
	return {
		controller,
		cleanup: () => {
			if (!cleaned) {
				cleaned = true;
				clearTimeout(id);
			}
		},
	};
};

/**
 * Implements exponential backoff with jitter for retries.
 * @param attempt The current retry attempt number.
 * @returns A Promise that resolves after the calculated delay.
 */
const delay = (attempt: number): Promise<void> => {
	// Max delay of 10 seconds
	const baseMs = Math.min(1000 * 2 ** attempt, 10000);
	const jitter = baseMs * 0.25 * (Math.random() - 0.5); // +/- 12.5% jitter
	const finalMs = Math.max(100, Math.min(baseMs + jitter, 10000)); // Min 100ms, Max 10s
	return new Promise((resolve) => setTimeout(resolve, finalMs));
};

/**
 * Determines if a request should be retried based on error, attempt, method, and custom conditions.
 * @param error The ApiError that occurred.
 * @param attempt The current attempt number (0-indexed).
 * @param maxRetries The maximum number of retries allowed.
 * @param method The HTTP method used for the request.
 * @param customRetry An optional custom function to determine retryability.
 * @returns true if the request should be retried, false otherwise.
 */
const shouldRetryRequest = (
	error: ApiError,
	attempt: number,
	maxRetries: number,
	method: HttpMethod,
	customRetry?: (error: ApiError, attempt: number) => boolean,
): boolean => {
	if (customRetry) {
		try {
			return attempt < maxRetries && customRetry(error, attempt);
		} catch (e) {
			if (IS_DEV) console.error('Custom shouldRetry function threw an error:', e);
			return false; // If custom retry logic fails, don't retry
		}
	}

	// Default retry logic for idempotent methods and specific error types
	return (
		attempt < maxRetries &&
		CONFIG.retry.idempotentMethods.has(method) &&
		(error.name === 'AbortError' ||
			error.name === 'TimeoutError' ||
			CONFIG.retry.codes.has(error.status) ||
			/network|fetch|connection|dns/i.test(error.message)) // Added 'dns' for network errors
	);
};

/**
 * Logs inferred TypeScript types for development debugging.
 * @param endpoint The API endpoint.
 * @param data The data from which to infer types.
 */
const logTypes = (
	endpoint: string,
	data: unknown,
	prefix = '',
	options?: LogTypesOptions,
): void => {
	if (!IS_DEV) return;

	const {
		maxDepth = 20,
		maxProperties = 50,
		maxArrayItems = 10,
		showPropertyCount = false,
	} = options || {};

	const inferType = (val: unknown, depth = 0, path = ''): string => {
		if (depth > maxDepth) return 'unknown /* depth exceeded */';
		if (val === null) return 'null';
		if (val === undefined) return 'undefined';

		if (Array.isArray(val)) {
			if (val.length === 0) return 'unknown[]';
			const sampleSize = Math.min(val.length, maxArrayItems);
			const firstType = inferType(val[0], depth + 1, `${path}[0]`);
			const allSameBasicType = val
				.slice(0, sampleSize)
				.every((item) => typeof item === typeof val[0] || (item === null && val[0] === null));
			const ellipsis =
				showPropertyCount && val.length > sampleSize
					? ` /* +${val.length - sampleSize} more items */`
					: '';
			return allSameBasicType
				? `${firstType}[]${ellipsis}`
				: `Array<${firstType} | unknown>${ellipsis}`;
		}

		if (typeof val === 'object' && val !== null) {
			const obj = val as Record<string, unknown>;
			const entries = Object.entries(obj);
			const displayEntries = entries.slice(0, maxProperties);

			const props = displayEntries
				.map(([k, v]) => {
					const keyPath = path ? `${path}.${k}` : k;
					const valueType = /password|token|secret|key|auth/i.test(k)
						? 'string /* redacted */'
						: inferType(v, depth + 1, keyPath);
					return `    ${JSON.stringify(k)}: ${valueType};`;
				})
				.join('\n');

			const ellipsis =
				showPropertyCount && entries.length > maxProperties
					? `\n    // ... +${entries.length - maxProperties} more properties`
					: entries.length > maxProperties
						? '\n    // ... more properties'
						: '';

			return `{\n${props}${ellipsis}\n}`;
		}

		return typeof val;
	};

	try {
		const typeName = (prefix + endpoint)
			.replace(/[^a-zA-Z0-9]/g, '_')
			.replace(/^_+|_+$/g, '')
			.replace(/_{2,}/g, '_')
			.replace(/^(\d)/, '_$1');
		const inferred = inferType(data);
		console.log(`🔍 ${prefix}Inferred Type for "${endpoint}"`);
		console.log(`type ${typeName}Type = ${inferred};`);

		// Log common error properties if they exist
		if (data && typeof data === 'object' && !Array.isArray(data)) {
			const obj = data as Record<string, unknown>;
			if ('error' in obj) {
				console.log(`// Error message type: ${typeof obj.error}`);
				if (typeof obj.error === 'string') {
					console.log(`// Error: "${obj.error}"`);
				}
			}
			if ('message' in obj) {
				console.log(`// Message type: ${typeof obj.message}`);
				if (typeof obj.message === 'string') {
					console.log(`// Message: "${obj.message}"`);
				}
			}
		}
	} catch (err) {
		console.warn('[logTypes] Failed to infer types:', err);
	}
};

/**
 * Prepares the request body for fetch, handling different types and applying size limits.
 * @param data The request body data.
 * @param maxSize The maximum allowed request body size in bytes.
 * @returns The prepared BodyInit or undefined.
 * @throws Error if the request body is too large.
 */
const prepareRequestBody = (
	data: RequestBody | undefined,
	maxSize: number,
): BodyInit | undefined => {
	if (data == null) return undefined;

	if (data instanceof FormData || data instanceof Blob || data instanceof ArrayBuffer) {
		// For these types, size check is harder without reading the entire stream.
		// Rely on network layer or server to handle extreme sizes.
		return data;
	}

	if (typeof data === 'string') {
		if (new TextEncoder().encode(data).length > maxSize) {
			// Check byte length for strings
			throw new Error('Request body too large (string)', { cause: 'PayloadTooLarge' });
		}
		return data;
	}

	// Assume it's Record<string, unknown> and stringify
	const jsonString = JSON.stringify(data);
	if (new TextEncoder().encode(jsonString).length > maxSize) {
		// Check byte length for JSON
		throw new Error('Request body too large (JSON)', { cause: 'PayloadTooLarge' });
	}
	return jsonString;
};

/**
 * Builds Next.js specific options for fetch.
 * @param revalidate ISR revalidation time.
 * @param tags Cache tags for on-demand revalidation.
 * @returns An object containing Next.js fetch options.
 */
const buildNextOptions = (revalidate?: number | false, tags?: string[]): { next?: NextOptions } => {
	if (revalidate === undefined && (!tags || tags.length === 0)) {
		return {};
	}

	const nextOptions: NextOptions = {};

	if (revalidate !== undefined) {
		nextOptions.revalidate = revalidate;
	}

	if (tags && tags.length > 0) {
		nextOptions.tags = tags.filter(
			(tag) =>
				typeof tag === 'string' &&
				tag.length > 0 &&
				tag.length <= 100 &&
				/^[a-zA-Z0-9\-_]+$/.test(tag), // Ensure tags are safe for file systems/URLs
		);
	}

	return { next: nextOptions };
};

/**
 * Executes a single fetch attempt, handling redirects manually for SSRF protection.
 * @template TResponse The expected response data type.
 * @param initialUrl The initial URL to fetch.
 * @param method The HTTP method.
 * @param headers The request headers.
 * @param body The request body.
 * @param cache The cache strategy.
 * @param timeout The request timeout.
 * @param maxResponseSize The maximum allowed response size.
 * @param nextOptions Next.js specific options.
 * @param attempt The current attempt number.
 * @returns A Promise resolving to FetchResult.
 */
const executeFetch = async <TResponse>(
	initialUrl: string,
	method: HttpMethod,
	headers: HeadersInit,
	body: BodyInit | undefined,
	cache: RequestCache,
	timeout: number,
	maxResponseSize: number,
	nextOptions: { next?: NextOptions },
	attempt: number,
): Promise<FetchResult<TResponse>> => {
	let currentUrl = initialUrl;
	let redirectCount = 0;
	let response: Response;
	let currentResponseStatus = 500;
	let timeoutController: TimeoutController | null = null;
	let responseContentType: string | null = null;

	try {
		while (true) {
			if (redirectCount > CONFIG.security.maxRedirects) {
				throw new Error('Too many redirects', { cause: 'TooManyRedirects' });
			}

			timeoutController = createTimeout(timeout);
			response = await fetch(currentUrl, {
				method,
				headers,
				body,
				cache,
				signal: timeoutController.controller.signal,
				redirect: 'manual', // Crucial for manual redirect handling and SSRF protection
				...nextOptions,
			});
			timeoutController.cleanup();
			timeoutController = null; // Clear reference

			currentResponseStatus = response.status;
			responseContentType = response.headers.get('content-type');

			// Handle redirects (3xx status codes)
			if (response.status >= 300 && response.status < 400 && response.headers.has('Location')) {
				const redirectUrl = response.headers.get('Location')!;
				const resolvedRedirectUrl = new URL(redirectUrl, currentUrl).toString(); // Resolve relative redirects

				if (!isUrlSafe(resolvedRedirectUrl)) {
					throw new Error('Redirect URL not allowed: potential SSRF risk', {
						cause: 'SecurityError',
					});
				}

				currentUrl = resolvedRedirectUrl;
				redirectCount++;
			} else {
				// Not a redirect, or no Location header, so break and process response
				break;
			}
		}

		// Process final response
		const responseData = await parseResponse<TResponse>(response, maxResponseSize);

		if (response.ok) {
			return {
				success: true,
				data: responseData,
				status: response.status,
				headers: response.headers,
			};
		}

		// HTTP error response - now with enhanced error data and automatic type logging
		const errorData = responseData;

		// Always log types for error responses in development
		if (IS_DEV) {
			logTypes(currentUrl, errorData, 'Error_');
		}

		return {
			success: false,
			error: createApiError(
				'HttpError',
				`HTTP ${response.status} Error`,
				response.status,
				attempt,
				errorData, // This can now be any type
				`HTTP ${response.status} error for URL: ${currentUrl}`,
				undefined,
				responseContentType || undefined,
			),
		};
	} catch (err) {
		timeoutController?.cleanup(); // Ensure cleanup if error occurs before response is received

		const originalError = err instanceof Error ? err : new Error(String(err));

		// Determine specific error type with enhanced error data
		if (err instanceof Error) {
			if (err.name === 'AbortError' || err.message.includes('timeout')) {
				return {
					success: false,
					error: createApiError(
						'TimeoutError',
						`Request timeout after ${timeout}ms`,
						408,
						attempt,
						null,
						`Request to ${currentUrl} timed out after ${timeout}ms`,
						originalError,
						responseContentType || undefined,
					),
				};
			}
			if (err.message.includes('too large') || err.cause === 'PayloadTooLarge') {
				return {
					success: false,
					error: createApiError(
						'PayloadTooLargeError',
						'Response or request body too large',
						413,
						attempt,
						null,
						`Payload too large for URL: ${currentUrl}`,
						originalError,
						responseContentType || undefined,
					),
				};
			}
			if (
				err.message.includes('not allowed') ||
				err.message.includes('SSRF') ||
				err.cause === 'SecurityError'
			) {
				return {
					success: false,
					error: createApiError(
						'SecurityError',
						'Request blocked for security reasons',
						403,
						attempt,
						null,
						`Security error for URL: ${currentUrl} - ${err.message}`,
						originalError,
						responseContentType || undefined,
					),
				};
			}
			if (err.cause === 'TooManyRedirects') {
				return {
					success: false,
					error: createApiError(
						'TooManyRedirectsError',
						'Too many redirects',
						400, // Or 500, depending on how you classify this
						attempt,
						null,
						`Exceeded max redirects (${CONFIG.security.maxRedirects}) for URL: ${currentUrl}`,
						originalError,
						responseContentType || undefined,
					),
				};
			}
			if (err.cause === 'InvalidJson') {
				return {
					success: false,
					error: createApiError(
						'ParseError',
						'Invalid JSON response',
						currentResponseStatus,
						attempt,
						null,
						`Failed to parse JSON response from ${currentUrl}: ${err.message}`,
						originalError,
						responseContentType || undefined,
					),
				};
			}
			// Catch other network-related errors
			if (
				err.message.includes('network') ||
				err.message.includes('fetch') ||
				err.message.includes('connection') ||
				(err as NodeJS.ErrnoException).code
			) {
				return {
					success: false,
					error: createApiError(
						'NetworkError',
						'Network request failed',
						500,
						attempt,
						null,
						`Network error for URL: ${currentUrl} - ${err.message} (Code: ${(err as NodeJS.ErrnoException).code || 'N/A'})`,
						originalError,
						responseContentType || undefined,
					),
				};
			}
			// Fallback for any other unexpected errors
			return {
				success: false,
				error: createApiError(
					'UnknownError',
					'An unexpected error occurred',
					currentResponseStatus,
					attempt,
					null,
					`An unknown error occurred for URL: ${currentUrl} - ${err.message}`,
					originalError,
					responseContentType || undefined,
				),
			};
		}

		// If error is not an instance of Error
		return {
			success: false,
			error: createApiError(
				'UnknownError',
				'An unexpected error occurred',
				currentResponseStatus,
				attempt,
				null,
				`An unknown non-Error type was thrown for URL: ${currentUrl}`,
				originalError,
				responseContentType || undefined,
			),
		};
	}
};

/**
 * API request function with comprehensive TypeScript support, retry, timeout,
 * and enhanced security features including SSRF protection against redirects.
 *
 * @template TResponse - Expected response data type (before transformation).
 * @template TBody - Request body type.
 * @template TTransformedResponse - Expected response data type after transformation.
 * @param method - HTTP method.
 * @param endpoint - API endpoint path or full URL.
 * @param options - Request configuration.
 * @returns Promise resolving to typed ApiResponse.
 *
 * @example
 * ```typescript
 * // Simple GET
 * const users = await apiRequest<User[]>('GET', '/users');
 *
 * // POST with full configuration and transformation
 * interface CreateUserData { name: string; email: string; }
 * interface CreateApiResponse { id: string; status: string; }
 * interface TransformedCreateResponse { userId: string; timestamp: number; }
 *
 * const result = await apiRequest<CreateApiResponse, CreateUserData, TransformedCreateResponse>('POST', '/users', {
 * data: { name: 'John', email: 'john@example.com' },
 * params: { userId: 123, status: 'active' },
 * retries: 3,
 * timeout: 5000,
 * cache: "force-cache",
 * revalidate: 60,
 * tags:["id", "users"],
 * headers: { 'X-Custom-Header': 'foobar' },
 * shouldRetry: (error, attempt) => error.status === 503 && attempt < 2,
 * onError: (error, attempt) => console.warn(`Retry ${attempt}:`, error),
 * transform: (data) => ({ userId: data.id, timestamp: Date.now() }),
 * logTypes: true,
 * allowedHosts: ['api.example.com'],
 * maxResponseSize: 5 * 1024 * 1024,
 * maxRequestBodySize: 2 * 1024 * 1024 // New: Max request body size
 * });
 *
 * if (apiRequest.isSuccess(result)) {
 * console.log(result.data.userId); // result.data is of type TransformedCreateResponse
 * }
 *
 * // Environment configuration:
 * // ALLOWED_HOSTS=api.example.com,cdn.example.com
 * // SAFEFETCH_ALLOWED_HOSTS=secure-api.com
 * ```
 */
export default async function apiRequest<
	TResponse = unknown, // Original response type from API
	TBody extends RequestBody = RequestBody,
	TTransformedResponse = TResponse, // Transformed response type
>(
	method: HttpMethod,
	endpoint: string,
	options: RequestOptions<TBody, TTransformedResponse> = {},
): Promise<ApiResponse<TTransformedResponse>> {
	const {
		data,
		params,
		retries = 1,
		timeout = 30000,
		cache = 'default',
		revalidate,
		tags = [],
		headers: customHeaders,
		logTypes: logTypesOption = false,
		transform,
		onError,
		shouldRetry: customShouldRetry,
		allowedHosts,
		maxResponseSize = MAX_RESPONSE_SIZE_DEFAULT,
		maxRequestBodySize = MAX_REQUEST_BODY_SIZE_DEFAULT, // New option
	} = options;

	const handleLogTypes = (endpoint: string, data: unknown, prefix = ''): void => {
		if (!logTypesOption) return;

		if (typeof logTypesOption === 'boolean') {
			// Use default options when logTypes is true
			logTypes(endpoint, data, prefix);
		} else {
			// Use provided options when logTypes is an object
			logTypes(endpoint, data, prefix, logTypesOption);
		}
	};

	// Input validation
	if (retries < 0 || retries > 10) {
		const error = createApiError(
			'ValidationError',
			'Retries must be between 0 and 10',
			400,
			undefined,
			null,
			'Invalid retries option',
		);
		return { success: false, status: 400, error, data: null };
	}
	if (timeout < 1000 || timeout > 300000) {
		const error = createApiError(
			'ValidationError',
			'Timeout must be between 1s and 5 minutes',
			400,
			undefined,
			null,
			'Invalid timeout option',
		);
		return { success: false, status: 400, error, data: null };
	}
	if (maxResponseSize < 1024 || maxResponseSize > 100 * 1024 * 1024) {
		const error = createApiError(
			'ValidationError',
			'Max response size must be between 1KB and 100MB',
			400,
			undefined,
			null,
			'Invalid maxResponseSize option',
		);
		return { success: false, status: 400, error, data: null };
	}
	if (maxRequestBodySize < 1024 || maxRequestBodySize > 100 * 1024 * 1024) {
		const error = createApiError(
			'ValidationError',
			'Max request body size must be between 1KB and 100MB',
			400,
			undefined,
			null,
			'Invalid maxRequestBodySize option',
		);
		return { success: false, status: 400, error, data: null };
	}

	// Prepare request components
	let url: string, headers: HeadersInit, body: BodyInit | undefined;
	try {
		url = buildUrl(endpoint, params, allowedHosts);
		headers = buildHeaders(data, customHeaders);
		body = prepareRequestBody(data, maxRequestBodySize); // Use maxRequestBodySize here
	} catch (error) {
		const apiError = createApiError(
			'ValidationError',
			'Request validation failed',
			400,
			undefined,
			null,
			error instanceof Error
				? `Request validation failed: ${error.message}`
				: 'Request validation failed with unknown error',
		);
		return { success: false, status: 400, error: apiError, data: null };
	}

	// Next.js options
	const nextOptions = buildNextOptions(revalidate, tags);

	let lastError: ApiError = createApiError(
		'UnknownError',
		'Request failed',
		500,
		undefined,
		null,
		'Initial unknown error before fetch attempt',
	);

	// Retry loop
	for (let attempt = 0; attempt <= retries; attempt++) {
		const result = await executeFetch<TResponse>(
			// TResponse is the type *before* transformation
			url,
			method,
			headers,
			body,
			cache,
			timeout,
			maxResponseSize,
			nextOptions,
			attempt,
		);

		if (result.success) {
			let finalData: TTransformedResponse; // Use TTransformedResponse here
			try {
				// Apply transformation if provided, otherwise cast to TTransformedResponse (which defaults to TResponse)
				finalData = transform
					? transform(result.data)
					: (result.data as unknown as TTransformedResponse);
			} catch (error) {
				lastError = createApiError(
					'TransformError',
					'Response transformation failed',
					result.status,
					attempt,
					null,
					`Response transformation failed for URL: ${url}. Error: ${error instanceof Error ? error.message : String(error)}`,
				);
				onError?.(lastError, attempt);
				return {
					success: false,
					status: result.status,
					error: lastError,
					data: null,
				};
			}

			handleLogTypes(endpoint, finalData);

			return {
				success: true,
				status: result.status,
				data: finalData,
				headers: result.headers,
			};
		}

		lastError = result.error;
		onError?.(lastError, attempt);

		if (!shouldRetryRequest(lastError, attempt, retries, method, customShouldRetry)) break;
		await delay(attempt);
	}

	return {
		success: false,
		status: lastError.status,
		error: lastError,
		data: null,
	};
}

/**
 * Type guard for successful responses
 *
 * @example
 * const res = await apiRequest('GET', '/users');
 * if (apiRequest.isSuccess(res)) {
 * // Safe access to res.data
 * } else {
 * console.error(res.error);
 * }
 */
apiRequest.isSuccess = <T>(
	response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: true }> => response.success;

/**
 * Type guard for error responses
 *
 * @example
 * const res = await apiRequest('GET', '/users');
 * if (apiRequest.isError(res)) {
 * console.error(res.error);
 * }
 */
apiRequest.isError = <T>(
	response: ApiResponse<T>,
): response is Extract<ApiResponse<T>, { success: false }> => !response.success;
