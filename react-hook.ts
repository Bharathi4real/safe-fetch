/**
 * SafeFetch Enhanced – Complete Next.js Integration
 * Includes React hooks, Server Actions, Route Handlers, and Middleware
 * New features: Request deduplication, Loading states, Optimistic updates
 * (c) 2025 Bharathi4real – BSD 3-Clause License
 */

"use server";

import { revalidatePath, revalidateTag } from "next/cache";
import { redirect } from "next/navigation";
import { type NextRequest, NextResponse } from "next/server";
import { useCallback, useEffect, useRef, useState, useMemo } from "react";

// ==================== CORE TYPES ====================

export interface EnvConfig {
	authUsername?: string;
	authPassword?: string;
	authToken?: string;
	baseUrl?: string;
	allowBasicAuthInProd?: string;
}

const DEFAULT_ENV_CONFIG: Required<EnvConfig> = {
	authUsername: "AUTH_USERNAME",
	authPassword: "AUTH_PASSWORD",
	authToken: "AUTH_TOKEN",
	baseUrl: "BASE_URL",
	allowBasicAuthInProd: "ALLOW_BASIC_AUTH_IN_PROD",
};

const createEnv = (envConfig: EnvConfig = {}) => {
	if (typeof window !== "undefined") return {};
	const config = { ...DEFAULT_ENV_CONFIG, ...envConfig };
	return {
		AUTH_USERNAME: process.env[config.authUsername]?.trim(),
		AUTH_PASSWORD: process.env[config.authPassword]?.trim(),
		AUTH_TOKEN: process.env[config.authToken]?.trim(),
		BASE_URL: process.env[config.baseUrl]?.trim() || "",
		ALLOW_BASIC_AUTH_IN_PROD:
			process.env[config.allowBasicAuthInProd] === "true",
	};
};

const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;
export type HttpMethod = (typeof HTTP_METHODS)[number];

const STATUS = {
	OK: 200,
	CREATED: 201,
	NO_CONTENT: 204,
	BAD_REQUEST: 400,
	UNAUTHORIZED: 401,
	FORBIDDEN: 403,
	NOT_FOUND: 404,
	METHOD_NOT_ALLOWED: 405,
	REQUEST_TIMEOUT: 408,
	PAYLOAD_TOO_LARGE: 413,
	RATE_LIMITED: 429,
	INTERNAL_ERROR: 500,
	SERVICE_UNAVAILABLE: 503,
} as const;

export type StatusCode = (typeof STATUS)[keyof typeof STATUS];

export type ErrorType =
	| "VALIDATION_ERROR"
	| "AUTH_ERROR"
	| "RATE_LIMIT_ERROR"
	| "NETWORK_ERROR"
	| "TIMEOUT_ERROR"
	| "SERVER_ERROR";

export interface ApiError extends Error {
	status: StatusCode;
	type: ErrorType;
	message: string;
	timestamp: string;
	requestId: string;
	details?: Record<string, unknown>;
}

export type CacheOption = "force-cache" | "no-store" | "no-cache" | "default";

export type QueryValue = string | number | boolean | null | undefined;
export type QueryParams = Record<string, QueryValue>;

export interface ClientConfig {
	baseUrl: string;
	authHeader?: string;
}

export interface RequestOptions<TData = unknown> {
	data?: TData;
	query?: QueryParams;
	cache?: CacheOption;
	revalidate?: number | false;
	revalidateTags?: string[];
	revalidatePaths?: string[];
	revalidateType?: "page" | "layout";
	timeout?: number;
	retryAttempts?: number;
	retryDelay?: number;
	retryMultiplier?: number;
	csrfToken?: string;
	logTypes?: boolean;
	customHeaders?: Record<string, string>;
	clientConfig?: ClientConfig;
	deduplicate?: boolean;
}

export type ApiResponse<T> =
	| {
			success: true;
			data: T;
			status: StatusCode;
			headers: Record<string, string>;
			requestId: string;
	  }
	| {
			success: false;
			error: ApiError;
			data: null;
	  };

// ==================== LOADING STATES MANAGEMENT ====================

export interface LoadingState {
	isLoading: boolean;
	loadingType: 'initial' | 'refetch' | 'mutate' | 'background';
	progress?: number;
}

export interface GlobalLoadingState {
	requests: Map<string, LoadingState>;
	globalLoading: boolean;
}

class LoadingStateManager {
	private state: GlobalLoadingState = {
		requests: new Map(),
		globalLoading: false,
	};
	private listeners = new Set<(state: GlobalLoadingState) => void>();

	subscribe(listener: (state: GlobalLoadingState) => void) {
		this.listeners.add(listener);
		return () => this.listeners.delete(listener);
	}

	private notify() {
		this.listeners.forEach(listener => listener({ ...this.state }));
	}

	startLoading(requestId: string, type: LoadingState['loadingType'] = 'initial') {
		this.state.requests.set(requestId, { isLoading: true, loadingType: type });
		this.state.globalLoading = this.state.requests.size > 0;
		this.notify();
	}

	updateProgress(requestId: string, progress: number) {
		const existing = this.state.requests.get(requestId);
		if (existing) {
			this.state.requests.set(requestId, { ...existing, progress });
			this.notify();
		}
	}

	stopLoading(requestId: string) {
		this.state.requests.delete(requestId);
		this.state.globalLoading = this.state.requests.size > 0;
		this.notify();
	}

	getState(): GlobalLoadingState {
		return { ...this.state };
	}

	isLoading(requestId?: string): boolean {
		if (requestId) {
			return this.state.requests.get(requestId)?.isLoading || false;
		}
		return this.state.globalLoading;
	}
}

export const loadingManager = new LoadingStateManager();

// ==================== REQUEST DEDUPLICATION ====================

interface PendingRequest<T> {
	promise: Promise<ApiResponse<T>>;
	timestamp: number;
	abortController: AbortController;
}

class RequestDeduplicator {
	private pendingRequests = new Map<string, PendingRequest<unknown>>();
	private readonly TTL = 5000; // 5 seconds

	private createKey(method: HttpMethod, url: string, data?: unknown): string {
		const dataHash = data ? JSON.stringify(data) : '';
		return `${method}:${url}:${dataHash}`;
	}

	private cleanup() {
		const now = Date.now();
		for (const [key, request] of this.pendingRequests.entries()) {
			if (now - request.timestamp > this.TTL) {
				request.abortController.abort();
				this.pendingRequests.delete(key);
			}
		}
	}

	async deduplicate<T>(
		method: HttpMethod,
		url: string,
		data: unknown,
		executor: (abortController: AbortController) => Promise<ApiResponse<T>>
	): Promise<ApiResponse<T>> {
		const key = this.createKey(method, url, data);
		
		// Clean up expired requests
		this.cleanup();

		// Check for existing request
		const existing = this.pendingRequests.get(key) as PendingRequest<T> | undefined;
		if (existing) {
			return existing.promise;
		}

		// Create new request
		const abortController = new AbortController();
		const promise = executor(abortController).finally(() => {
			this.pendingRequests.delete(key);
		});

		this.pendingRequests.set(key, {
			promise,
			timestamp: Date.now(),
			abortController,
		});

		return promise;
	}

	abort(method: HttpMethod, url: string, data?: unknown) {
		const key = this.createKey(method, url, data);
		const request = this.pendingRequests.get(key);
		if (request) {
			request.abortController.abort();
			this.pendingRequests.delete(key);
		}
	}

	clear() {
		for (const request of this.pendingRequests.values()) {
			request.abortController.abort();
		}
		this.pendingRequests.clear();
	}
}

export const requestDeduplicator = new RequestDeduplicator();

// ==================== OPTIMISTIC UPDATES ====================

export interface OptimisticUpdate<T> {
	id: string;
	data: T;
	timestamp: number;
	type: 'create' | 'update' | 'delete';
	rollback: () => void;
}

class OptimisticManager<T = unknown> {
	private updates = new Map<string, OptimisticUpdate<T>>();
	private listeners = new Set<(updates: OptimisticUpdate<T>[]) => void>();

	subscribe(listener: (updates: OptimisticUpdate<T>[]) => void) {
		this.listeners.add(listener);
		return () => this.listeners.delete(listener);
	}

	private notify() {
		const updates = Array.from(this.updates.values());
		this.listeners.forEach(listener => listener(updates));
	}

	add(update: Omit<OptimisticUpdate<T>, 'timestamp'>): string {
		const fullUpdate: OptimisticUpdate<T> = {
			...update,
			timestamp: Date.now(),
		};
		this.updates.set(update.id, fullUpdate);
		this.notify();
		return update.id;
	}

	remove(id: string) {
		this.updates.delete(id);
		this.notify();
	}

	rollback(id: string) {
		const update = this.updates.get(id);
		if (update) {
			update.rollback();
			this.remove(id);
		}
	}

	rollbackAll() {
		for (const update of this.updates.values()) {
			update.rollback();
		}
		this.updates.clear();
		this.notify();
	}

	getUpdates(): OptimisticUpdate<T>[] {
		return Array.from(this.updates.values());
	}

	clear() {
		this.updates.clear();
		this.notify();
	}
}

export const optimisticManager = new OptimisticManager();

// ==================== TESTING UTILITIES ====================

export interface MockResponse<T = unknown> {
	data?: T;
	status?: StatusCode;
	error?: Partial<ApiError>;
	delay?: number;
	headers?: Record<string, string>;
}

class MockManager {
	private mocks = new Map<string, MockResponse>();
	private enabled = false;

	enable() {
		this.enabled = true;
	}

	disable() {
		this.enabled = false;
	}

	clear() {
		this.mocks.clear();
	}

	mock(method: HttpMethod, url: string, response: MockResponse) {
		const key = `${method}:${url}`;
		this.mocks.set(key, response);
	}

	async getMockResponse(
		method: HttpMethod,
		url: string,
	): Promise<MockResponse | null> {
		if (!this.enabled) return null;

		const key = `${method}:${url}`;
		const mockResponse = this.mocks.get(key);

		if (!mockResponse) return null;

		// Simulate network delay
		if (mockResponse.delay) {
			await new Promise((resolve) => setTimeout(resolve, mockResponse.delay));
		}

		return mockResponse;
	}

	isEnabled(): boolean {
		return this.enabled;
	}
}

export const mockManager = new MockManager();

// ==================== CORE IMPLEMENTATION ====================

const MAX = {
	TAGS: 10,
	TAG_LEN: 64,
	PATHS: 10,
	RES_SIZE: 1_000_000,
	PAYLOAD: 100_000,
	TIMEOUT: 30_000,
	RATE_WINDOW: 60_000,
	RATE_MAX: 500,
	CIRCUIT_TTL: 30_000,
	CIRCUIT_MAX: 100,
} as const;

const rateTimestamps: number[] = [];

const isRateLimited = (): boolean => {
	const now = Date.now();
	while (rateTimestamps.length && rateTimestamps[0] < now - MAX.RATE_WINDOW)
		rateTimestamps.shift();
	if (rateTimestamps.length >= MAX.RATE_MAX) return true;
	rateTimestamps.push(now);
	return false;
};

const getAuthHeader = (
	env: ReturnType<typeof createEnv>,
): string | undefined => {
	if (typeof window !== "undefined")
		throw new Error("getAuthHeader must run server-side");

	if (env.AUTH_TOKEN) {
		const isValidJwt = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/.test(
			env.AUTH_TOKEN,
		);
		if (!isValidJwt || env.AUTH_TOKEN.length > 512) {
			throw new Error("Invalid AUTH_TOKEN format");
		}
		return `Bearer ${env.AUTH_TOKEN}`;
	}

	if (process.env.NODE_ENV === "production" && !env.ALLOW_BASIC_AUTH_IN_PROD) {
		throw new Error(
			"Basic Auth not allowed in production without ALLOW_BASIC_AUTH_IN_PROD=true",
		);
	}

	if (env.AUTH_USERNAME && env.AUTH_PASSWORD) {
		return `Basic ${Buffer.from(`${env.AUTH_USERNAME}:${env.AUTH_PASSWORD}`).toString("base64")}`;
	}

	throw new Error("No authentication credentials provided");
};

export function createClientConfig(
	config: { envConfig?: EnvConfig; allowedDomains?: string[] } = {},
): ClientConfig {
	if (typeof window !== "undefined") {
		throw new Error("createClientConfig must run server-side");
	}

	const env = createEnv(config.envConfig);

	if (!env.BASE_URL?.startsWith("https://")) {
		throw new Error("BASE_URL must start with https://");
	}

	const DEFAULT_ALLOWED_DOMAINS = ["api.example.com", "another.example.com"];
	const allowedDomains = config.allowedDomains || DEFAULT_ALLOWED_DOMAINS;

	if (
		process.env.NODE_ENV === "production" &&
		!allowedDomains.includes(new URL(env.BASE_URL).hostname)
	) {
		throw new Error(
			`BASE_URL must be one of the allowed production domains: ${allowedDomains.join(", ")}`,
		);
	}

	return {
		baseUrl: env.BASE_URL!,
		authHeader: getAuthHeader(env),
	};
}

function createError(
	status: StatusCode,
	type: ErrorType,
	message: string,
	requestId: string,
	details?: Record<string, unknown>,
): ApiError {
	const error = new Error(message) as ApiError;
	error.status = status;
	error.type = type;
	error.timestamp = new Date().toISOString();
	error.requestId = requestId;
	error.details = details;
	return error;
}

function getErrorType(status: number): ErrorType {
	if (status === 400 || status === 422) return "VALIDATION_ERROR";
	if (status === 401 || status === 403) return "AUTH_ERROR";
	if (status === 408) return "TIMEOUT_ERROR";
	if (status === 429) return "RATE_LIMIT_ERROR";
	if (status >= 500) return "SERVER_ERROR";
	return "NETWORK_ERROR";
}

const isRetryableError = (status: number): boolean => {
	return status >= 500 || status === 408 || status === 429;
};

const calculateDelay = (
	attempt: number,
	baseDelay: number,
	multiplier: number,
): number => {
	return Math.min(baseDelay * multiplier ** (attempt - 1), 30000);
};

const sleep = (ms: number): Promise<void> =>
	new Promise((resolve) => setTimeout(resolve, ms));

// Enhanced apiRequest with deduplication and loading management
export async function apiRequest<T>(
	method: HttpMethod,
	url: string,
	options: RequestOptions = {},
): Promise<ApiResponse<T>> {
	const requestId = `req_${crypto.randomUUID()}`;
	const isClient = typeof window !== "undefined";

	const {
		data,
		query,
		cache = "no-store",
		revalidate,
		revalidateTags = [],
		revalidatePaths = [],
		revalidateType,
		timeout = MAX.TIMEOUT,
		retryAttempts = 3,
		retryDelay = 1000,
		retryMultiplier = 2,
		csrfToken,
		logTypes = false,
		customHeaders = {},
		clientConfig,
		deduplicate = true,
	} = options;

	// Handle deduplication for GET requests by default
	if (deduplicate && method === 'GET') {
		return requestDeduplicator.deduplicate(
			method,
			url,
			{ query, ...customHeaders },
			(abortController) => executeRequest(abortController)
		);
	}

	return executeRequest();

	async function executeRequest(externalAbortController?: AbortController): Promise<ApiResponse<T>> {
		// Start loading state
		loadingManager.startLoading(requestId);

		try {
			// Rate limiting check
			if (isRateLimited()) {
				return {
					success: false,
					error: createError(
						STATUS.RATE_LIMITED,
						"RATE_LIMIT_ERROR",
						"Too many requests",
						requestId,
					),
					data: null,
				};
			}

			// Log request types if enabled
			if (logTypes) {
				console.log(`[SAFEFETCH] ${method} ${url}`, {
					requestId,
					data: data ? typeof data : undefined,
					query: query ? Object.keys(query) : undefined,
					timestamp: new Date().toISOString(),
				});
			}

			// Check for mock response first
			const mockResponse = await mockManager.getMockResponse(method, url);
			if (mockResponse) {
				if (mockResponse.error) {
					return {
						success: false,
						error: createError(
							mockResponse.error.status || STATUS.INTERNAL_ERROR,
							mockResponse.error.type || "SERVER_ERROR",
							mockResponse.error.message || "Mock error",
							requestId,
							mockResponse.error.details,
						),
						data: null,
					};
				}

				return {
					success: true,
					data: mockResponse.data as T,
					status: mockResponse.status || STATUS.OK,
					headers: mockResponse.headers || {},
					requestId,
				};
			}

			// Client-side validation
			if (isClient && !clientConfig) {
				return {
					success: false,
					error: createError(
						STATUS.BAD_REQUEST,
						"VALIDATION_ERROR",
						"clientConfig is required for client-side requests",
						requestId,
					),
					data: null,
				};
			}

			// Get base URL and auth from appropriate source
			const baseUrl = isClient ? clientConfig!.baseUrl : createEnv().BASE_URL;
			const authHeader = isClient
				? clientConfig!.authHeader
				: (() => {
						try {
							return getAuthHeader(createEnv());
						} catch {
							return undefined;
						}
					})();

			if (!baseUrl) {
				return {
					success: false,
					error: createError(
						STATUS.BAD_REQUEST,
						"VALIDATION_ERROR",
						"Base URL not configured",
						requestId,
					),
					data: null,
				};
			}

			let fullUrl: URL;
			try {
				fullUrl = new URL(url, baseUrl);
			} catch {
				return {
					success: false,
					error: createError(
						STATUS.BAD_REQUEST,
						"VALIDATION_ERROR",
						"Invalid URL",
						requestId,
					),
					data: null,
				};
			}

			if (fullUrl.protocol !== "https:") {
				return {
					success: false,
					error: createError(
						STATUS.BAD_REQUEST,
						"VALIDATION_ERROR",
						"HTTPS required",
						requestId,
					),
					data: null,
				};
			}

			if (query) {
				Object.entries(query).forEach(([key, val]) => {
					if (val != null) fullUrl.searchParams.append(key, String(val));
				});
			}

			const isFormData = typeof FormData !== "undefined" && data instanceof FormData;
			const headers: Record<string, string> = {
				Accept: "application/json",
				"X-Requested-With": "XMLHttpRequest",
				"X-Request-ID": requestId,
				...customHeaders,
			};
			if (authHeader) headers.Authorization = authHeader;
			if (!isFormData && !["GET", "HEAD"].includes(method))
				headers["Content-Type"] = "application/json";
			if (csrfToken) headers["X-CSRF-Token"] = csrfToken;

			// Retry logic with exponential backoff
			let lastError: ApiError | null = null;

			for (let attempt = 1; attempt <= retryAttempts; attempt++) {
				try {
					let body: string | FormData | undefined;
					if (!["GET", "HEAD"].includes(method)) {
						if (isFormData) {
							body = data as FormData;
						} else if (data !== undefined) {
							body = JSON.stringify(data);
						}
					}

					// Create combined abort controller
					const abortController = new AbortController();
					const timeoutId = setTimeout(() => abortController.abort(), timeout);
					
					if (externalAbortController) {
						externalAbortController.signal.addEventListener('abort', () => {
							abortController.abort();
						});
					}

					const fetchOptions: RequestInit & {
						next?: { revalidate?: number | false; tags?: string[] };
					} = {
						method,
						headers,
						cache,
						body,
						signal: abortController.signal,
					};

					if (!isClient && (revalidate !== undefined || revalidateTags.length)) {
						fetchOptions.next = {
							revalidate,
							tags: revalidateTags,
						};
					}

					const response = await fetch(fullUrl.toString(), fetchOptions);
					clearTimeout(timeoutId);

					const responseHeaders: Record<string, string> = {};
					response.headers.forEach((value, key) => {
						responseHeaders[key] = value;
					});

					let parsedData: T;
					const contentType = response.headers.get("Content-Type") || "";
					if (contentType.includes("application/json")) {
						parsedData = await response.json();
					} else if (contentType.startsWith("text/")) {
						parsedData = (await response.text()) as unknown as T;
					} else {
						parsedData = (await response.blob()) as unknown as T;
					}

					if (!response.ok) {
						const error = createError(
							response.status as StatusCode,
							getErrorType(response.status),
							response.statusText || "Request failed",
							requestId,
						);

						// Log error types if enabled
						if (logTypes) {
							console.error(`[SAFEFETCH] ${method} ${url} - Error ${response.status}`, {
								requestId,
								status: response.status,
								type: error.type,
								message: error.message,
								attempt,
								timestamp: new Date().toISOString(),
							});
						}

						// Check if we should retry
						if (attempt < retryAttempts && isRetryableError(response.status)) {
							lastError = error;
							const delayMs = calculateDelay(attempt, retryDelay, retryMultiplier);
							
							if (logTypes) {
								console.warn(`[SAFEFETCH] Retrying ${method} ${url} in ${delayMs}ms (attempt ${attempt + 1}/${retryAttempts})`);
							}
							
							await sleep(delayMs);
							continue;
						}

						return {
							success: false,
							error,
							data: null,
						};
					}

					// Log successful response if enabled
					if (logTypes) {
						console.log(`[SAFEFETCH] ${method} ${url} - Success ${response.status}`, {
							requestId,
							status: response.status,
							dataType: typeof parsedData,
							timestamp: new Date().toISOString(),
						});
					}

					// Revalidate cache on server-side
					if (!isClient && (revalidatePaths.length || revalidateTags.length)) {
						try {
							await Promise.all([
								...revalidatePaths.map((p) => revalidatePath(p, revalidateType)),
								...revalidateTags.map((t) => revalidateTag(t)),
							]);
						} catch (err) {
							console.error("[CACHE] Revalidation failed:", err);
						}
					}

					return {
						success: true,
						data: parsedData,
						status: response.status as StatusCode,
						headers: responseHeaders,
						requestId,
					};
				} catch (err) {
					const networkError = createError(
						STATUS.INTERNAL_ERROR,
						err instanceof Error && err.name === "AbortError"
							? "TIMEOUT_ERROR"
							: "NETWORK_ERROR",
						err instanceof Error ? err.message : "Network error",
						requestId,
					);

					// Log network errors if enabled
					if (logTypes) {
						console.error(`[SAFEFETCH] ${method} ${url} - Network Error`, {
							requestId,
							error: networkError.message,
							type: networkError.type,
							attempt,
							timestamp: new Date().toISOString(),
						});
					}

					// Retry network errors except for the last attempt
					if (attempt < retryAttempts) {
						lastError = networkError;
						const delayMs = calculateDelay(attempt, retryDelay, retryMultiplier);
						
						if (logTypes) {
							console.warn(`[SAFEFETCH] Retrying ${method} ${url} after network error in ${delayMs}ms (attempt ${attempt + 1}/${retryAttempts})`);
						}
						
						await sleep(delayMs);
						continue;
					}

					return {
						success: false,
						error: networkError,
						data: null,
					};
				}
			}

			// This should never be reached due to the loop logic above
			return {
				success: false,
				error:
					lastError ||
					createError(500, "NETWORK_ERROR", "Max retries exceeded", requestId),
				data: null,
			};
		} finally {
			loadingManager.stopLoading(requestId);
		}
	}
}

// ==================== ENHANCED REACT HOOKS ====================

export interface UseSafeFetchOptions<TData = unknown>
	extends Omit<RequestOptions<TData>, "clientConfig"> {
	enabled?: boolean;
	clientConfig: ClientConfig;
	onSuccess?: (data: unknown) => void;
	onError?: (error: ApiError) => void;
	optimisticUpdate?: {
		enabled: boolean;
		updateFn?: (currentData: unknown, optimisticData: unknown) => unknown;
	};
}

export interface UseSafeFetchResult<T> {
	data: T | null;
	loading: boolean;
	error: ApiError | null;
	refetch: () => Promise<void>;
	mutate: (newData: T) => void;
	optimisticUpdate: (updateData: Partial<T>, rollbackFn: () => void) => string;
	removeOptimisticUpdate: (id: string) => void;
	loadingState: LoadingState | null;
}

export function useSafeFetch<T>(
	method: HttpMethod,
	url: string,
	options: UseSafeFetchOptions,
): UseSafeFetchResult<T> {
	const [data, setData] = useState<T | null>(null);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<ApiError | null>(null);
	const [loadingState, setLoadingState] = useState<LoadingState | null>(null);
	const abortControllerRef = useRef<AbortController | null>(null);
	const requestIdRef = useRef<string | null>(null);

	const {
		enabled = true,
		clientConfig,
		onSuccess,
		onError,
		optimisticUpdate,
		...requestOptions
	} = options;

	// Subscribe to loading state changes
	useEffect(() => {
		const unsubscribe = loadingManager.subscribe((globalState) => {
			if (requestIdRef.current) {
				const currentLoadingState = globalState.requests.get(requestIdRef.current);
				setLoadingState(currentLoadingState || null);
				setLoading(currentLoadingState?.isLoading || false);
			}
		});

		return unsubscribe;
	}, []);

	const fetchData = useCallback(async () => {
		if (!enabled) return;

		// Cancel previous request
		if (abortControllerRef.current) {
			abortControllerRef.current.abort();
		}

		abortControllerRef.current = new AbortController();
		const requestId = `req_${crypto.randomUUID()}`;
		requestIdRef.current = requestId;

		setError(null);

		try {
			const result = await apiRequest<T>(method, url, {
				...requestOptions,
				clientConfig,
			});

			if (result.success) {
				setData(result.data);
				onSuccess?.(result.data);
			} else {
				setError(result.error);
				onError?.(result.error);
			}
		} catch (err) {
			const apiError = err as ApiError;
			setError(apiError);
			onError?.(apiError);
		}
	}, [method, url, enabled, clientConfig, onSuccess, onError, requestOptions]);

	const mutate = useCallback((newData: T) => {
		setData(newData);
	}, []);

	const handleOptimisticUpdate = useCallback((
		updateData: Partial<T>,
		rollbackFn: () => void
	): string => {
		if (!optimisticUpdate?.enabled) {
			throw new Error('Optimistic updates not enabled');
		}

		const id = crypto.randomUUID();
		const currentData = data;
		
		// Apply optimistic update
		const updatedData = optimisticUpdate.updateFn 
			? optimisticUpdate.updateFn(currentData, updateData) as T
			: { ...currentData, ...updateData } as T;
		
		setData(updatedData);

		// Register rollback function
		optimisticManager.add({
			id,
			data: updateData,
			type: 'update',
			rollback: () => {
				setData(currentData);
				rollbackFn();
			},
		});

		return id;
	}, [data, optimisticUpdate]);

	const removeOptimisticUpdate = useCallback((id: string) => {
		optimisticManager.remove(id);
	}, []);

	useEffect(() => {
		fetchData();

		return () => {
			if (abortControllerRef.current) {
				abortControllerRef.current.abort();
			}
		};
	}, [fetchData]);

	return {
		data,
		loading,
		error,
		refetch: fetchData,
		mutate,
		optimisticUpdate: handleOptimisticUpdate,
		removeOptimisticUpdate,
		loadingState,
	};
}

export interface UseSafeMutationOptions<TData = unknown, TResponse = unknown> {
	clientConfig: ClientConfig;
	onSuccess?: (data: TResponse, variables: TData) => void;
	onError?: (error: ApiError, variables: TData) => void;
	optimisticUpdate?: {
		enabled: boolean;
		updateFn?: (variables: TData) => TResponse;
		rollbackFn?: (error: ApiError, variables: TData) => void;
	};
}

export interface UseSafeMutationResult<TData = unknown, TResponse = unknown> {
	mutate: (variables: TData) => Promise<ApiResponse<TResponse>>;
	mutateAsync: (variables: TData) => Promise<TResponse>;
	loading: boolean;
	error: ApiError | null;
	data: TResponse | null;
	reset: () => void;
	loadingState: LoadingState | null;
}

export function useSafeMutation<TData = unknown, TResponse = unknown>(
	method: Exclude<HttpMethod, "GET">,
	url: string,
	options: UseSafeMutationOptions<TData, TResponse>,
): UseSafeMutationResult<TData, TResponse> {
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<ApiError | null>(null);
	const [data, setData] = useState<TResponse | null>(null);
	const [loadingState, setLoadingState] = useState<LoadingState | null>(null);
	const requestIdRef = useRef<string | null>(null);

	const { clientConfig, onSuccess, onError, optimisticUpdate } = options;

	// Subscribe to loading state changes
	useEffect(() => {
		const unsubscribe = loadingManager.subscribe((globalState) => {
			if (requestIdRef.current) {
				const currentLoadingState = globalState.requests.get(requestIdRef.current);
				setLoadingState(currentLoadingState || null);
				setLoading(currentLoadingState?.isLoading || false);
			}
		});

		return unsubscribe;
	}, []);

	const mutate = useCallback(
		async (variables: TData): Promise<ApiResponse<TResponse>> => {
			const requestId = `req_${crypto.randomUUID()}`;
			requestIdRef.current = requestId;

			setError(null);
			loadingManager.startLoading(requestId, 'mutate');

			let optimisticId: string | undefined;

			// Handle optimistic updates
			if (optimisticUpdate?.enabled && optimisticUpdate.updateFn) {
				const optimisticData = optimisticUpdate.updateFn(variables);
				optimisticId = crypto.randomUUID();
				
				optimisticManager.add({
					id: optimisticId,
					data: optimisticData,
					type: 'update',
					rollback: () => {
						optimisticUpdate.rollbackFn?.(error!, variables);
					},
				});
			}

			try {
				const result = await apiRequest<TResponse>(method, url, {
					data: variables,
					clientConfig,
				});

				if (result.success) {
					setData(result.data);
					onSuccess?.(result.data, variables);
					
					// Remove optimistic update on success
					if (optimisticId) {
						optimisticManager.remove(optimisticId);
					}
				} else {
					setError(result.error);
					onError?.(result.error, variables);
					
					// Rollback optimistic update on error
					if (optimisticId) {
						optimisticManager.rollback(optimisticId);
					}
				}

				return result;
			} catch (err) {
				const apiError = err as ApiError;
				setError(apiError);
				onError?.(apiError, variables);
				
				// Rollback optimistic update on error
				if (optimisticId) {
					optimisticManager.rollback(optimisticId);
				}

				return {
					success: false,
					error: apiError,
					data: null,
				};
			} finally {
				loadingManager.stopLoading(requestId);
			}
		},
		[method, url, clientConfig, onSuccess, onError, optimisticUpdate, error],
	);

	const mutateAsync = useCallback(
		async (variables: TData): Promise<TResponse> => {
			const result = await mutate(variables);
			if (result.success) {
				return result.data;
			}
			throw result.error;
		},
		[mutate],
	);

	const reset = useCallback(() => {
		setLoading(false);
		setError(null);
		setData(null);
		setLoadingState(null);
	}, []);

	return {
		mutate,
		mutateAsync,
		loading,
		error,
		data,
		reset,
		loadingState,
	};
}

// Hook for global loading state
export function useGlobalLoading() {
	const [globalState, setGlobalState] = useState<GlobalLoadingState>(
		loadingManager.getState()
	);

	useEffect(() => {
		const unsubscribe = loadingManager.subscribe(setGlobalState);
		return unsubscribe;
	}, []);

	return {
		isLoading: globalState.globalLoading,
		requests: globalState.requests,
		getRequestState: (requestId: string) => globalState.requests.get(requestId),
	};
}

// Hook for optimistic updates
export function useOptimisticUpdates<T>() {
	const [updates, setUpdates] = useState<OptimisticUpdate<T>[]>([]);

	useEffect(() => {
		const unsubscribe = optimisticManager.subscribe(setUpdates);
		return unsubscribe;
	}, []);

	return {
		updates,
		rollbackAll: optimisticManager.rollbackAll.bind(optimisticManager),
		rollback: optimisticManager.rollback.bind(optimisticManager),
		clear: optimisticManager.clear.bind(optimisticManager),
	};
}

// Enhanced testing utilities with rate limiting support
export const testing = {
	mockManager,
	loadingManager,
	requestDeduplicator,
	optimisticManager,

	// Helper to mock successful responses
	mockSuccess: <T>(
		method: HttpMethod,
		url: string,
		data: T,
		options?: {
			status?: StatusCode;
			delay?: number;
			headers?: Record<string, string>;
		},
	) => {
		mockManager.mock(method, url, {
			data,
			status: options?.status || STATUS.OK,
			delay: options?.delay,
			headers: options?.headers,
		});
	},

	// Helper to mock error responses
	mockError: (
		method: HttpMethod,
		url: string,
		options: {
			status?: StatusCode;
			type?: ErrorType;
			message?: string;
			delay?: number;
		},
	) => {
		mockManager.mock(method, url, {
			error: {
				status: options.status || STATUS.INTERNAL_ERROR,
				type: options.type || "SERVER_ERROR",
				message: options.message || "Mock error",
			},
			delay: options.delay,
		});
	},

	// Enable/disable mocking
	enable: () => mockManager.enable(),
	disable: () => mockManager.disable(),
	clear: () => {
		mockManager.clear();
		loadingManager.getState().requests.clear();
		requestDeduplicator.clear();
		optimisticManager.clear();
		// Clear rate limiting timestamps for testing
		rateTimestamps.length = 0;
	},

	// Test utilities for loading states
	simulateLoading: (requestId: string, duration: number = 1000) => {
		loadingManager.startLoading(requestId);
		setTimeout(() => loadingManager.stopLoading(requestId), duration);
	},

	// Test utilities for optimistic updates
	addOptimisticUpdate: <T>(update: Omit<OptimisticUpdate<T>, 'timestamp'>) => {
		return optimisticManager.add(update);
	},

	// Rate limiting test utilities
	triggerRateLimit: () => {
		// Fill rate limit buffer to trigger rate limiting
		const now = Date.now();
		rateTimestamps.length = 0;
		for (let i = 0; i < MAX.RATE_MAX; i++) {
			rateTimestamps.push(now);
		}
	},

	resetRateLimit: () => {
		rateTimestamps.length = 0;
	},

	getRateLimitStatus: () => ({
		currentRequests: rateTimestamps.length,
		maxRequests: MAX.RATE_MAX,
		windowMs: MAX.RATE_WINDOW,
		isRateLimited: isRateLimited(),
	}),
};

// ==================== SERVER ACTIONS ====================

export interface ServerActionConfig<TInput = unknown, TOutput = unknown> {
	method: HttpMethod;
	url: string | ((input: TInput) => string);
	revalidateTags?: string[];
	revalidatePaths?: string[];
	revalidateType?: "page" | "layout";
	onSuccess?: (data: TOutput, input: TInput) => void | Promise<void>;
	onError?: (error: ApiError, input: TInput) => void | Promise<void>;
	transform?: (input: TInput) => unknown;
	validate?: (input: TInput) => boolean | string;
}

export function createServerAction<TInput = unknown, TOutput = unknown>(
	config: ServerActionConfig<TInput, TOutput>,
) {
	return async (input: TInput): Promise<TOutput> => {
		"use server";

		// Validation
		if (config.validate) {
			const validation = config.validate(input);
			if (validation !== true) {
				throw new Error(
					typeof validation === "string" ? validation : "Validation failed",
				);
			}
		}

		const url =
			typeof config.url === "function" ? config.url(input) : config.url;
		const data = config.transform ? config.transform(input) : input;

		const result = await apiRequest<TOutput>(config.method, url, {
			data: config.method !== "GET" ? data : undefined,
			query: config.method === "GET" ? (data as QueryParams) : undefined,
			revalidateTags: config.revalidateTags,
			revalidatePaths: config.revalidatePaths,
			revalidateType: config.revalidateType,
		});

		if (!result.success) {
			await config.onError?.(result.error, input);

			// Handle different error types for better UX
			if (result.error.type === "AUTH_ERROR") {
				redirect("/login");
			}

			throw result.error;
		}

		await config.onSuccess?.(result.data, input);
		return result.data;
	};
}

// Server Actions Builder with optimistic updates support
export const serverActions = {
	create: <TInput, TOutput>(
		config: Omit<ServerActionConfig<TInput, TOutput>, "method">,
	) => createServerAction({ ...config, method: "POST" }),

	update: <TInput, TOutput>(
		config: Omit<ServerActionConfig<TInput, TOutput>, "method">,
	) => createServerAction({ ...config, method: "PUT" }),

	patch: <TInput, TOutput>(
		config: Omit<ServerActionConfig<TInput, TOutput>, "method">,
	) => createServerAction({ ...config, method: "PATCH" }),

	delete: <TInput, TOutput>(
		config: Omit<ServerActionConfig<TInput, TOutput>, "method">,
	) => createServerAction({ ...config, method: "DELETE" }),

	get: <TInput, TOutput>(
		config: Omit<ServerActionConfig<TInput, TOutput>, "method">,
	) => createServerAction({ ...config, method: "GET" }),
};

// ==================== ROUTE HANDLERS ====================

export interface RouteHandlerConfig {
	method: HttpMethod;
	externalUrl: string;
	revalidateTags?: string[];
	revalidatePaths?: string[];
	revalidateType?: "page" | "layout";
	transform?: {
		request?: (data: unknown) => unknown;
		response?: (data: unknown) => unknown;
	};
	headers?: Record<string, string>;
}

export function createRouteHandler(config: RouteHandlerConfig) {
	return async (request: NextRequest): Promise<NextResponse> => {
		try {
			let data: unknown;

			// Extract data from request
			if (["POST", "PUT", "PATCH"].includes(config.method)) {
				const contentType = request.headers.get("content-type");
				if (contentType?.includes("application/json")) {
					data = await request.json();
				} else if (contentType?.includes("multipart/form-data")) {
					data = await request.formData();
				}
			}

			// Extract query params for GET requests
			if (config.method === "GET") {
				const searchParams = request.nextUrl.searchParams;
				data = Object.fromEntries(searchParams.entries());
			}

			// Transform request data
			const transformedData = config.transform?.request
				? config.transform.request(data)
				: data;

			// Make external API call
			const result = await apiRequest(config.method, config.externalUrl, {
				data: ["GET", "HEAD"].includes(config.method)
					? undefined
					: transformedData,
				query:
					config.method === "GET"
						? (transformedData as QueryParams)
						: undefined,
				revalidateTags: config.revalidateTags,
				revalidatePaths: config.revalidatePaths,
				revalidateType: config.revalidateType,
				customHeaders: config.headers,
			});

			if (!result.success) {
				return NextResponse.json(
					{ error: result.error.message, type: result.error.type },
					{ status: result.error.status },
				);
			}

			// Transform response data
			const responseData = config.transform?.response
				? config.transform.response(result.data)
				: result.data;

			return NextResponse.json(responseData, {
				status: result.status,
				headers: {
					"X-Request-ID": result.requestId,
					...Object.fromEntries(
						Object.entries(result.headers).filter(
							([key]) =>
								key.toLowerCase().startsWith("x-") ||
								key.toLowerCase() === "cache-control",
						),
					),
				},
			});
		} catch (error) {
			console.error("[ROUTE_HANDLER] Error:", error);
			return NextResponse.json(
				{ error: "Internal server error", type: "SERVER_ERROR" },
				{ status: 500 },
			);
		}
	};
}

// Route Handler Builder
export const routeHandlers = {
	GET: (
		externalUrl: string,
		config?: Omit<RouteHandlerConfig, "method" | "externalUrl">,
	) => createRouteHandler({ ...config, method: "GET", externalUrl }),

	POST: (
		externalUrl: string,
		config?: Omit<RouteHandlerConfig, "method" | "externalUrl">,
	) => createRouteHandler({ ...config, method: "POST", externalUrl }),

	PUT: (
		externalUrl: string,
		config?: Omit<RouteHandlerConfig, "method" | "externalUrl">,
	) => createRouteHandler({ ...config, method: "PUT", externalUrl }),

	PATCH: (
		externalUrl: string,
		config?: Omit<RouteHandlerConfig, "method" | "externalUrl">,
	) => createRouteHandler({ ...config, method: "PATCH", externalUrl }),

	DELETE: (
		externalUrl: string,
		config?: Omit<RouteHandlerConfig, "method" | "externalUrl">,
	) => createRouteHandler({ ...config, method: "DELETE", externalUrl }),
};

// ==================== MIDDLEWARE ====================

export interface MiddlewareConfig {
	authStrategy?: "jwt" | "basic" | "custom";
	csrfProtection?: boolean;
	rateLimiting?: {
		windowMs?: number;
		max?: number;
	};
	allowedOrigins?: string[];
	customAuthValidator?: (request: NextRequest) => Promise<boolean> | boolean;
}

export function createSafeFetchMiddleware(config: MiddlewareConfig = {}) {
	return async (request: NextRequest): Promise<NextResponse | undefined> => {
		// CORS handling
		if (config.allowedOrigins && request.method === "OPTIONS") {
			const origin = request.headers.get("origin");
			if (origin && config.allowedOrigins.includes(origin)) {
				return new NextResponse(null, {
					status: 200,
					headers: {
						"Access-Control-Allow-Origin": origin,
						"Access-Control-Allow-Methods":
							"GET, POST, PUT, DELETE, PATCH, OPTIONS",
						"Access-Control-Allow-Headers":
							"Content-Type, Authorization, X-CSRF-Token",
						"Access-Control-Max-Age": "86400",
					},
				});
			}
		}

		// Auth validation
		if (config.authStrategy && config.authStrategy !== "custom") {
			const authHeader = request.headers.get("authorization");
			if (!authHeader) {
				return NextResponse.json(
					{ error: "Authorization required" },
					{ status: 401 },
				);
			}

			if (config.authStrategy === "jwt" && !authHeader.startsWith("Bearer ")) {
				return NextResponse.json(
					{ error: "Invalid auth format" },
					{ status: 401 },
				);
			}

			if (config.authStrategy === "basic" && !authHeader.startsWith("Basic ")) {
				return NextResponse.json(
					{ error: "Invalid auth format" },
					{ status: 401 },
				);
			}
		}

		// Custom auth validation
		if (config.customAuthValidator) {
			const isValid = await config.customAuthValidator(request);
			if (!isValid) {
				return NextResponse.json(
					{ error: "Authentication failed" },
					{ status: 401 },
				);
			}
		}

		// CSRF protection
		if (
			config.csrfProtection &&
			["POST", "PUT", "PATCH", "DELETE"].includes(request.method)
		) {
			const csrfToken = request.headers.get("x-csrf-token");
			if (!csrfToken || !/^[a-zA-Z0-9-_]{32,}$/.test(csrfToken)) {
				return NextResponse.json(
					{ error: "Invalid CSRF token" },
					{ status: 403 },
				);
			}
		}

		// Continue to next middleware or route
		return undefined;
	};
}

// ==================== ERROR BOUNDARY ====================

export class SafeFetchError extends Error implements ApiError {
	status: StatusCode;
	type: ErrorType;
	timestamp: string;
	requestId: string;
	details?: Record<string, unknown>;

	constructor(apiError: ApiError) {
		super(apiError.message);
		this.name = "SafeFetchError";
		this.status = apiError.status;
		this.type = apiError.type;
		this.timestamp = apiError.timestamp;
		this.requestId = apiError.requestId;
		this.details = apiError.details;
	}
}

// Next.js Error Boundary Helper
export function handleSafeFetchError(error: unknown): NextResponse {
	if (error instanceof SafeFetchError) {
		return NextResponse.json(
			{
				error: error.message,
				type: error.type,
				requestId: error.requestId,
				timestamp: error.timestamp,
			},
			{ status: error.status },
		);
	}

	// Generic error fallback
	return NextResponse.json(
		{ error: "Internal server error", type: "SERVER_ERROR" },
		{ status: 500 },
	);
}

// ==================== UTILITY FUNCTIONS ====================

// Debounced API request helper
export function createDebouncedRequest<T>(
	method: HttpMethod,
	url: string,
	delay: number = 300
) {
	let timeoutId: NodeJS.Timeout;
	
	return (options: RequestOptions = {}): Promise<ApiResponse<T>> => {
		return new Promise((resolve) => {
			clearTimeout(timeoutId);
			timeoutId = setTimeout(async () => {
				const result = await apiRequest<T>(method, url, options);
				resolve(result);
			}, delay);
		});
	};
}

// Batch requests helper
export async function batchRequests<T>(
	requests: Array<{
		method: HttpMethod;
		url: string;
		options?: RequestOptions;
	}>,
	maxConcurrency: number = 5
): Promise<ApiResponse<T>[]> {
	const results: ApiResponse<T>[] = [];
	
	for (let i = 0; i < requests.length; i += maxConcurrency) {
		const batch = requests.slice(i, i + maxConcurrency);
		const batchPromises = batch.map(({ method, url, options = {} }) =>
			apiRequest<T>(method, url, options)
		);
		
		const batchResults = await Promise.all(batchPromises);
		results.push(...batchResults);
	}
	
	return results;
}

// Request interceptor type
export type RequestInterceptor = (
	method: HttpMethod,
	url: string,
	options: RequestOptions
) => RequestOptions | Promise<RequestOptions>;

export type ResponseInterceptor<T> = (
	response: ApiResponse<T>
) => ApiResponse<T> | Promise<ApiResponse<T>>;

// Global interceptors
const requestInterceptors: RequestInterceptor[] = [];
const responseInterceptors: ResponseInterceptor<unknown>[] = [];

export const interceptors = {
	request: {
		use: (interceptor: RequestInterceptor) => {
			requestInterceptors.push(interceptor);
			return () => {
				const index = requestInterceptors.indexOf(interceptor);
				if (index > -1) requestInterceptors.splice(index, 1);
			};
		},
	},
	response: {
		use: <T>(interceptor: ResponseInterceptor<T>) => {
			responseInterceptors.push(interceptor as ResponseInterceptor<unknown>);
			return () => {
				const index = responseInterceptors.indexOf(interceptor as ResponseInterceptor<unknown>);
				if (index > -1) responseInterceptors.splice(index, 1);
			};
		},
	},
};

export default apiRequest;