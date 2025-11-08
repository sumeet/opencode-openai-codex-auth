import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { Readable } from "node:stream";
import { ReadableStream as NodeReadableStream } from "node:stream/web";
import { join } from "node:path";
import { homedir } from "node:os";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { randomUUID } from "node:crypto";

import {
	createAuthorizationFlow,
	exchangeAuthorizationCode,
	parseAuthorizationInput,
	refreshAccessToken,
	decodeJWT,
} from "../auth/auth.js";
import { openBrowserUrl } from "../auth/browser.js";
import { startLocalOAuthServer } from "../auth/server.js";
import { loadPluginConfig, getCodexMode } from "../config.js";
import { AUTH_LABELS, CODEX_BASE_URL, JWT_CLAIM_PATH, PLUGIN_NAME } from "../constants.js";
import { getCodexInstructions } from "../prompts/codex.js";
import {
	createCodexHeaders,
	rewriteUrlForCodex,
	transformRequestForCodex,
} from "../request/fetch-helpers.js";
import { convertSseToJson } from "../request/response-handler.js";
import type { RequestBody, TokenSuccess, UserConfig } from "../types.js";
import { logProxyError } from "./logging.js";

const DEFAULT_PORT = Number(process.env.CODEX_PROXY_PORT ?? 9000);
const HOST = process.env.CODEX_PROXY_HOST ?? "127.0.0.1";
const DATA_DIR = join(homedir(), ".opencode");
const TOKEN_FILE = process.env.CODEX_PROXY_TOKEN_PATH ?? join(DATA_DIR, "codex-oauth-token.json");
const FORCE_JSON_RESPONSES = process.env.CODEX_PROXY_FORCE_JSON !== "0";

interface StoredCredentials extends TokenSuccess {
	accountId: string;
}

interface AuthState {
	credentials: StoredCredentials | null;
	refreshPromise: Promise<void> | null;
}

const authState: AuthState = { credentials: null, refreshPromise: null };

async function ensureDataDir(): Promise<void> {
	if (!existsSync(DATA_DIR)) {
		mkdirSync(DATA_DIR, { recursive: true });
	}
}

function loadStoredCredentials(): StoredCredentials | null {
	try {
		if (!existsSync(TOKEN_FILE)) {
			return null;
		}
		const parsed = JSON.parse(readFileSync(TOKEN_FILE, "utf8")) as StoredCredentials;
		return parsed;
	} catch (error) {
		console.warn(`[${PLUGIN_NAME}] Failed to read cached credentials: ${(error as Error).message}`);
		return null;
	}
}

async function persistCredentials(creds: StoredCredentials): Promise<void> {
	await ensureDataDir();
	writeFileSync(TOKEN_FILE, JSON.stringify(creds, null, 2), "utf8");
}

function hasValidAccess(creds: StoredCredentials | null): boolean {
	if (!creds) return false;
	const bufferMs = 60_000;
	return creds.expires > Date.now() + bufferMs;
}

function extractAccountId(accessToken: string): string {
	const decoded = decodeJWT(accessToken);
	const accountId = decoded?.[JWT_CLAIM_PATH]?.chatgpt_account_id;
	if (!accountId) {
		throw new Error("Failed to extract ChatGPT account id from token");
	}
	return accountId;
}

async function interactiveLogin(): Promise<StoredCredentials> {
	const { pkce, state, url } = await createAuthorizationFlow();
	const serverInfo = await startLocalOAuthServer({ state });

	console.log(`[${PLUGIN_NAME}] ${AUTH_LABELS.INSTRUCTIONS}`);
	console.log(`[${PLUGIN_NAME}] Opening browser for OAuth login…`);
	console.log(`[${PLUGIN_NAME}] If the browser does not open automatically, visit:\n${url}\n`);
	openBrowserUrl(url);

	const redirectResult = await serverInfo.waitForCode(state);
	serverInfo.close();

	let authorizationCode: string | undefined = redirectResult?.code;
	if (!authorizationCode) {
		const rl = createInterface({ input: process.stdin, output: process.stdout });
		const manualInput = await rl.question(
			"Paste the full redirected URL or authorization code from the browser: ",
		);
		rl.close();
		const parsed = parseAuthorizationInput(manualInput);
		authorizationCode = parsed.code;
		if (!authorizationCode) {
			throw new Error("Authorization code not provided");
		}
	}

	const tokenResult = await exchangeAuthorizationCode(authorizationCode, pkce.verifier);
	if (tokenResult.type === "failed") {
		throw new Error("Failed to exchange authorization code for tokens");
	}

	const accountId = extractAccountId(tokenResult.access);
	const credentials: StoredCredentials = {
		...tokenResult,
		accountId,
	};
	await persistCredentials(credentials);
	return credentials;
}

async function refreshCredentials(current: StoredCredentials): Promise<StoredCredentials> {
	const refreshed = await refreshAccessToken(current.refresh);
	if (refreshed.type === "failed") {
		throw new Error("Token refresh failed");
	}

	const updated: StoredCredentials = {
		...refreshed,
		accountId: extractAccountId(refreshed.access),
	};
	await persistCredentials(updated);
	return updated;
}

async function bootstrapCredentials(): Promise<void> {
	if (authState.credentials && hasValidAccess(authState.credentials)) {
		return;
	}

	const cached = loadStoredCredentials();
	if (cached && hasValidAccess(cached)) {
		authState.credentials = cached;
		return;
	}

	if (cached) {
		try {
			authState.credentials = await refreshCredentials(cached);
			return;
		} catch (error) {
			console.warn(
				`[${PLUGIN_NAME}] Failed to refresh cached credentials: ${(error as Error).message}`,
			);
		}
	}

	authState.credentials = await interactiveLogin();
}

async function ensureFreshCredentials(): Promise<void> {
	if (authState.credentials && hasValidAccess(authState.credentials)) {
		return;
	}

	if (!authState.credentials) {
		await bootstrapCredentials();
		return;
	}

	if (!authState.refreshPromise) {
		authState.refreshPromise = refreshCredentials(authState.credentials)
			.then((creds) => {
				authState.credentials = creds;
			})
			.catch((error) => {
				console.error(`[${PLUGIN_NAME}] Refresh failed: ${(error as Error).message}`);
				authState.credentials = null;
			})
			.finally(() => {
				authState.refreshPromise = null;
			});
	}

	await authState.refreshPromise;

	if (!authState.credentials) {
		await bootstrapCredentials();
	}
}

function normalizePath(pathname: string): string {
	if (!pathname.startsWith("/")) return `/${pathname}`;
	if (pathname.startsWith("/v1/")) return pathname.slice(3);
	if (pathname === "/v1") return "/";
	return pathname;
}

function buildCodexUrl(requestUrl: URL): string {
	const normalizedPath = normalizePath(requestUrl.pathname);
	const target = `${CODEX_BASE_URL}${normalizedPath}${requestUrl.search}`;
	if (normalizedPath.includes("/codex/")) {
		return target;
	}
	return rewriteUrlForCodex(target);
}

async function readRequestBody(req: IncomingMessage): Promise<string> {
	return new Promise((resolve, reject) => {
		const chunks: Buffer[] = [];
		req.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
		req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
		req.on("error", reject);
	});
}

async function forwardResponse(upstream: Response, res: ServerResponse): Promise<void> {
	upstream.headers.forEach((value, key) => {
		res.setHeader(key, value);
	});
	res.statusCode = upstream.status;

	if (!upstream.body) {
		const text = await upstream.text();
		res.end(text);
		return;
	}

	const readableStream = upstream.body as unknown as NodeReadableStream;
	const readable = Readable.fromWeb(readableStream);
	readable.on("error", (error) => {
		console.error(`[${PLUGIN_NAME}] Error piping response: ${(error as Error).message}`);
		res.destroy(error as Error);
	});
	readable.pipe(res);
}

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
	res.statusCode = status;
	res.setHeader("content-type", "application/json");
	res.end(JSON.stringify(payload));
}

async function handleResponsesEndpoint(
	req: IncomingMessage,
	res: ServerResponse,
	context: ProxyContext,
): Promise<void> {
	const host = req.headers.host ?? `localhost:${DEFAULT_PORT}`;
	const requestUrl = new URL(req.url ?? "/v1/responses", `http://${host}`);

	if (req.method !== "POST") {
		sendJson(res, 405, { error: "Method not allowed" });
		return;
	}

	const rawBody = await readRequestBody(req);
	if (!rawBody) {
		sendJson(res, 400, { error: "Request body is required" });
		return;
	}

	let parsedBody: RequestBody;
	try {
		parsedBody = JSON.parse(rawBody) as RequestBody;
	} catch (error) {
		sendJson(res, 400, { error: `Invalid JSON body: ${(error as Error).message}` });
		return;
	}

	if (parsedBody.metadata) {
		delete parsedBody.metadata;
	}

	const sanitizedBody = JSON.stringify(parsedBody);
	const traceId = parsedBody.prompt_cache_key ?? randomUUID();

	await ensureFreshCredentials();
	if (!authState.credentials) {
		sendJson(res, 401, { error: "Authentication required" });
		return;
	}

	const codexUrl = buildCodexUrl(requestUrl);
	const initialInit: RequestInit = { body: sanitizedBody };
	const transformation = await transformRequestForCodex(
		initialInit,
		codexUrl,
		context.instructions,
		context.userConfig,
		context.codexMode,
	);
	const finalBody = transformation?.updatedInit?.body ?? sanitizedBody;
	const bodyForHeaders = transformation?.body as RequestBody | undefined;
	const effectiveBody = bodyForHeaders ?? parsedBody;

	const headers = createCodexHeaders(undefined, authState.credentials.accountId, authState.credentials.access, {
		model: bodyForHeaders?.model,
		promptCacheKey: bodyForHeaders?.prompt_cache_key,
	});
	headers.set("content-type", "application/json");

	const upstreamResponse = await fetch(codexUrl, {
		method: "POST",
		headers,
		body: finalBody,
	});

	let responseForClient = upstreamResponse;
	if (FORCE_JSON_RESPONSES) {
		responseForClient = await convertSseToJson(upstreamResponse, upstreamResponse.headers);
	}

	if (!responseForClient.ok) {
		try {
			const clone = responseForClient.clone();
			const responseBody = await clone.text();
			logProxyError({
				traceId,
				url: codexUrl,
				status: responseForClient.status,
				statusText: responseForClient.statusText,
				model: effectiveBody?.model ?? parsedBody.model,
				hasTools: Boolean(effectiveBody?.tools ?? parsedBody.tools),
				bodyLength: sanitizedBody.length,
				responseBody: responseBody.slice(0, 8000),
			});
		} catch (error) {
			console.error(
				`[${PLUGIN_NAME}] Failed to log upstream error: ${(error as Error).message}`,
			);
		}
	}

	await forwardResponse(responseForClient, res);
}

interface ProxyContext {
	instructions: string;
	userConfig: UserConfig;
	codexMode: boolean;
}

async function startServer(): Promise<void> {
	const instructions = await getCodexInstructions();
	const pluginConfig = loadPluginConfig();
	const codexMode = getCodexMode(pluginConfig);
	const context: ProxyContext = {
		instructions,
		userConfig: {
			global: {},
			models: {},
		},
		codexMode,
	};

	await bootstrapCredentials();

	const server = createServer(async (req, res) => {
		try {
			const pathname = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`).pathname;
			const normalized = normalizePath(pathname);

			if (req.method === "GET" && normalized === "/health") {
				sendJson(res, 200, { ok: true });
				return;
			}

			if (normalized.startsWith("/responses")) {
				await handleResponsesEndpoint(req, res, context);
				return;
			}

			sendJson(res, 404, { error: "Not found" });
		} catch (error) {
			console.error(`[${PLUGIN_NAME}] Unexpected error: ${(error as Error).message}`);
			if (!res.headersSent) {
				sendJson(res, 500, { error: "Internal server error" });
			} else {
				res.end();
			}
		}
	});

	server.listen(DEFAULT_PORT, HOST, () => {
		console.log(
			`[${PLUGIN_NAME}] Codex proxy listening on http://${HOST}:${DEFAULT_PORT} (POST /v1/responses)`,
		);
		console.log(`[${PLUGIN_NAME}] Set OPENAI_BASE_URL to this address in claude-code-gpt-5/.env`);
	});
}

void startServer().catch((error) => {
	console.error(`[${PLUGIN_NAME}] Failed to start proxy: ${(error as Error).stack}`);
	process.exit(1);
});
