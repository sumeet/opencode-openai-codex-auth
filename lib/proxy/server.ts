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
import { AUTH_LABELS, CODEX_BASE_URL, JWT_CLAIM_PATH, PLUGIN_NAME } from "../constants.js";
import { getCodexInstructions } from "../prompts/codex.js";
import { createCodexHeaders, rewriteUrlForCodex } from "../request/fetch-helpers.js";
import { convertSseToJson } from "../request/response-handler.js";
import type { RequestBody, TokenSuccess } from "../types.js";
import { logProxyError } from "./logging.js";

const DEFAULT_PORT = Number(process.env.CODEX_PROXY_PORT ?? 9000);
const HOST = process.env.CODEX_PROXY_HOST ?? "127.0.0.1";
const DATA_DIR = join(homedir(), ".opencode");
const TOKEN_FILE = process.env.CODEX_PROXY_TOKEN_PATH ?? join(DATA_DIR, "codex-oauth-token.json");
// Minimal proxy: stream Codex SSE as-is; no JSON collapsing, no tool-name tweaks

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
): Promise<void> {
    const verbose = process.env.CODEX_PROXY_VERBOSE === '1';
    const PROMPT_HEAD = Number.parseInt(process.env.CODEX_PROXY_PROMPT_HEAD ?? '300', 10);
    const PROMPT_TAIL = Number.parseInt(process.env.CODEX_PROXY_PROMPT_TAIL ?? '0', 10);
    const SEP = process.env.CODEX_PROXY_SEPARATOR ?? '======';
    const host = req.headers.host ?? `localhost:${DEFAULT_PORT}`;
    const requestUrl = new URL(req.url ?? "/v1/responses", `http://${host}`);
    const t0 = Date.now();

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

    // Honor client stream preference for downstream conversion, but Codex
    // backend always streams its responses. We capture the original flag here
    // and still ask Codex for SSE, converting to JSON for non-streaming clients.
    const clientStreamRequested = Boolean(parsedBody.stream);

    // Codex backend requires stateless mode
    parsedBody.store = false;
    // Always stream from Codex (we convert to JSON if client didn't request stream)
    parsedBody.stream = true;

    // Capture developer/system guidance from client
    const inferredDevGuide = extractInstructionsFromInput(parsedBody.input);

    // Instructions: allow disabling Codex instructions via env
    const DISABLE_CODEX_INSTRUCTIONS = process.env.CODEX_PROXY_DISABLE_CODEX_INSTRUCTIONS === '1';
    if (!parsedBody.instructions || typeof parsedBody.instructions !== "string") {
        parsedBody.instructions = "";
    }
    if (!parsedBody.instructions.trim()) {
        parsedBody.instructions = DISABLE_CODEX_INSTRUCTIONS ? "" : (globalCodexInstructions || "You are Codex.");
    }

    // Build input with optional environment override first, then (deduped) inferred developer guide,
    // then the original input items. This avoids reordering after we inject and prevents duplicates.
    try {
        const originalInput: any[] = Array.isArray(parsedBody.input) ? parsedBody.input : [];
        const newInput: any[] = [];

        const DISABLE_ENV_OVERRIDE = process.env.CODEX_PROXY_DISABLE_ENV_OVERRIDE === '1';
        const overrideFromEnv = process.env.ENV_OVERRIDE_TEXT;
        const defaultOverride = [
            "[ENVIRONMENT OVERRIDE]",
            "You are running inside Claude Code CLI (not Codex).",
            "Ignore Codex-specific operating rules and tool mappings above.",
            "Follow the client-provided system/developer prompts and the tool schema present in the input items.",
            "When instructions conflict, prefer the client-provided Claude Code guidance.",
        ].join(" ");

        if (!DISABLE_ENV_OVERRIDE) {
            const envOverrideText = (overrideFromEnv && overrideFromEnv.trim()) ? overrideFromEnv.trim() : defaultOverride;
            newInput.push({
                type: "message",
                role: "developer",
                content: [{ type: "input_text", text: envOverrideText }],
            });
        }

        // Keep it simple: do not duplicate or reposition existing developer/system guidance.
        // We only prepend the environment override, then append the original input as-is.

        // Append original input
        for (const item of originalInput) newInput.push(item);

        parsedBody.input = newInput;
    } catch {
        // ignore
    }

    // No additional tool remaps injected here; rely on the client's own system prompt
    // and tools to drive behavior, with the environment override above clarifying priorities.

    // Ensure encrypted reasoning continuity is included when stateless
    if (!Array.isArray((parsedBody as any).include) || (parsedBody as any).include.length === 0) {
        (parsedBody as any).include = ["reasoning.encrypted_content"];
    }

    const sanitizedBody = JSON.stringify(parsedBody);
    const traceId = parsedBody.prompt_cache_key ?? randomUUID();

    // Print full system prompt and full request input (no truncation)
    try {
        const instr = typeof (parsedBody as any).instructions === 'string' ? (parsedBody as any).instructions : '';
        const tools = Array.isArray((parsedBody as any).tools) ? (parsedBody as any).tools.length : 0;
        const inputs = Array.isArray((parsedBody as any).input) ? (parsedBody as any).input : [];
        const ts = new Date().toISOString();
        console.error(`--- REQUEST ${ts} trace=${traceId} ---`);
        console.error(`[codex-proxy] model=${parsedBody.model ?? '?' } stream=${Boolean((parsedBody as any).stream)} tools=${tools}`);
        console.error(`[codex-proxy] instructions:`);
        console.error(instr);
        console.error(`[codex-proxy] input:`);
        console.error(JSON.stringify(inputs, null, 2));
    } catch {}

	await ensureFreshCredentials();
	if (!authState.credentials) {
		sendJson(res, 401, { error: "Authentication required" });
		return;
	}

	const codexUrl = buildCodexUrl(requestUrl);
	const finalBody = sanitizedBody;
	const effectiveBody = parsedBody;

	const headers = createCodexHeaders(undefined, authState.credentials.accountId, authState.credentials.access, {
		model: effectiveBody?.model,
		promptCacheKey: effectiveBody?.prompt_cache_key,
	});
	headers.set("content-type", "application/json");

    const upstreamResponse = await fetch(codexUrl, {
        method: "POST",
        headers,
        body: finalBody,
    });

  let responseForClient = upstreamResponse;
  // If the client did not request streaming, collapse SSE → JSON
  if (!clientStreamRequested) {
    try {
      responseForClient = await convertSseToJson(upstreamResponse, upstreamResponse.headers);
      if (verbose) {
        console.error(`[codex-proxy]   collapsed SSE→JSON trace=${traceId}`);
      }
    } catch (e) {
      // If collapsing fails, fall back to raw stream so caller at least gets something
      console.error(`[${PLUGIN_NAME}] Failed to convert SSE to JSON: ${(e as Error).message}`);
      responseForClient = upstreamResponse;
    }
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
                hadInstructions: typeof (parsedBody as any).instructions === 'string',
                instrLength: typeof (parsedBody as any).instructions === 'string' ? (parsedBody as any).instructions.length : 0,
                include: (parsedBody as any).include,
                responseBody: responseBody.slice(0, 8000),
            });
        } catch (error) {
			console.error(
				`[${PLUGIN_NAME}] Failed to log upstream error: ${(error as Error).message}`,
			);
        }
    }

    const ts2 = new Date().toISOString();
    console.error(`[codex-proxy] ← ${responseForClient.status} ${responseForClient.statusText} dur=${Date.now()-t0}ms trace=${traceId}`);
    console.error(`--- END ${ts2} trace=${traceId} ---`);

    await forwardResponse(responseForClient, res);
}

let globalCodexInstructions: string | null = null;

function extractTextFromContent(content: unknown): string {
    if (typeof content === "string") return content;
    if (Array.isArray(content)) {
        try {
            return content
                .filter((c: any) => c && typeof c === "object")
                .map((c: any) => (typeof c.text === "string" ? c.text : ""))
                .join("\n");
        } catch {
            return "";
        }
    }
    return "";
}

function extractInstructionsFromInput(input: unknown): string | null {
    if (!Array.isArray(input)) return null;
    const parts: string[] = [];
    for (const item of input) {
        if (!item || typeof item !== "object") continue;
        const role = (item as any).role;
        if (role === "developer" || role === "system") {
            const text = extractTextFromContent((item as any).content);
            if (text && text.trim()) parts.push(text.trim());
        }
    }
    if (parts.length === 0) return null;
    return parts.join("\n\n");
}

async function startServer(): Promise<void> {
	try {
		globalCodexInstructions = await getCodexInstructions();
	} catch (e) {
		console.warn(`[${PLUGIN_NAME}] Failed to load Codex instructions: ${(e as Error).message}`);
		globalCodexInstructions = "You are Codex.";
	}
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
				await handleResponsesEndpoint(req, res);
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
