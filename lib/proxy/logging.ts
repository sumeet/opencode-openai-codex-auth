import { appendFileSync, existsSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir } from "node:os";

const DEFAULT_LOG_PATH = join(homedir(), ".opencode", "logs", "codex-proxy-errors.ndjson");
const LOG_PATH = process.env.CODEX_PROXY_LOG_PATH ?? DEFAULT_LOG_PATH;

function ensureParentDir(): void {
	const dir = dirname(LOG_PATH);
	if (!existsSync(dir)) {
		mkdirSync(dir, { recursive: true });
	}
}

export interface ProxyErrorLog {
	traceId: string;
	url: string;
	status: number;
	statusText: string;
	model?: string;
	hasTools?: boolean;
	bodyLength?: number;
	responseBody?: string;
}

export function logProxyError(entry: ProxyErrorLog): void {
	try {
		ensureParentDir();
		const record = {
			timestamp: new Date().toISOString(),
			...entry,
		};
		appendFileSync(LOG_PATH, `${JSON.stringify(record)}\n`, "utf8");
	} catch (error) {
		console.error("[openai-codex-plugin] Failed to write proxy log:", (error as Error).message);
	}
}
