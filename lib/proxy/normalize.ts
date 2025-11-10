type AnyObj = Record<string, any>;

const NAME_MAP: Record<string, string> = {
  // planning
  todo_write: "TodoWrite",
  todowrite: "TodoWrite",
  todo_read: "TodoRead",
  todoread: "TodoRead",
  exit_plan_mode: "exit_plan_mode",

  // files / search
  ls: "LS",
  glob: "Glob",
  grep: "Grep",
  read: "Read",
  write: "Write",
  edit: "Edit",
  multi_edit: "MultiEdit",
  multiedit: "MultiEdit",

  // notebooks
  notebook_read: "NotebookRead",
  notebookedit: "NotebookEdit",
  notebook_edit: "NotebookEdit",

  // shell
  bash: "Bash",

  // web
  web_fetch: "WebFetch",
  webfetch: "WebFetch",
  web_search: "WebSearch",
  websearch: "WebSearch",

  // agent
  task: "Task",
};

function canonicalKey(name: unknown): string | null {
  if (typeof name !== "string" || !name) return null;
  return name.trim().toLowerCase().replace(/[^a-z0-9]+/g, "_");
}

function remapName(name: unknown): string | null {
  const key = canonicalKey(name);
  if (!key) return null;
  return NAME_MAP[key] || null;
}

export function normalizeToolNames(responseJson: AnyObj): AnyObj {
  try {
    const out = responseJson?.output;
    if (!Array.isArray(out)) return responseJson;

    for (const item of out) {
      if (!item || typeof item !== "object") continue;
      if (item.type === "function_call") {
        const mapped = remapName(item.name);
        if (mapped) item.name = mapped;
      }
    }
    return responseJson;
  } catch {
    return responseJson;
  }
}

