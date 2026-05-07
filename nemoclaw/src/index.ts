// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * NemoClaw — OpenClaw Plugin for OpenShell
 *
 * Uses the real OpenClaw plugin API. Types defined locally are minimal stubs
 * that match the OpenClaw SDK interfaces available at runtime via
 * `openclaw/plugin-sdk`. We define them here because the SDK package is only
 * available inside the OpenClaw host process and cannot be imported at build
 * time.
 */

import { handleSlashCommand } from "./commands/slash.js";
import {
  describeOnboardEndpoint,
  describeOnboardProvider,
  loadOnboardConfig,
} from "./onboard/config.js";
import {
  createAccessRequest,
  getAccessRequest,
  listAccessPresets,
  type AccessCanonicalRequest,
  type AccessClientOptions,
  type AccessRequestResponse,
  type AccessStatus,
  type CreateAccessRequestBody,
} from "./access-client.js";
import {
  findRecentAccessDenial,
  readRecentAccessDenials,
  type NemoClawAccessDenial,
} from "./access-denials.js";
import { scanForSecrets, isMemoryPath } from "./security/secret-scanner.js";

type PluginScalar = string | number | boolean | null | undefined;
type PluginValue = PluginScalar | PluginRecord | PluginValue[];
type PluginRecord = { [key: string]: PluginValue };

function isToolParams(value: PluginValue | object | null | undefined): value is ToolParams {
  return (
    value !== null && value !== undefined && typeof value === "object" && !Array.isArray(value)
  );
}

function readStringProperty(
  value: PluginValue | object | null | undefined,
  key: string,
): string | undefined {
  if (!isToolParams(value)) {
    return undefined;
  }
  const property = value[key];
  return typeof property === "string" ? property : undefined;
}

function readBeforeToolCallEvent(
  value: PluginValue | object | null | undefined,
): Partial<BeforeToolCallEvent> | undefined {
  if (!isToolParams(value)) {
    return undefined;
  }
  const params = value["params"];
  return {
    toolName: readStringProperty(value, "toolName"),
    params: isToolParams(params) ? params : undefined,
  };
}

// Resolve live inference model from the OpenClaw config passed to the plugin
// host. Avoid child_process here: OpenClaw's plugin scanner blocks third-party
// plugins that import shell execution APIs, and NemoClaw's access-request
// tools must be available in the sandbox at startup.
function probeOpenClawConfig(config: OpenClawConfig): { endpoint: string; provider: string; model: string } {
  const agents = config["agents"];
  const defaults = isToolParams(agents) ? agents["defaults"] : undefined;
  const modelConfig = isToolParams(defaults) ? defaults["model"] : undefined;
  const primary = readStringProperty(modelConfig, "primary");
  const model = primary?.startsWith("inference/") ? primary.slice("inference/".length) : primary;
  return {
    endpoint: "",
    provider: "",
    model: model ?? "",
  };
}

// ---------------------------------------------------------------------------
// OpenClaw Plugin SDK compatible types (mirrors openclaw/plugin-sdk)
// ---------------------------------------------------------------------------

/** Subset of OpenClawConfig that we actually read. */
export interface OpenClawConfig {
  [key: string]: PluginValue;
}

/** Logger provided by the plugin host. */
export interface PluginLogger {
  info(message: string): void;
  warn(message: string): void;
  error(message: string): void;
  debug(message: string): void;
}

type ToolParams = { [key: string]: PluginValue };

export interface PluginToolResult {
  [key: string]: PluginValue | AccessCanonicalRequest;
}

export interface PluginToolDefinition {
  name: string;
  description: string;
  parameters: PluginRecord;
  execute: (id: string, params: ToolParams) => PluginToolResult | Promise<PluginToolResult>;
}

/** Context passed to slash-command handlers. */
export interface PluginCommandContext {
  senderId?: string;
  channel: string;
  isAuthorizedSender: boolean;
  args?: string;
  commandBody: string;
  config: OpenClawConfig;
  from?: string;
  to?: string;
  accountId?: string;
}

/** Return value from a slash-command handler. */
export interface PluginCommandResult {
  text?: string;
  mediaUrl?: string;
  mediaUrls?: string[];
}

/** Registration shape for a slash command. */
export interface PluginCommandDefinition {
  name: string;
  description: string;
  acceptsArgs?: boolean;
  requireAuth?: boolean;
  handler: (ctx: PluginCommandContext) => PluginCommandResult | Promise<PluginCommandResult>;
}

/** Auth method for a provider plugin. */
export interface ProviderAuthMethod {
  type: string;
  envVar?: string;
  headerName?: string;
  label?: string;
}

/** Model entry in a provider's model catalog. */
export interface ModelProviderEntry {
  id: string;
  label: string;
  contextWindow?: number;
  maxOutput?: number;
}

/** Model catalog shape. */
export interface ModelProviderConfig {
  chat?: ModelProviderEntry[];
  completion?: ModelProviderEntry[];
}

/** Registration shape for a custom model provider. */
export interface ProviderPlugin {
  id: string;
  label: string;
  docsPath?: string;
  aliases?: string[];
  envVars?: string[];
  models?: ModelProviderConfig;
  auth: ProviderAuthMethod[];
}

/** Background service registration. */
export interface PluginService {
  id: string;
  start: (ctx: { config: OpenClawConfig; logger: PluginLogger }) => void | Promise<void>;
  stop?: (ctx: { config: OpenClawConfig; logger: PluginLogger }) => void | Promise<void>;
}

/** Event payload for before_tool_call hooks. */
export interface BeforeToolCallEvent {
  toolName: string;
  params: ToolParams;
  runId?: string;
  toolCallId?: string;
}

/** Return value from a before_tool_call hook. */
export interface BeforeToolCallResult {
  params?: ToolParams;
  block?: boolean;
  blockReason?: string;
}

/**
 * The API object injected into the plugin's register function by the OpenClaw
 * host. Only the methods we actually call are listed here.
 */
export interface OpenClawPluginApi {
  id: string;
  name: string;
  version?: string;
  config: OpenClawConfig;
  pluginConfig?: OpenClawConfig;
  logger: PluginLogger;
  registerCommand: (command: PluginCommandDefinition) => void;
  registerProvider: (provider: ProviderPlugin) => void;
  registerService: (service: PluginService) => void;
  registerTool: (tool: PluginToolDefinition) => void;
  resolvePath: (input: string) => string;
  on: (
    hookName: string,
    handler: (...args: readonly PluginValue[]) => BeforeToolCallResult | undefined,
  ) => void;
}

// ---------------------------------------------------------------------------
// Plugin-specific config (read from pluginConfig in openclaw.plugin.json)
// ---------------------------------------------------------------------------

export interface NemoClawConfig {
  blueprintVersion: string;
  blueprintRegistry: string;
  sandboxName: string;
  inferenceProvider: string;
}

function activeModelEntries(
  onboardCfg: ReturnType<typeof loadOnboardConfig>,
  fallbackModel = "",
): ModelProviderEntry[] {
  // Prefer fallbackModel (live gateway model) over the potentially stale onboard config (#2608).
  const activeModel = fallbackModel || onboardCfg?.model || "";
  if (!activeModel) {
    return [
      {
        id: "nvidia/nemotron-3-super-120b-a12b",
        label: "Nemotron 3 Super 120B (March 2026)",
        contextWindow: 131072,
        maxOutput: 8192,
      },
      {
        id: "nvidia/llama-3.1-nemotron-ultra-253b-v1",
        label: "Nemotron Ultra 253B",
        contextWindow: 131072,
        maxOutput: 4096,
      },
      {
        id: "nvidia/llama-3.3-nemotron-super-49b-v1.5",
        label: "Nemotron Super 49B v1.5",
        contextWindow: 131072,
        maxOutput: 4096,
      },
      {
        id: "nvidia/nemotron-3-nano-30b-a3b",
        label: "Nemotron 3 Nano 30B",
        contextWindow: 131072,
        maxOutput: 4096,
      },
    ];
  }

  return [
    {
      id: `inference/${activeModel}`,
      label: activeModel,
      contextWindow: 131072,
      maxOutput: 8192,
    },
  ];
}

function registeredProviderForConfig(
  onboardCfg: ReturnType<typeof loadOnboardConfig>,
  providerCredentialEnv: string,
  fallbackModel = "",
): ProviderPlugin {
  const authLabel =
    providerCredentialEnv === "NVIDIA_API_KEY"
      ? `NVIDIA API Key (${providerCredentialEnv})`
      : `OpenAI API Key (${providerCredentialEnv})`;

  return {
    id: "inference",
    label: "Managed Inference Route",
    aliases: ["inference-local", "nemoclaw"],
    envVars: [providerCredentialEnv],
    models: { chat: activeModelEntries(onboardCfg, fallbackModel) },
    auth: [
      {
        type: "bearer",
        envVar: providerCredentialEnv,
        headerName: "Authorization",
        label: authLabel,
      },
    ],
  };
}

const DEFAULT_PLUGIN_CONFIG: NemoClawConfig = {
  blueprintVersion: "latest",
  blueprintRegistry: "ghcr.io/nvidia/nemoclaw-blueprint",
  sandboxName: "openclaw",
  inferenceProvider: "nvidia",
};

export function getPluginConfig(api: OpenClawPluginApi): NemoClawConfig {
  const raw = api.pluginConfig ?? {};
  return {
    blueprintVersion:
      typeof raw["blueprintVersion"] === "string"
        ? raw["blueprintVersion"]
        : DEFAULT_PLUGIN_CONFIG.blueprintVersion,
    blueprintRegistry:
      typeof raw["blueprintRegistry"] === "string"
        ? raw["blueprintRegistry"]
        : DEFAULT_PLUGIN_CONFIG.blueprintRegistry,
    sandboxName:
      typeof raw["sandboxName"] === "string"
        ? raw["sandboxName"]
        : DEFAULT_PLUGIN_CONFIG.sandboxName,
    inferenceProvider:
      typeof raw["inferenceProvider"] === "string"
        ? raw["inferenceProvider"]
        : DEFAULT_PLUGIN_CONFIG.inferenceProvider,
  };
}

// ---------------------------------------------------------------------------
// Plugin entry point
// ---------------------------------------------------------------------------

/** Tool names that can write/modify files and should be scanned for secrets. */
const WRITE_TOOL_NAMES = new Set(["write", "edit", "apply_patch", "notebook_edit"]);
const DEFAULT_ACCESS_WAIT_MS = 90_000;
const MAX_ACCESS_WAIT_MS = 300_000;
const ACCESS_POLL_INTERVAL_MS = 1_000;
const TERMINAL_ACCESS_STATUSES = new Set<AccessStatus>([
  "applied",
  "denied",
  "denied_by_ceiling",
  "failed",
  "expired",
]);

function readNumberProperty(
  value: PluginValue | object | null | undefined,
  key: string,
): number | undefined {
  if (!isToolParams(value)) {
    return undefined;
  }
  const property = value[key];
  return typeof property === "number" && Number.isFinite(property) ? property : undefined;
}

function readAccessMode(params: ToolParams): "read" | "read_write" {
  return params["access"] === "read_write" ? "read_write" : "read";
}

function readDuration(params: ToolParams): "session" | "persistent" {
  return params["duration"] === "persistent" ? "persistent" : "session";
}

function normalizeRequestedResource(resource: string): string {
  const normalized = resource.trim().toLowerCase();
  const normalizedHost = (() => {
    if (!normalized.includes("://")) {
      return normalized;
    }
    try {
      return new URL(normalized).hostname.toLowerCase();
    } catch {
      return normalized;
    }
  })();
  if (
    normalizedHost === "github" ||
    normalizedHost === "github.com" ||
    normalizedHost === "api.github.com"
  ) {
    return "github";
  }
  return normalized;
}

function clampWaitTimeout(value: number | undefined, fallback: number): number {
  const timeout = value ?? fallback;
  if (timeout <= 0) {
    return 0;
  }
  return Math.min(timeout, MAX_ACCESS_WAIT_MS);
}

function toToolResult(response: AccessRequestResponse): PluginToolResult {
  return {
    request_id: response.request_id,
    status: response.status,
    message:
      response.message ??
      (TERMINAL_ACCESS_STATUSES.has(response.status)
        ? "NemoClaw returned a terminal access status."
        : "Access request is still pending; call check_resource_access with the request_id to continue polling."),
    ...(response.canonical_request ? { canonical_request: response.canonical_request } : {}),
  };
}

async function waitForAccessStatus(
  initial: AccessRequestResponse,
  timeoutMs: number,
  clientOptions: AccessClientOptions,
): Promise<AccessRequestResponse> {
  if (TERMINAL_ACCESS_STATUSES.has(initial.status) || timeoutMs <= 0) {
    return initial;
  }

  const deadline = Date.now() + timeoutMs;
  let current = initial;
  while (!TERMINAL_ACCESS_STATUSES.has(current.status) && Date.now() < deadline) {
    const remaining = deadline - Date.now();
    await new Promise((resolve) =>
      setTimeout(resolve, Math.min(ACCESS_POLL_INTERVAL_MS, remaining)),
    );
    if (Date.now() > deadline) {
      break;
    }
    current = await getAccessRequest(current.request_id, clientOptions);
  }
  return current;
}

function accessClientOptions(): AccessClientOptions {
  const controlUrl = process.env.NEMOCLAW_CONTROL_URL;
  if (!controlUrl) {
    throw new Error("NEMOCLAW_CONTROL_URL is required for NemoClaw mTLS control access.");
  }
  const caPemB64 = process.env.NEMOCLAW_CONTROL_CA_PEM_B64;
  const certPemB64 = process.env.NEMOCLAW_CONTROL_CERT_PEM_B64;
  const keyPemB64 = process.env.NEMOCLAW_CONTROL_KEY_PEM_B64;
  return {
    controlUrl,
    ...(caPemB64 ? { ca: Buffer.from(caPemB64, "base64").toString("utf-8") } : {}),
    ...(certPemB64 ? { cert: Buffer.from(certPemB64, "base64").toString("utf-8") } : {}),
    ...(keyPemB64 ? { key: Buffer.from(keyPemB64, "base64").toString("utf-8") } : {}),
    ...(process.env.NEMOCLAW_CONTROL_CA_PATH
      ? { caPath: process.env.NEMOCLAW_CONTROL_CA_PATH }
      : {}),
    ...(process.env.NEMOCLAW_CONTROL_CERT_PATH
      ? { certPath: process.env.NEMOCLAW_CONTROL_CERT_PATH }
      : {}),
    ...(process.env.NEMOCLAW_CONTROL_KEY_PATH
      ? { keyPath: process.env.NEMOCLAW_CONTROL_KEY_PATH }
      : {}),
    ...(process.env.NEMOCLAW_CONTROL_SERVERNAME
      ? { servername: process.env.NEMOCLAW_CONTROL_SERVERNAME }
      : {}),
    ...(process.env.NEMOCLAW_PLUGIN_ATTESTATION
      ? { attestationToken: process.env.NEMOCLAW_PLUGIN_ATTESTATION }
      : {}),
  };
}

function createAccessRequestBody(params: ToolParams): CreateAccessRequestBody {
  const userIntent = readStringProperty(params, "user_intent") ?? "";
  const resource = normalizeRequestedResource(readStringProperty(params, "resource") ?? "");
  const reason = readStringProperty(params, "reason") ?? "";
  const taskId = readStringProperty(params, "task_id");

  return {
    version: "nemoclaw.access.v1",
    ...(taskId ? { task_id: taskId } : {}),
    user_intent: userIntent,
    llm_proposal: {
      resource_type: "network",
      preset: resource,
      access: readAccessMode(params),
      duration: readDuration(params),
      reason,
    },
  };
}

function createAccessRequestBodyFromDenial(denial: NemoClawAccessDenial): CreateAccessRequestBody {
  const suggestion = denial.suggested_access;
  if (!suggestion) {
    throw new Error("The denial does not include a suggested access preset.");
  }
  return {
    version: "nemoclaw.access.v1",
    task_id: denial.id,
    user_intent: denial.user_message,
    llm_proposal: {
      resource_type: "network",
      preset: suggestion.resource,
      access: suggestion.access,
      duration: suggestion.duration,
      reason:
        denial.openshell?.detail ??
        `Retry blocked request to ${denial.observed.host ?? denial.observed.url ?? "external resource"}.`,
    },
  };
}

function accessToolParameters(required: string[], properties: PluginRecord): PluginRecord {
  return {
    type: "object",
    additionalProperties: false,
    required,
    properties,
  };
}

export default function register(api: OpenClawPluginApi): void {
  // 1. Register /nemoclaw slash command (chat interface)
  api.registerCommand({
    name: "nemoclaw",
    description: "NemoClaw sandbox management (status, eject).",
    acceptsArgs: true,
    handler: (ctx) => handleSlashCommand(ctx, api),
  });

  // 2. Register nvidia-nim provider — always probe the live gateway inference
  // state so the TUI footer reflects the current model after a runtime
  // `openshell inference set` (#2608).
  const onboardCfg = loadOnboardConfig();
  const probed = probeOpenClawConfig(api.config);

  let bannerEndpoint = onboardCfg ? describeOnboardEndpoint(onboardCfg) : "";
  let bannerProvider = onboardCfg ? describeOnboardProvider(onboardCfg) : "";
  // Prefer the live gateway model over the stale onboard config model.
  let bannerModel = probed.model || onboardCfg?.model || "";

  if (!bannerEndpoint) bannerEndpoint = probed.endpoint;
  if (!bannerProvider) bannerProvider = probed.provider;

  if (!bannerEndpoint) bannerEndpoint = "build.nvidia.com";
  if (!bannerProvider) bannerProvider = "NVIDIA Endpoints";
  if (!bannerModel) bannerModel = "nvidia/nemotron-3-super-120b-a12b";

  const providerCredentialEnv = onboardCfg?.credentialEnv ?? "NVIDIA_API_KEY";
  api.registerProvider(
    registeredProviderForConfig(onboardCfg, providerCredentialEnv, probed.model),
  );

  api.registerTool({
    name: "request_resource_access",
    description:
      "Request least-privilege external resource access through NemoClaw. The resource field must be a NemoClaw preset id, not a hostname. Call list_resource_access_presets first if you are unsure which preset to request. Prefer read access unless the task clearly requires mutation. This proposes access only; NemoClaw and OpenShell decide and enforce.",
    parameters: accessToolParameters(["user_intent", "resource", "reason"], {
      user_intent: {
        type: "string",
        description: "The user's natural-language request.",
      },
      resource: {
        type: "string",
        description:
          "NemoClaw preset id to request. Use list_resource_access_presets to discover valid preset ids. Use github for GitHub hosts such as github.com and api.github.com.",
      },
      access: {
        type: "string",
        enum: ["read", "read_write"],
        default: "read",
        description: "Requested access mode. Use read unless mutation is required.",
      },
      reason: {
        type: "string",
        description: "Why this access is needed for the current task.",
      },
      duration: {
        type: "string",
        enum: ["session", "persistent"],
        default: "session",
        description: "Requested duration. Session access is the v1 default.",
      },
      task_id: {
        type: "string",
        description: "Optional opaque task identifier for NemoClaw correlation.",
      },
      wait_timeout_ms: {
        type: "number",
        minimum: 0,
        maximum: MAX_ACCESS_WAIT_MS,
        default: DEFAULT_ACCESS_WAIT_MS,
        description: "How long to wait for a terminal status before returning pending.",
      },
    }),
    async execute(_id, params) {
      const clientOptions = accessClientOptions();
      const response = await createAccessRequest(createAccessRequestBody(params), clientOptions);
      const timeoutMs = clampWaitTimeout(
        readNumberProperty(params, "wait_timeout_ms"),
        DEFAULT_ACCESS_WAIT_MS,
      );
      return toToolResult(await waitForAccessStatus(response, timeoutMs, clientOptions));
    },
  });

  api.registerTool({
    name: "list_resource_access_presets",
    description:
      "List NemoClaw resource-access preset ids currently accepted for access requests. Call this before request_resource_access when the needed preset is unclear.",
    parameters: accessToolParameters([], {}),
    async execute() {
      const response = await listAccessPresets(accessClientOptions());
      return {
        presets: response.presets.map((preset) => ({
          name: preset.name,
          description: preset.description,
        })),
      };
    },
  });

  api.registerTool({
    name: "check_resource_access",
    description:
      "Check or continue waiting for a NemoClaw access request. This reports status only and cannot approve or modify access.",
    parameters: accessToolParameters(["request_id"], {
      request_id: {
        type: "string",
        description: "The request_id returned by request_resource_access.",
      },
      wait_timeout_ms: {
        type: "number",
        minimum: 0,
        maximum: MAX_ACCESS_WAIT_MS,
        default: 0,
        description: "Optional time to wait for a terminal status before returning pending.",
      },
    }),
    async execute(_id, params) {
      const requestId = readStringProperty(params, "request_id");
      if (!requestId) {
        return {
          request_id: "",
          status: "failed",
          message: "Missing request_id.",
        };
      }

      const clientOptions = accessClientOptions();
      const response = await getAccessRequest(requestId, clientOptions);
      const timeoutMs = clampWaitTimeout(readNumberProperty(params, "wait_timeout_ms"), 0);
      return toToolResult(await waitForAccessStatus(response, timeoutMs, clientOptions));
    },
  });

  api.registerTool({
    name: "get_recent_access_denials",
    description:
      "List recent structured NemoClaw network policy denials observed inside the sandbox. Use this after a network/tool failure to decide whether to request operator-approved resource access.",
    parameters: accessToolParameters([], {
      limit: {
        type: "number",
        minimum: 1,
        maximum: 20,
        default: 5,
        description: "Maximum number of recent denials to return.",
      },
    }),
    execute(_id, params) {
      const limit = readNumberProperty(params, "limit") ?? 5;
      return {
        denials: readRecentAccessDenials({ limit }),
      };
    },
  });

  api.registerTool({
    name: "request_access_for_denial",
    description:
      "Request operator approval using the suggested access from a recent NemoClaw structured network denial. This cannot approve access; it only creates or polls a host-side access request.",
    parameters: accessToolParameters(["denial_id"], {
      denial_id: {
        type: "string",
        description: "The denial id returned by get_recent_access_denials.",
      },
      wait_timeout_ms: {
        type: "number",
        minimum: 0,
        maximum: MAX_ACCESS_WAIT_MS,
        default: DEFAULT_ACCESS_WAIT_MS,
        description: "How long to wait for a terminal status before returning pending.",
      },
    }),
    async execute(_id, params) {
      const denialId = readStringProperty(params, "denial_id");
      if (!denialId) {
        return {
          request_id: "",
          status: "failed",
          message: "Missing denial_id.",
        };
      }
      const denial = findRecentAccessDenial(denialId);
      if (!denial) {
        return {
          request_id: "",
          status: "failed",
          message: `Access denial not found: ${denialId}`,
        };
      }

      const clientOptions = accessClientOptions();
      const response = await createAccessRequest(
        createAccessRequestBodyFromDenial(denial),
        clientOptions,
      );
      const timeoutMs = clampWaitTimeout(
        readNumberProperty(params, "wait_timeout_ms"),
        DEFAULT_ACCESS_WAIT_MS,
      );
      return toToolResult(await waitForAccessStatus(response, timeoutMs, clientOptions));
    },
  });

  // 3. Register before_tool_call hook to block secrets in memory writes (#1233)
  // NOTE: This relies on OpenClaw's before_tool_call plugin hook contract
  // (PluginHookBeforeToolCallEvent/Result in openclaw/src/plugins/types.ts).
  // If the hook name or return shape changes in a future OpenClaw release,
  // the try/catch ensures the plugin still loads — the scanner just becomes
  // a no-op. Verify after OpenClaw upgrades that blocked writes still show
  // the expected error message.
  try {
    api.on(
      "before_tool_call",
      (...args: readonly PluginValue[]): BeforeToolCallResult | undefined => {
        const event = readBeforeToolCallEvent(args[0]);
        if (!event?.toolName || !event.params) return undefined;

        const toolName = event.toolName.toLowerCase();
        if (!WRITE_TOOL_NAMES.has(toolName)) return undefined;

        const rawPath = event.params["file_path"] ?? event.params["path"];
        if (typeof rawPath !== "string" || rawPath.length === 0) return undefined;
        // Resolve symlinks and traversal before checking — prevents bypasses like
        // /sandbox/project/../../.openclaw-data/memory/secrets.md
        const filePath = api.resolvePath(rawPath);
        if (!isMemoryPath(filePath)) return undefined;

        const content =
          event.params["content"] ?? event.params["new_string"] ?? event.params["patch"];
        if (typeof content !== "string" || content.length === 0) return undefined;

        const matches = scanForSecrets(content);
        if (matches.length === 0) return undefined;

        const summary = matches.map((m) => `  - ${m.pattern} (${m.redacted})`).join("\n");
        api.logger.warn(`[SECURITY] Blocked memory write to ${filePath} — secrets detected`);

        return {
          block: true,
          blockReason:
            `Memory write blocked: detected ${String(matches.length)} likely secret(s):\n${summary}\n\n` +
            "Remove secrets before saving to persistent memory. " +
            "Use environment variables or credential stores instead.",
        };
      },
    );
  } catch (err) {
    api.logger.warn(
      `[SECURITY] Could not register secret scanner hook: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  api.logger.info("");
  api.logger.info("  ┌─────────────────────────────────────────────────────┐");
  api.logger.info("  │  NemoClaw registered                                │");
  api.logger.info("  │                                                     │");
  api.logger.info(`  │  Endpoint:  ${bannerEndpoint.padEnd(40)}│`);
  api.logger.info(`  │  Provider:  ${bannerProvider.padEnd(40)}│`);
  api.logger.info(`  │  Model:     ${bannerModel.padEnd(40)}│`);
  api.logger.info("  │  Slash:     /nemoclaw                               │");
  api.logger.info("  └─────────────────────────────────────────────────────┘");
  api.logger.info("");
}
