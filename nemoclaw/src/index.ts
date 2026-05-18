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

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { renderBox } from "./banner.js";
import { handleSlashCommand } from "./commands/slash.js";
import {
  describeOnboardEndpoint,
  describeOnboardProvider,
  loadOnboardConfig,
} from "./onboard/config.js";
import {
  createAccessRequest,
  createProviderAccessRequest,
  getAccessRequest,
  getProviderAccess,
  listAccessPresets,
  listProviderAccess,
  waitAccessRequest,
  type AccessCanonicalRequest,
  type AccessClientOptions,
  type AccessRequestResponse,
  type AccessStatus,
  type CreateAccessRequestBody,
  type CreateProviderAccessRequestBody,
} from "./access-client.js";
import { registerRuntimeContext } from "./runtime-context.js";
import { scanForSecrets, isMemoryPath } from "./security/secret-scanner.js";

type PluginScalar = string | number | boolean | null | undefined;
type PluginValue = PluginScalar | PluginRecord | PluginValue[];
type PluginRecord = { [key: string]: PluginValue };

type ProviderToolHint = {
  tool: string;
  paths: string[];
  role: "preferred" | "fallback";
};

type ProviderCredentialHint = {
  kind: string;
  header?: string;
  value?: string;
  note: string;
};

const PROVIDER_TOOL_HINTS: Record<string, ProviderToolHint[]> = {
  anthropic: [
    { tool: "curl", paths: ["/usr/bin/curl", "/usr/local/bin/curl"], role: "preferred" },
    { tool: "node", paths: ["/usr/bin/node", "/usr/local/bin/node"], role: "fallback" },
  ],
  brave: [
    { tool: "curl", paths: ["/usr/bin/curl", "/usr/local/bin/curl"], role: "preferred" },
    { tool: "node", paths: ["/usr/bin/node", "/usr/local/bin/node"], role: "fallback" },
  ],
  claude: [
    { tool: "claude", paths: ["/usr/bin/claude", "/usr/local/bin/claude"], role: "preferred" },
    { tool: "curl", paths: ["/usr/bin/curl", "/usr/local/bin/curl"], role: "fallback" },
    { tool: "node", paths: ["/usr/bin/node", "/usr/local/bin/node"], role: "fallback" },
  ],
  codex: [
    { tool: "codex", paths: ["/usr/bin/codex", "/usr/local/bin/codex"], role: "preferred" },
    { tool: "curl", paths: ["/usr/bin/curl", "/usr/local/bin/curl"], role: "fallback" },
    { tool: "node", paths: ["/usr/bin/node", "/usr/local/bin/node"], role: "fallback" },
  ],
  copilot: [
    { tool: "copilot", paths: ["/usr/bin/copilot", "/usr/local/bin/copilot"], role: "preferred" },
    { tool: "gh", paths: ["/usr/bin/gh", "/usr/local/bin/gh"], role: "fallback" },
  ],
  discord: [
    { tool: "node", paths: ["/usr/bin/node", "/usr/local/bin/node"], role: "preferred" },
    { tool: "curl", paths: ["/usr/bin/curl", "/usr/local/bin/curl"], role: "fallback" },
  ],
  github: [
    { tool: "gh", paths: ["/usr/bin/gh", "/usr/local/bin/gh"], role: "preferred" },
    { tool: "curl", paths: ["/usr/bin/curl", "/usr/local/bin/curl"], role: "fallback" },
    { tool: "git", paths: ["/usr/bin/git", "/usr/local/bin/git"], role: "fallback" },
    { tool: "node", paths: ["/usr/bin/node", "/usr/local/bin/node"], role: "fallback" },
  ],
  gitlab: [
    { tool: "glab", paths: ["/usr/bin/glab", "/usr/local/bin/glab"], role: "preferred" },
    { tool: "curl", paths: ["/usr/bin/curl", "/usr/local/bin/curl"], role: "fallback" },
    { tool: "git", paths: ["/usr/bin/git", "/usr/local/bin/git"], role: "fallback" },
    { tool: "node", paths: ["/usr/bin/node", "/usr/local/bin/node"], role: "fallback" },
  ],
  huggingface: [
    { tool: "python3", paths: ["/usr/bin/python3", "/usr/local/bin/python3"], role: "preferred" },
    { tool: "node", paths: ["/usr/bin/node", "/usr/local/bin/node"], role: "fallback" },
    { tool: "curl", paths: ["/usr/bin/curl", "/usr/local/bin/curl"], role: "fallback" },
  ],
  jira: [
    { tool: "node", paths: ["/usr/bin/node", "/usr/local/bin/node"], role: "preferred" },
    { tool: "curl", paths: ["/usr/bin/curl", "/usr/local/bin/curl"], role: "fallback" },
  ],
  nvidia: [
    { tool: "curl", paths: ["/usr/bin/curl", "/usr/local/bin/curl"], role: "preferred" },
    { tool: "node", paths: ["/usr/bin/node", "/usr/local/bin/node"], role: "fallback" },
  ],
  openai: [
    { tool: "curl", paths: ["/usr/bin/curl", "/usr/local/bin/curl"], role: "preferred" },
    { tool: "node", paths: ["/usr/bin/node", "/usr/local/bin/node"], role: "fallback" },
  ],
  opencode: [
    {
      tool: "opencode",
      paths: ["/usr/bin/opencode", "/usr/local/bin/opencode"],
      role: "preferred",
    },
    { tool: "curl", paths: ["/usr/bin/curl", "/usr/local/bin/curl"], role: "fallback" },
    { tool: "node", paths: ["/usr/bin/node", "/usr/local/bin/node"], role: "fallback" },
  ],
  slack: [
    { tool: "node", paths: ["/usr/bin/node", "/usr/local/bin/node"], role: "preferred" },
    { tool: "curl", paths: ["/usr/bin/curl", "/usr/local/bin/curl"], role: "fallback" },
  ],
  telegram: [
    { tool: "node", paths: ["/usr/bin/node", "/usr/local/bin/node"], role: "preferred" },
    { tool: "curl", paths: ["/usr/bin/curl", "/usr/local/bin/curl"], role: "fallback" },
  ],
};

const PROVIDER_CREDENTIAL_HINTS: Record<string, ProviderCredentialHint> = {
  anthropic: {
    kind: "api_key_header",
    header: "x-api-key",
    value: "$ENV",
    note: "Use the provider's required Anthropic version header alongside x-api-key. Route requests through the sandbox HTTP(S) proxy so OpenShell can resolve placeholders.",
  },
  brave: {
    kind: "api_key_header",
    header: "X-Subscription-Token",
    value: "$ENV",
    note: "Use the Brave Search subscription token header through the sandbox HTTP(S) proxy.",
  },
  github: {
    kind: "bearer_header",
    header: "Authorization",
    value: "Bearer $ENV",
    note: "Use the GitHub CLI when available, or pass this Authorization header through the sandbox HTTP(S) proxy for direct API calls.",
  },
  gitlab: {
    kind: "bearer_header",
    header: "Authorization",
    value: "Bearer $ENV",
    note: "Use glab when available, or pass this Authorization header through the sandbox HTTP(S) proxy for direct API calls.",
  },
  huggingface: {
    kind: "bearer_header",
    header: "Authorization",
    value: "Bearer $ENV",
    note: "Use this Authorization header through the sandbox HTTP(S) proxy for Hugging Face API calls.",
  },
  nvidia: {
    kind: "bearer_header",
    header: "Authorization",
    value: "Bearer $ENV",
    note: "Use this Authorization header through the sandbox HTTP(S) proxy for NVIDIA API calls.",
  },
  openai: {
    kind: "bearer_header",
    header: "Authorization",
    value: "Bearer $ENV",
    note: "Use this Authorization header through the sandbox HTTP(S) proxy for OpenAI-compatible API calls.",
  },
  opencode: {
    kind: "provider_cli_or_documented_auth",
    note: "Prefer the provider CLI. For direct API calls, use the provider-documented authentication format through the sandbox HTTP(S) proxy; do not assume a bearer header.",
  },
  slack: {
    kind: "bearer_header",
    header: "Authorization",
    value: "Bearer $ENV",
    note: "Use Slack SDKs or pass this Authorization header through the sandbox HTTP(S) proxy when the token type supports Web API calls.",
  },
  telegram: {
    kind: "provider_url_token",
    note: "Telegram bot tokens are normally part of the Bot API URL path. Use Telegram-specific tooling or API URL construction through the sandbox HTTP(S) proxy; do not send it as a generic bearer header.",
  },
};

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

// Resolve live inference config from OpenShell as a fallback when the
// onboard config file is not available (e.g. when running inside the
// sandbox). Returns empty strings if the probe fails.
function probeOpenShellInference(): { endpoint: string; provider: string; model: string } {
  try {
    const raw = execFileSync("openshell", ["inference", "get", "--json"], {
      encoding: "utf-8",
      timeout: 3000,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const parsed: unknown = JSON.parse(raw);
    const parsedObject = typeof parsed === "object" && parsed !== null ? parsed : null;
    const endpoint = readStringProperty(parsedObject, "endpoint");
    const provider = readStringProperty(parsedObject, "provider");
    const model = readStringProperty(parsedObject, "model");
    return {
      endpoint: endpoint ?? "",
      provider: provider ?? "",
      model: model ?? "",
    };
  } catch {
    return { endpoint: "", provider: "", model: "" };
  }
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

/** Return value from a before_prompt_build hook. */
export interface BeforePromptBuildResult {
  systemPrompt?: string;
  prependContext?: string;
  appendContext?: string;
  prependSystemContext?: string;
  appendSystemContext?: string;
}

/** Union of all hook result types. */
export type HookResult = BeforeToolCallResult | BeforePromptBuildResult | undefined;

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
    handler: (...args: readonly PluginValue[]) => HookResult | Promise<HookResult>,
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
const TERMINAL_ACCESS_STATUSES = new Set<AccessStatus>(["applied", "denied", "failed"]);

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
  return normalizedHost;
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
        ? "OpenShell returned a terminal access status."
        : "Access request is still pending; call the matching OpenShell access tool with action=check and this request_id to continue polling."),
    ...(response.canonical_request ? { canonical_request: response.canonical_request } : {}),
  };
}

function providerAccessToolResult(
  providerName: string,
  attached: Awaited<ReturnType<typeof getProviderAccess>>,
): PluginToolResult {
  if (!attached) {
    return {
      provider_name: providerName,
      status: "pending_approval",
      message:
        "Provider is not attached to this sandbox. Use openshell_provider_access action=request if this task needs its credential or account-backed network access.",
    };
  }
  return {
    ...providerAccessDetails(attached),
    status: "applied",
    message:
      "Provider credential and provider policy are attached to this sandbox. Follow credential_usage and available_tools; do not request this provider again unless it is detached.",
  };
}

function normalizeProviderKey(providerName: string, providerType?: string): string {
  return (providerType || providerName).trim().toLowerCase();
}

function providerToolReport(providerName: string, providerType?: string): PluginRecord {
  const hints = PROVIDER_TOOL_HINTS[normalizeProviderKey(providerName, providerType)] ?? [];
  const availableTools = new Set<string>();
  const missingTools = new Set<string>();
  const availableBinaries: string[] = [];
  const missingBinaries: string[] = [];
  const preferredTools = new Set<string>();
  const fallbackTools = new Set<string>();

  for (const hint of hints) {
    if (hint.role === "preferred") preferredTools.add(hint.tool);
    if (hint.role === "fallback") fallbackTools.add(hint.tool);
    const existingPath = hint.paths.find((path) => existsSync(path));
    if (existingPath) {
      availableTools.add(hint.tool);
      availableBinaries.push(existingPath);
      for (const path of hint.paths) {
        if (path !== existingPath && !existsSync(path)) missingBinaries.push(path);
      }
    } else {
      missingTools.add(hint.tool);
      missingBinaries.push(...hint.paths);
    }
  }

  return {
    available_tools: [...availableTools],
    missing_tools: [...missingTools],
    preferred_tools: [...preferredTools],
    fallback_tools: [...fallbackTools],
    available_binaries: availableBinaries,
    missing_binaries: missingBinaries,
  };
}

function providerCredentialUsage(
  attached: NonNullable<Awaited<ReturnType<typeof getProviderAccess>>>,
): PluginRecord | undefined {
  if (!attached.credential_env) return undefined;
  const hint = PROVIDER_CREDENTIAL_HINTS[
    normalizeProviderKey(attached.provider_name, attached.provider_type)
  ] ?? {
    kind: "provider_cli_or_documented_auth",
    note: "Prefer the provider CLI if available. For direct API calls, use the provider-documented authentication format through the sandbox HTTP(S) proxy; do not assume a bearer header.",
  };
  const value = hint.value?.replace("$ENV", `$${attached.credential_env}`);
  return {
    kind: hint.kind,
    ...(hint.header ? { header: hint.header } : {}),
    ...(value ? { value } : {}),
    proxy_required: true,
    proxy_env: ["HTTP_PROXY", "HTTPS_PROXY"],
    note: `${hint.note} OpenShell resolves openshell:resolve:env:* placeholders at the proxy; do not print or decode them.`,
  };
}

function providerAccessDetails(
  attached: NonNullable<Awaited<ReturnType<typeof getProviderAccess>>>,
): PluginRecord {
  const credentialUsage = providerCredentialUsage(attached);
  const toolReport = providerToolReport(attached.provider_name, attached.provider_type);
  const availableTools = Array.isArray(toolReport.available_tools)
    ? toolReport.available_tools.filter((tool): tool is string => typeof tool === "string")
    : [];
  const nextStep =
    credentialUsage && availableTools.some((tool) => tool === "gh" || tool === "glab")
      ? "Use the provider CLI shown in available_tools, or use credential_usage through HTTPS_PROXY for direct API calls."
      : credentialUsage &&
          availableTools.includes("curl") &&
          credentialUsage.header &&
          credentialUsage.value
        ? `Use curl with ${credentialUsage.header}: ${credentialUsage.value} through HTTPS_PROXY.`
        : credentialUsage
          ? "Use credential_usage through HTTP_PROXY/HTTPS_PROXY with an available fallback tool."
          : "Provider is attached, but no credential env was reported; inspect /v1/providers or ask the operator to reattach credentials.";

  return {
    provider_name: attached.provider_name,
    ...(attached.provider_type ? { provider_type: attached.provider_type } : {}),
    credential_state: attached.credential_state,
    usable_via_proxy: attached.usable_via_proxy,
    raw_secret_available: attached.raw_secret_available,
    credential_available: attached.credential_available,
    ...(attached.credential_env ? { credential_env: attached.credential_env } : {}),
    ...(credentialUsage ? { credential_usage: credentialUsage } : {}),
    ...toolReport,
    next_step: nextStep,
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
  return waitAccessRequest(initial.request_id, timeoutMs, clientOptions);
}

function accessClientOptions(): AccessClientOptions {
  return {
    ...(process.env.OPENSHELL_POLICY_LOCAL_URL
      ? { policyLocalUrl: process.env.OPENSHELL_POLICY_LOCAL_URL }
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

function createProviderAccessRequestBody(params: ToolParams): CreateProviderAccessRequestBody {
  const userIntent = readStringProperty(params, "user_intent") ?? "";
  const providerName = readStringProperty(params, "provider_name") ?? "";
  const providerType = readStringProperty(params, "provider_type");
  const reason = readStringProperty(params, "reason") ?? "";
  const taskId = readStringProperty(params, "task_id");

  return {
    version: "nemoclaw.provider_access.v1",
    ...(taskId ? { task_id: taskId } : {}),
    user_intent: userIntent,
    provider_name: providerName.trim(),
    ...(providerType ? { provider_type: providerType.trim() } : {}),
    reason,
  };
}

function readToolAction(params: ToolParams): string {
  return (readStringProperty(params, "action") ?? "").trim().toLowerCase();
}

function missingStringFields(params: ToolParams, fields: string[]): string[] {
  return fields.filter((field) => !readStringProperty(params, field)?.trim());
}

function validationFailure(message: string): PluginToolResult {
  return {
    status: "failed",
    message,
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
  const probed = probeOpenShellInference();

  // 4. Register runtime context injection (sandbox-awareness hook)
  const pluginConfig = getPluginConfig(api);
  try {
    registerRuntimeContext(api, pluginConfig);
  } catch (err) {
    api.logger.warn(
      `Could not register runtime context hook: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

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
    name: "openshell_provider_access",
    description:
      "List, check, or request OpenShell provider access for this sandbox. Provider access is the preferred path for authenticated/account-backed work because a provider may attach both credentials and the required network/resource policy. Use action=list before requesting network-only access.",
    parameters: accessToolParameters(["action"], {
      action: {
        type: "string",
        enum: ["list", "check", "request"],
        description:
          "list returns attached provider credentials; check reads a request_id or provider_name; request asks OpenShell to attach an existing host-managed provider.",
      },
      provider_name: {
        type: "string",
        description: "Provider name, for example github.",
      },
      provider_type: {
        type: "string",
        description:
          "Optional expected provider type, for example github. Request approval fails if the provider exists with a different type.",
      },
      request_id: {
        type: "string",
        description: "Request id returned by action=request.",
      },
      user_intent: {
        type: "string",
        description: "The user's natural-language request. Required for action=request.",
      },
      reason: {
        type: "string",
        description:
          "Why this provider is needed for the current task. Required for action=request.",
      },
      task_id: {
        type: "string",
        description: "Optional opaque task identifier for correlation.",
      },
      wait_timeout_ms: {
        type: "number",
        minimum: 0,
        maximum: MAX_ACCESS_WAIT_MS,
        default: 0,
        description:
          "For action=request or check by request_id, optional time to wait for terminal status.",
      },
    }),
    async execute(_id, params) {
      const action = readToolAction(params);
      const clientOptions = accessClientOptions();

      if (action === "list") {
        const response = await listProviderAccess(clientOptions);
        return {
          credential_usage:
            "Provider credential environment values may be openshell:resolve:env:* placeholders. Use the per-provider credential_usage through the sandbox HTTP_PROXY/HTTPS_PROXY so OpenShell can resolve the placeholder at the proxy; do not decode, print, or treat it as a raw token.",
          providers: response.providers.map((provider) => ({
            ...providerAccessDetails(provider),
            status: provider.status,
          })),
        };
      }

      if (action === "check") {
        const requestId = readStringProperty(params, "request_id");
        if (requestId) {
          const response = await getAccessRequest(requestId, clientOptions);
          const timeoutMs = clampWaitTimeout(readNumberProperty(params, "wait_timeout_ms"), 0);
          return toToolResult(await waitForAccessStatus(response, timeoutMs, clientOptions));
        }
        const providerName = readStringProperty(params, "provider_name")?.trim();
        if (!providerName) {
          return {
            provider_name: "",
            status: "failed",
            message: "For action=check, provide either request_id or provider_name.",
          };
        }
        return providerAccessToolResult(
          providerName,
          await getProviderAccess(providerName, clientOptions),
        );
      }

      if (action === "request") {
        const missing = missingStringFields(params, ["provider_name", "user_intent", "reason"]);
        if (missing.length > 0) {
          return validationFailure(
            `For action=request, provide required field(s): ${missing.join(", ")}.`,
          );
        }
        const providerName = readStringProperty(params, "provider_name")?.trim();
        if (providerName) {
          const attached = await getProviderAccess(providerName, clientOptions);
          if (attached) {
            return providerAccessToolResult(providerName, attached);
          }
        }
        const response = await createProviderAccessRequest(
          createProviderAccessRequestBody(params),
          clientOptions,
        );
        const timeoutMs = clampWaitTimeout(
          readNumberProperty(params, "wait_timeout_ms"),
          DEFAULT_ACCESS_WAIT_MS,
        );
        return toToolResult(await waitForAccessStatus(response, timeoutMs, clientOptions));
      }

      return {
        status: "failed",
        message: "Unknown action. Use one of: list, check, request.",
      };
    },
  });

  api.registerTool({
    name: "openshell_network_access",
    description:
      "List, check, or request OpenShell network-only access for this sandbox. Use this for unauthenticated network/resource reachability. If the task may need authentication, API tokens, OAuth, or account identity, call openshell_provider_access action=list first and prefer provider access.",
    parameters: accessToolParameters(["action"], {
      action: {
        type: "string",
        enum: ["list_presets", "check", "request"],
        description:
          "list_presets returns requestable network/resource presets; check reads a request_id; request asks OpenShell for network-only access.",
      },
      resource: {
        type: "string",
        description:
          "Preset id to request. Use action=list_presets to discover valid ids. Use github for GitHub hosts such as github.com and api.github.com.",
      },
      access: {
        type: "string",
        enum: ["read", "read_write"],
        default: "read",
        description: "Requested access mode. Use read unless mutation is required.",
      },
      duration: {
        type: "string",
        enum: ["session", "persistent"],
        default: "session",
        description: "Requested duration. Session access is the default.",
      },
      request_id: {
        type: "string",
        description: "Request id returned by action=request.",
      },
      user_intent: {
        type: "string",
        description: "The user's natural-language request. Required for action=request.",
      },
      reason: {
        type: "string",
        description: "Why this network access is needed. Required for action=request.",
      },
      task_id: {
        type: "string",
        description: "Optional opaque task identifier for correlation.",
      },
      wait_timeout_ms: {
        type: "number",
        minimum: 0,
        maximum: MAX_ACCESS_WAIT_MS,
        default: 0,
        description: "For action=request or check, optional time to wait for terminal status.",
      },
    }),
    async execute(_id, params) {
      const action = readToolAction(params);
      const clientOptions = accessClientOptions();

      if (action === "list_presets") {
        const response = await listAccessPresets(clientOptions);
        return {
          presets: response.presets.map((preset) => ({
            name: preset.name,
            description: preset.description,
            ...(preset.provider_profile ? { provider_profile: preset.provider_profile } : {}),
          })),
        };
      }

      if (action === "check") {
        const requestId = readStringProperty(params, "request_id");
        if (!requestId) {
          return {
            request_id: "",
            status: "failed",
            message: "For action=check, provide request_id.",
          };
        }
        const response = await getAccessRequest(requestId, clientOptions);
        const timeoutMs = clampWaitTimeout(readNumberProperty(params, "wait_timeout_ms"), 0);
        return toToolResult(await waitForAccessStatus(response, timeoutMs, clientOptions));
      }

      if (action === "request") {
        const missing = missingStringFields(params, ["resource", "user_intent", "reason"]);
        if (missing.length > 0) {
          return validationFailure(
            `For action=request, provide required field(s): ${missing.join(", ")}.`,
          );
        }
        const response = await createAccessRequest(createAccessRequestBody(params), clientOptions);
        const timeoutMs = clampWaitTimeout(
          readNumberProperty(params, "wait_timeout_ms"),
          DEFAULT_ACCESS_WAIT_MS,
        );
        return toToolResult(await waitForAccessStatus(response, timeoutMs, clientOptions));
      }

      return {
        status: "failed",
        message: "Unknown action. Use one of: list_presets, check, request.",
      };
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
        // /sandbox/project/../../.openclaw/memory/secrets.md
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

  const bannerLines = [
    "  NemoClaw registered",
    null,
    `  Endpoint:  ${bannerEndpoint}`,
    `  Provider:  ${bannerProvider}`,
    `  Model:     ${bannerModel}`,
    "  Slash:     /nemoclaw",
  ];

  api.logger.info("");
  for (const line of renderBox(bannerLines)) {
    api.logger.info(line);
  }
  api.logger.info("");
}
