// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { execFileSync } from "node:child_process";
import http from "node:http";
import net from "node:net";

export type AccessStatus = "pending_approval" | "applied" | "denied" | "failed";

export type AccessCanonicalRequest = {
  [key: string]: unknown;
};

export interface AccessRequestResponse {
  request_id: string;
  status: AccessStatus;
  message?: string;
  canonical_request?: AccessCanonicalRequest;
}

export interface AccessPresetInfo {
  name: string;
  description: string;
  provider_profile?: string;
}

export interface AccessPresetsResponse {
  presets: AccessPresetInfo[];
}

export interface ProviderAccessInfo {
  provider_name: string;
  provider_type?: string;
  status: "attached";
  credential_env?: string;
  credential_state: "attached_placeholder" | "attached_unknown";
  usable_via_proxy: boolean;
  raw_secret_available: boolean;
  /** @deprecated Use credential_state and usable_via_proxy. */
  credential_available: boolean;
}

export interface ProviderAccessResponse {
  providers: ProviderAccessInfo[];
}

export interface CreateAccessRequestBody {
  version: "nemoclaw.access.v1";
  task_id?: string;
  user_intent: string;
  llm_proposal: {
    resource_type: "network";
    preset: string;
    access: "read" | "read_write";
    duration: "session" | "persistent";
    reason: string;
  };
}

export interface CreateProviderAccessRequestBody {
  version: "nemoclaw.provider_access.v1";
  task_id?: string;
  user_intent: string;
  provider_name: string;
  provider_type?: string;
  reason: string;
}

export interface AccessClientOptions {
  policyLocalUrl?: string;
  timeoutMs?: number;
}

type L7Rule = {
  allow: {
    method: string;
    path: string;
  };
};

type NetworkEndpoint = {
  host: string;
  port: number;
  protocol?: string;
  enforcement?: string;
  access?: string;
  tls?: string;
  rules?: L7Rule[];
};

type NetworkRule = {
  name: string;
  endpoints: NetworkEndpoint[];
  binaries: Array<{ path: string }>;
};

type AccessPreset = AccessPresetInfo & {
  rule: NetworkRule;
};

type ProviderProfileEndpoint = {
  host?: unknown;
  port?: unknown;
  protocol?: unknown;
  tls?: unknown;
  access?: unknown;
  enforcement?: unknown;
  rules?: unknown;
  allowed_ips?: unknown;
  ports?: unknown;
  deny_rules?: unknown;
  allow_encoded_slash?: unknown;
  websocket_credential_rewrite?: unknown;
  request_body_credential_rewrite?: unknown;
  persisted_queries?: unknown;
  graphql_persisted_queries?: unknown;
  graphql_max_body_bytes?: unknown;
  path?: unknown;
};

type ProviderProfile = {
  id: string;
  display_name?: string;
  description?: string;
  endpoints?: ProviderProfileEndpoint[];
  binaries?: Array<string | { path?: unknown }>;
};

type AttachedProvider = {
  provider_name: string;
  provider_type?: string;
  credential_env?: string;
};

type AttachedProviderJson = Record<string, unknown> & {
  provider_name: string;
};

const NODE_BINARIES = [{ path: "/usr/local/bin/node" }, { path: "/usr/bin/node" }];
const READ_METHODS = ["GET", "HEAD"];
const READ_WRITE_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];
const PROVIDER_PROFILE_CACHE_MS = 30_000;
const PROVIDER_ENV_PLACEHOLDER_PREFIX = "openshell:resolve:env:";

const PROVIDER_ENV_HINTS: Record<string, { provider_name: string; provider_type: string }> = {
  ANTHROPIC_API_KEY: { provider_name: "anthropic", provider_type: "anthropic" },
  BRAVE_API_KEY: { provider_name: "brave", provider_type: "brave" },
  CLAUDE_API_KEY: { provider_name: "claude", provider_type: "claude" },
  COPILOT_GITHUB_TOKEN: { provider_name: "copilot", provider_type: "copilot" },
  GITHUB_TOKEN: { provider_name: "github", provider_type: "github" },
  GITLAB_TOKEN: { provider_name: "gitlab", provider_type: "gitlab" },
  GLAB_TOKEN: { provider_name: "gitlab", provider_type: "gitlab" },
  GH_TOKEN: { provider_name: "github", provider_type: "github" },
  HF_TOKEN: { provider_name: "huggingface", provider_type: "huggingface" },
  HUGGINGFACE_TOKEN: { provider_name: "huggingface", provider_type: "huggingface" },
  NVIDIA_API_KEY: { provider_name: "nvidia", provider_type: "nvidia" },
  OPENAI_API_KEY: { provider_name: "openai", provider_type: "openai" },
  OPENCODE_API_KEY: { provider_name: "opencode", provider_type: "opencode" },
  SLACK_APP_TOKEN: { provider_name: "slack", provider_type: "slack" },
  SLACK_BOT_TOKEN: { provider_name: "slack", provider_type: "slack" },
  TELEGRAM_BOT_TOKEN: { provider_name: "telegram", provider_type: "telegram" },
};

let cachedProviderPresets: { loadedAt: number; presets: AccessPreset[] } | null = null;

const PRESETS: AccessPreset[] = [
  {
    name: "github",
    description: "GitHub.com and GitHub API access (git)",
    provider_profile: "github",
    rule: {
      name: "github",
      endpoints: [
        { host: "github.com", port: 443, protocol: "rest", enforcement: "enforce" },
        { host: "api.github.com", port: 443, protocol: "rest", enforcement: "enforce" },
      ],
      binaries: [{ path: "/usr/bin/git" }],
    },
  },
  {
    name: "outlook",
    description: "Microsoft Outlook and Graph API access",
    provider_profile: "outlook",
    rule: {
      name: "outlook_graph",
      endpoints: [
        { host: "graph.microsoft.com", port: 443, protocol: "rest", enforcement: "enforce" },
        { host: "login.microsoftonline.com", port: 443, protocol: "rest", enforcement: "enforce" },
        { host: "outlook.office365.com", port: 443, protocol: "rest", enforcement: "enforce" },
        { host: "outlook.office.com", port: 443, protocol: "rest", enforcement: "enforce" },
      ],
      binaries: [{ path: "/usr/local/bin/node" }],
    },
  },
  {
    name: "pypi",
    description: "Python Package Index (PyPI) access",
    rule: {
      name: "pypi",
      endpoints: [
        { host: "pypi.org", port: 443, protocol: "rest", enforcement: "enforce" },
        { host: "files.pythonhosted.org", port: 443, protocol: "rest", enforcement: "enforce" },
      ],
      binaries: [
        { path: "/usr/bin/python3*" },
        { path: "/usr/bin/pip*" },
        { path: "/usr/local/bin/python3*" },
        { path: "/usr/local/bin/pip*" },
        { path: "/sandbox/.venv/bin/python*" },
        { path: "/sandbox/.venv/bin/pip*" },
      ],
    },
  },
  {
    name: "npm",
    description: "npm and Yarn registry access",
    rule: {
      name: "npm_yarn",
      endpoints: [
        { host: "registry.npmjs.org", port: 443, protocol: "rest", enforcement: "enforce" },
        { host: "registry.yarnpkg.com", port: 443, protocol: "rest", enforcement: "enforce" },
      ],
      binaries: [
        { path: "/usr/local/bin/npm*" },
        { path: "/usr/local/bin/npx*" },
        { path: "/usr/local/bin/node*" },
        { path: "/usr/local/bin/yarn*" },
        { path: "/usr/bin/npm*" },
        { path: "/usr/bin/node*" },
      ],
    },
  },
  {
    name: "brave",
    description: "Brave Search API access",
    rule: {
      name: "brave",
      endpoints: [
        { host: "api.search.brave.com", port: 443, protocol: "rest", enforcement: "enforce" },
      ],
      binaries: [...NODE_BINARIES, { path: "/usr/bin/curl" }],
    },
  },
  {
    name: "local-inference",
    description: "Local inference access via host gateway",
    rule: {
      name: "local_inference",
      endpoints: [
        { host: "host.openshell.internal", port: 11434, protocol: "rest", enforcement: "enforce" },
        { host: "host.openshell.internal", port: 11435, protocol: "rest", enforcement: "enforce" },
        { host: "host.openshell.internal", port: 8000, protocol: "rest", enforcement: "enforce" },
      ],
      binaries: [
        { path: "/usr/local/bin/openclaw" },
        { path: "/usr/local/bin/claude" },
        { path: "/usr/local/bin/node" },
        { path: "/usr/bin/node" },
        { path: "/usr/bin/curl" },
        { path: "/usr/bin/python3" },
      ],
    },
  },
  {
    name: "jira",
    description: "Jira and Atlassian Cloud access",
    rule: {
      name: "atlassian",
      endpoints: [
        { host: "*.atlassian.net", port: 443, protocol: "rest", enforcement: "enforce" },
        { host: "auth.atlassian.com", port: 443, protocol: "rest", enforcement: "enforce" },
        { host: "api.atlassian.com", port: 443, protocol: "rest", enforcement: "enforce" },
      ],
      binaries: [{ path: "/usr/local/bin/node" }],
    },
  },
  {
    name: "slack",
    description: "Slack API, Socket Mode, and webhooks access",
    rule: {
      name: "slack",
      endpoints: [
        { host: "slack.com", port: 443, protocol: "rest", enforcement: "enforce" },
        { host: "api.slack.com", port: 443, protocol: "rest", enforcement: "enforce" },
        { host: "hooks.slack.com", port: 443, protocol: "rest", enforcement: "enforce" },
      ],
      binaries: NODE_BINARIES,
    },
  },
  {
    name: "discord",
    description: "Discord API, gateway, and CDN access",
    rule: {
      name: "discord",
      endpoints: [
        { host: "discord.com", port: 443, protocol: "rest", enforcement: "enforce" },
        { host: "cdn.discordapp.com", port: 443, protocol: "rest", enforcement: "enforce" },
        { host: "media.discordapp.net", port: 443, protocol: "rest", enforcement: "enforce" },
      ],
      binaries: NODE_BINARIES,
    },
  },
  {
    name: "telegram",
    description: "Telegram Bot API access",
    rule: {
      name: "telegram_bot",
      endpoints: [
        { host: "api.telegram.org", port: 443, protocol: "rest", enforcement: "enforce" },
      ],
      binaries: NODE_BINARIES,
    },
  },
];

function openshellBinary(): string {
  return process.env.NEMOCLAW_OPENSHELL_BIN || "openshell";
}

function inferProviderNameFromEnv(envName: string): string {
  const hinted = PROVIDER_ENV_HINTS[envName];
  if (hinted) return hinted.provider_name;
  return envName
    .toLowerCase()
    .replace(/_(api_)?token$/u, "")
    .replace(/_api_key$/u, "")
    .replace(/[^a-z0-9]+/gu, "-")
    .replace(/^-+|-+$/gu, "");
}

function inferProviderTypeFromEnv(envName: string): string | undefined {
  return PROVIDER_ENV_HINTS[envName]?.provider_type;
}

function isProviderCredentialPlaceholder(value: string | undefined): boolean {
  return typeof value === "string" && value.startsWith(PROVIDER_ENV_PLACEHOLDER_PREFIX);
}

function parseProviderProfilesJson(raw: string): ProviderProfile[] {
  if (!raw.trim()) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }

  const candidates = Array.isArray(parsed)
    ? parsed
    : parsed &&
        typeof parsed === "object" &&
        Array.isArray((parsed as { profiles?: unknown }).profiles)
      ? (parsed as { profiles: unknown[] }).profiles
      : [];

  return candidates
    .filter((value): value is Record<string, unknown> => {
      return typeof value === "object" && value !== null && typeof value.id === "string";
    })
    .map((profile) => ({
      id: String(profile.id),
      display_name: typeof profile.display_name === "string" ? profile.display_name : undefined,
      description: typeof profile.description === "string" ? profile.description : undefined,
      endpoints: Array.isArray(profile.endpoints)
        ? (profile.endpoints as ProviderProfileEndpoint[])
        : [],
      binaries: Array.isArray(profile.binaries)
        ? (profile.binaries as Array<string | { path?: unknown }>)
        : [],
    }));
}

function providerBinaryPath(binary: string | { path?: unknown }): string | null {
  if (typeof binary === "string") return binary;
  if (binary && typeof binary.path === "string") return binary.path;
  return null;
}

function cleanProviderEndpoint(endpoint: ProviderProfileEndpoint): NetworkEndpoint | null {
  if (typeof endpoint.host !== "string" || Number(endpoint.port) <= 0) return null;
  const output: NetworkEndpoint = {
    host: endpoint.host,
    port: Number(endpoint.port),
  };
  for (const key of [
    "protocol",
    "tls",
    "access",
    "enforcement",
    "rules",
    "allowed_ips",
    "ports",
    "deny_rules",
    "allow_encoded_slash",
    "websocket_credential_rewrite",
    "request_body_credential_rewrite",
    "persisted_queries",
    "graphql_persisted_queries",
    "graphql_max_body_bytes",
    "path",
  ] as const) {
    const value = endpoint[key];
    if (
      value !== undefined &&
      value !== null &&
      value !== "" &&
      !(Array.isArray(value) && value.length === 0)
    ) {
      (output as Record<string, unknown>)[key] = value;
    }
  }
  return output;
}

function providerProfileToPreset(profile: ProviderProfile): AccessPreset | null {
  const endpoints = (profile.endpoints || [])
    .map(cleanProviderEndpoint)
    .filter((endpoint): endpoint is NetworkEndpoint => endpoint !== null);
  if (endpoints.length === 0) return null;

  const binaries = (profile.binaries || [])
    .map(providerBinaryPath)
    .filter((binary): binary is string => Boolean(binary))
    .map((path) => ({ path }));

  const ruleName = profile.id.replace(/-/g, "_");
  return {
    name: profile.id,
    description: profile.description || profile.display_name || `${profile.id} provider profile`,
    provider_profile: profile.id,
    rule: {
      name: ruleName,
      endpoints,
      binaries,
    },
  };
}

function readProviderProfilesFromOpenShell(): ProviderProfile[] {
  if (process.env.NEMOCLAW_OPENSHELL_PROVIDER_PROFILES_JSON) {
    return parseProviderProfilesJson(process.env.NEMOCLAW_OPENSHELL_PROVIDER_PROFILES_JSON);
  }
  try {
    const raw = execFileSync(openshellBinary(), ["provider", "list-profiles", "-o", "json"], {
      encoding: "utf-8",
      timeout: 5_000,
      stdio: ["ignore", "pipe", "ignore"],
    });
    return parseProviderProfilesJson(raw);
  } catch {
    return [];
  }
}

function listProviderProfilePresets(): AccessPreset[] {
  const now = Date.now();
  if (cachedProviderPresets && now - cachedProviderPresets.loadedAt < PROVIDER_PROFILE_CACHE_MS) {
    return cachedProviderPresets.presets;
  }
  const presets = readProviderProfilesFromOpenShell()
    .map(providerProfileToPreset)
    .filter((preset): preset is AccessPreset => preset !== null);
  cachedProviderPresets = { loadedAt: now, presets };
  return presets;
}

function allPresets(): AccessPreset[] {
  const byName = new Map<string, AccessPreset>();
  for (const preset of PRESETS) byName.set(preset.name, preset);
  for (const preset of listProviderProfilePresets()) {
    const existing = byName.get(preset.name);
    byName.set(
      preset.name,
      existing ? { ...existing, provider_profile: preset.provider_profile } : preset,
    );
  }
  return [...byName.values()].sort((left, right) => left.name.localeCompare(right.name));
}

export function clearAccessPresetCache(): void {
  cachedProviderPresets = null;
}

function normalizePresetName(resource: string): string {
  const normalized = resource.trim().toLowerCase();
  const host = (() => {
    if (!normalized.includes("://")) {
      return normalized;
    }
    try {
      return new URL(normalized).hostname.toLowerCase();
    } catch {
      return normalized;
    }
  })();
  if (host === "github.com" || host === "api.github.com") {
    return "github";
  }
  return host;
}

function rulesForAccess(access: "read" | "read_write"): L7Rule[] {
  const methods = access === "read_write" ? READ_WRITE_METHODS : READ_METHODS;
  return methods.map((method) => ({ allow: { method, path: "/**" } }));
}

function ruleForRequest(body: CreateAccessRequestBody): NetworkRule {
  const presetName = normalizePresetName(body.llm_proposal.preset);
  const preset = allPresets().find((candidate) => candidate.name === presetName);
  if (!preset) {
    throw new Error(`Unknown access preset '${body.llm_proposal.preset}'.`);
  }
  return {
    ...preset.rule,
    endpoints: preset.rule.endpoints.map((endpoint) => {
      if (endpoint.access === "full" || endpoint.tls === "skip") {
        return { ...endpoint };
      }
      return {
        ...endpoint,
        access: undefined,
        rules: endpoint.rules ?? rulesForAccess(body.llm_proposal.access),
      };
    }),
    binaries: preset.rule.binaries.map((binary) => ({ ...binary })),
  };
}

function policyLocalUrl(options: AccessClientOptions = {}): URL {
  return new URL(
    options.policyLocalUrl ?? process.env.OPENSHELL_POLICY_LOCAL_URL ?? "http://policy.local",
  );
}

function proxyUrl(): URL | null {
  const raw = process.env.HTTP_PROXY ?? process.env.http_proxy;
  if (!raw) return null;
  try {
    const parsed = new URL(raw);
    return parsed.protocol === "http:" ? parsed : null;
  } catch {
    return null;
  }
}

function parseJsonObject(raw: string): Record<string, unknown> {
  const parsed: unknown = raw.length > 0 ? JSON.parse(raw) : {};
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("OpenShell policy.local returned a non-object response");
  }
  return parsed as Record<string, unknown>;
}

function mapChunkStatus(
  status: unknown,
  policyReloaded: unknown,
  requestType: unknown,
): AccessStatus {
  if (status === "approved") {
    return policyReloaded === true || requestType === "provider" ? "applied" : "pending_approval";
  }
  if (status === "rejected") return "denied";
  if (status === "pending") return "pending_approval";
  return "failed";
}

function requestJson<T>(
  method: "GET" | "POST",
  requestPath: string,
  body: Record<string, unknown> | undefined,
  options: AccessClientOptions,
  parseResponse: (raw: string) => T,
): Promise<T> {
  const base = policyLocalUrl(options);
  if (base.protocol !== "http:") {
    throw new Error("OpenShell policy.local URL must use HTTP inside the sandbox.");
  }

  const payload = body === undefined ? undefined : JSON.stringify(body);
  const headers: Record<string, string | number> = {
    Accept: "application/json",
    Host: base.host,
  };
  if (payload !== undefined) {
    headers["Content-Type"] = "application/json";
    headers["Content-Length"] = Buffer.byteLength(payload);
  }

  const proxy = base.hostname === "policy.local" ? proxyUrl() : null;
  if (proxy) {
    return requestJsonViaHttpProxy(
      method,
      base,
      requestPath,
      headers,
      payload,
      options,
      parseResponse,
    );
  }

  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        method,
        protocol: base.protocol,
        hostname: base.hostname,
        port: base.port === "" ? undefined : Number(base.port),
        path: `${base.pathname.replace(/\/$/, "")}${requestPath}`,
        headers,
        timeout: options.timeoutMs ?? 310_000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          const raw = Buffer.concat(chunks).toString("utf-8");
          if (res.statusCode === undefined || res.statusCode < 200 || res.statusCode >= 300) {
            reject(
              new Error(
                `OpenShell policy.local ${method} ${requestPath} failed with HTTP ${res.statusCode ?? "unknown"}: ${raw}`,
              ),
            );
            return;
          }
          try {
            resolve(parseResponse(raw));
          } catch (err) {
            reject(err);
          }
        });
      },
    );

    req.on("timeout", () => {
      req.destroy(new Error(`OpenShell policy.local ${method} ${requestPath} timed out`));
    });
    req.on("error", reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

function requestJsonViaHttpProxy<T>(
  method: "GET" | "POST",
  base: URL,
  requestPath: string,
  headers: Record<string, string | number>,
  payload: string | undefined,
  options: AccessClientOptions,
  parseResponse: (raw: string) => T,
): Promise<T> {
  const proxy = proxyUrl();
  if (!proxy) {
    return Promise.reject(new Error("HTTP proxy is not configured."));
  }

  const target = `http://policy.local:80${base.pathname.replace(/\/$/, "")}${requestPath}`;
  const timeoutMs = options.timeoutMs ?? 310_000;
  const proxyPort = proxy.port ? Number(proxy.port) : 80;
  const headerLines = Object.entries(headers).map(([key, value]) => `${key}: ${value}`);
  const requestBytes = [
    `${method} ${target} HTTP/1.1`,
    ...headerLines,
    "Connection: close",
    "",
    payload ?? "",
  ].join("\r\n");

  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: proxy.hostname, port: proxyPort });
    const chunks: Buffer[] = [];
    const timer = setTimeout(() => {
      socket.destroy(new Error(`OpenShell policy.local ${method} ${requestPath} timed out`));
    }, timeoutMs);

    socket.on("connect", () => {
      socket.write(requestBytes);
    });
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    socket.on("end", () => {
      clearTimeout(timer);
      const raw = Buffer.concat(chunks).toString("utf-8");
      const headerEnd = raw.indexOf("\r\n\r\n");
      if (headerEnd === -1) {
        reject(
          new Error(
            `OpenShell policy.local ${method} ${requestPath} returned a malformed HTTP response`,
          ),
        );
        return;
      }
      const header = raw.slice(0, headerEnd);
      const body = raw.slice(headerEnd + 4);
      const statusLine = header.split("\r\n")[0] ?? "";
      const statusCode = Number(statusLine.split(/\s+/)[1]);
      if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) {
        reject(
          new Error(
            `OpenShell policy.local ${method} ${requestPath} failed with HTTP ${Number.isFinite(statusCode) ? statusCode : "unknown"}: ${body}`,
          ),
        );
        return;
      }
      try {
        resolve(parseResponse(body));
      } catch (err) {
        reject(err);
      }
    });
  });
}

function proposalBody(body: CreateAccessRequestBody): Record<string, unknown> {
  const rule = ruleForRequest(body);
  return {
    human_summary: `Request ${body.llm_proposal.access === "read_write" ? "read/write" : "read"} access to ${body.llm_proposal.preset}`,
    intent_summary: [body.user_intent, body.llm_proposal.reason].filter(Boolean).join(" "),
    operations: [{ addRule: { ruleName: rule.name, rule } }],
  };
}

function providerProposalBody(body: CreateProviderAccessRequestBody): Record<string, unknown> {
  return {
    human_summary: `Attach provider ${body.provider_name}`,
    intent_summary: [body.user_intent, body.reason].filter(Boolean).join(" "),
    operations: [
      {
        requestProvider: {
          providerName: body.provider_name,
          ...(body.provider_type ? { providerType: body.provider_type } : {}),
        },
      },
    ],
  };
}

function parseCreateResponse(raw: string): AccessRequestResponse {
  const parsed = parseJsonObject(raw);
  const accepted = Array.isArray(parsed.accepted_chunk_ids) ? parsed.accepted_chunk_ids : [];
  const requestId = accepted.find((id): id is string => typeof id === "string" && id.length > 0);
  if (!requestId) {
    return {
      request_id: "",
      status: "failed",
      message: `OpenShell rejected the proposal: ${JSON.stringify(parsed.rejection_reasons ?? [])}`,
    };
  }
  return {
    request_id: requestId,
    status: "pending_approval",
    message: "Proposal submitted to OpenShell; waiting for operator approval.",
  };
}

function parseStateResponse(raw: string): AccessRequestResponse {
  const parsed = parseJsonObject(raw);
  const requestId = typeof parsed.chunk_id === "string" ? parsed.chunk_id : "";
  return {
    request_id: requestId,
    status: mapChunkStatus(parsed.status, parsed.policy_reloaded, parsed.request_type),
    message:
      typeof parsed.rejection_reason === "string" && parsed.rejection_reason
        ? parsed.rejection_reason
        : typeof parsed.validation_result === "string" && parsed.validation_result
          ? parsed.validation_result
          : undefined,
    canonical_request: parsed,
  };
}

function parseAttachedProvidersResponse(raw: string): AttachedProvider[] {
  const parsed = parseJsonObject(raw);
  const providers = Array.isArray(parsed.providers) ? parsed.providers : [];
  return providers
    .filter((provider): provider is AttachedProviderJson => {
      return (
        typeof provider === "object" &&
        provider !== null &&
        typeof provider.provider_name === "string" &&
        provider.provider_name.trim().length > 0
      );
    })
    .map((provider) => ({
      provider_name: provider.provider_name.trim(),
      ...(typeof provider.provider_type === "string" && provider.provider_type.trim()
        ? { provider_type: provider.provider_type.trim() }
        : {}),
      ...(Array.isArray(provider.credential_keys) &&
      provider.credential_keys.find((key) => typeof key === "string" && key.trim().length > 0)
        ? {
            credential_env: (
              provider.credential_keys.find(
                (key) => typeof key === "string" && key.trim().length > 0,
              ) as string
            ).trim(),
          }
        : {}),
    }));
}

export function createAccessRequest(
  body: CreateAccessRequestBody,
  options: AccessClientOptions = {},
): Promise<AccessRequestResponse> {
  return requestJson("POST", "/v1/proposals", proposalBody(body), options, parseCreateResponse);
}

export function createProviderAccessRequest(
  body: CreateProviderAccessRequestBody,
  options: AccessClientOptions = {},
): Promise<AccessRequestResponse> {
  return requestJson(
    "POST",
    "/v1/proposals",
    providerProposalBody(body),
    options,
    parseCreateResponse,
  );
}

export function getAccessRequest(
  requestId: string,
  options: AccessClientOptions = {},
): Promise<AccessRequestResponse> {
  return requestJson(
    "GET",
    `/v1/proposals/${encodeURIComponent(requestId)}`,
    undefined,
    options,
    parseStateResponse,
  );
}

export function waitAccessRequest(
  requestId: string,
  timeoutMs: number,
  options: AccessClientOptions = {},
): Promise<AccessRequestResponse> {
  const seconds = Math.max(1, Math.min(300, Math.ceil(timeoutMs / 1000)));
  return requestJson(
    "GET",
    `/v1/proposals/${encodeURIComponent(requestId)}/wait?timeout=${seconds}`,
    undefined,
    { ...options, timeoutMs: Math.max(options.timeoutMs ?? 0, (seconds + 10) * 1000) },
    parseStateResponse,
  );
}

export function listAccessPresets(
  _options: AccessClientOptions = {},
): Promise<AccessPresetsResponse> {
  return Promise.resolve({
    presets: allPresets().map(({ name, description, provider_profile }) => ({
      name,
      description,
      ...(provider_profile ? { provider_profile } : {}),
    })),
  });
}

function listProviderAccessFromEnv(): ProviderAccessInfo[] {
  const byName = new Map<string, ProviderAccessInfo>();
  for (const [envName, value] of Object.entries(process.env)) {
    if (!isProviderCredentialPlaceholder(value)) continue;
    const providerName = inferProviderNameFromEnv(envName);
    if (!providerName) continue;
    const existing = byName.get(providerName);
    const next: ProviderAccessInfo = {
      provider_name: providerName,
      ...(inferProviderTypeFromEnv(envName)
        ? { provider_type: inferProviderTypeFromEnv(envName) }
        : {}),
      status: "attached",
      credential_env: envName,
      credential_state: "attached_placeholder",
      usable_via_proxy: true,
      raw_secret_available: false,
      credential_available: true,
    };
    if (!existing || (existing.credential_env ?? "") > envName) {
      byName.set(providerName, next);
    }
  }
  return [...byName.values()].sort((left, right) =>
    left.provider_name.localeCompare(right.provider_name),
  );
}

function mergeAttachedProviders(
  attachedProviders: AttachedProvider[],
  envProviders: ProviderAccessInfo[],
): ProviderAccessInfo[] {
  const byName = new Map<string, ProviderAccessInfo>();
  for (const attached of attachedProviders) {
    const providerName = attached.provider_name.trim();
    if (!providerName) continue;
    byName.set(providerName.toLowerCase(), {
      provider_name: providerName,
      ...(attached.provider_type ? { provider_type: attached.provider_type } : {}),
      status: "attached",
      ...(attached.credential_env ? { credential_env: attached.credential_env } : {}),
      credential_state: attached.credential_env ? "attached_placeholder" : "attached_unknown",
      usable_via_proxy: Boolean(attached.credential_env),
      raw_secret_available: false,
      credential_available: Boolean(attached.credential_env),
    });
  }
  for (const envProvider of envProviders) {
    const key = envProvider.provider_name.trim().toLowerCase();
    const existing = byName.get(key);
    byName.set(key, {
      ...envProvider,
      ...(existing?.provider_name ? { provider_name: existing.provider_name } : {}),
      ...(existing?.provider_type || envProvider.provider_type
        ? { provider_type: existing?.provider_type ?? envProvider.provider_type }
        : {}),
      ...(existing?.credential_env || envProvider.credential_env
        ? { credential_env: existing?.credential_env ?? envProvider.credential_env }
        : {}),
      credential_state:
        existing?.credential_state === "attached_placeholder" ||
        envProvider.credential_state === "attached_placeholder"
          ? "attached_placeholder"
          : "attached_unknown",
      usable_via_proxy: Boolean(existing?.usable_via_proxy || envProvider.usable_via_proxy),
      raw_secret_available: false,
      credential_available: Boolean(
        existing?.credential_available || envProvider.credential_available,
      ),
    });
  }
  return [...byName.values()].sort((left, right) =>
    left.provider_name.localeCompare(right.provider_name),
  );
}

export async function listProviderAccess(
  options: AccessClientOptions = {},
): Promise<ProviderAccessResponse> {
  const envProviders = listProviderAccessFromEnv();
  try {
    const attachedProviders = await requestJson(
      "GET",
      "/v1/providers",
      undefined,
      options,
      parseAttachedProvidersResponse,
    );
    return {
      providers: mergeAttachedProviders(attachedProviders, envProviders),
    };
  } catch {
    // Older OpenShell sandboxes do not expose /v1/providers. Preserve the
    // previous behavior there, using injected credential placeholders only.
  }
  return Promise.resolve({
    providers: envProviders,
  });
}

export async function getProviderAccess(
  providerName: string,
  options: AccessClientOptions = {},
): Promise<ProviderAccessInfo | null> {
  const normalized = providerName.trim().toLowerCase();
  if (!normalized) return null;
  const response = await listProviderAccess(options);
  return (
    response.providers.find(
      (provider) => provider.provider_name.trim().toLowerCase() === normalized,
    ) ?? null
  );
}
