// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import http from "node:http";

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

const NODE_BINARIES = [{ path: "/usr/local/bin/node" }, { path: "/usr/bin/node" }];
const READ_METHODS = ["GET", "HEAD"];
const READ_WRITE_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];

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
  const preset = PRESETS.find((candidate) => candidate.name === presetName);
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

function mapChunkStatus(status: unknown): AccessStatus {
  if (status === "approved") return "applied";
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

  return new Promise((resolve, reject) => {
    const proxy = base.hostname === "policy.local" ? proxyUrl() : null;
    const req = http.request(
      {
        method,
        protocol: proxy?.protocol ?? base.protocol,
        hostname: proxy?.hostname ?? base.hostname,
        port:
          proxy?.port !== undefined && proxy.port !== ""
            ? Number(proxy.port)
            : base.port === ""
              ? undefined
              : Number(base.port),
        path:
          proxy === null
            ? `${base.pathname.replace(/\/$/, "")}${requestPath}`
            : `${base.origin}${base.pathname.replace(/\/$/, "")}${requestPath}`,
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

function proposalBody(body: CreateAccessRequestBody): Record<string, unknown> {
  const rule = ruleForRequest(body);
  return {
    intent_summary: [body.user_intent, body.llm_proposal.reason].filter(Boolean).join(" "),
    operations: [{ addRule: { ruleName: rule.name, rule } }],
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
    status: mapChunkStatus(parsed.status),
    message:
      typeof parsed.rejection_reason === "string" && parsed.rejection_reason
        ? parsed.rejection_reason
        : typeof parsed.validation_result === "string" && parsed.validation_result
          ? parsed.validation_result
          : undefined,
    canonical_request: parsed,
  };
}

export function createAccessRequest(
  body: CreateAccessRequestBody,
  options: AccessClientOptions = {},
): Promise<AccessRequestResponse> {
  return requestJson("POST", "/v1/proposals", proposalBody(body), options, parseCreateResponse);
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
    presets: PRESETS.map(({ name, description, provider_profile }) => ({
      name,
      description,
      ...(provider_profile ? { provider_profile } : {}),
    })),
  });
}
