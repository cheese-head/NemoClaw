// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { ensureConfigDir, readConfigFile, writeConfigFile } from "./config-io";

export const ACCESS_REQUESTS_STATE_VERSION = 1;
export const DEFAULT_ACCESS_REQUEST_CEILING = {
  allowedPresets: ["github"] as const,
  maxRequestsPerHourPerSandbox: 20,
  maxOpenGrantsPerSandbox: 5,
  dedupeWindowMs: 5 * 60 * 1000,
};

export type AccessRequestPreset = "github";
export type AccessRequestAccess = "read" | "read_write";
export type AccessRequestDuration = "session";
export type AccessRequestResourceType = "network";
export type AccessRequestStatus =
  | "pending"
  | "pending_activation"
  | "applied"
  | "denied"
  | "denied_by_ceiling"
  | "failed"
  | "expired";

export type AccessRequestTerminalStatus = Extract<
  AccessRequestStatus,
  "applied" | "denied" | "denied_by_ceiling" | "failed" | "expired"
>;

export type AccessRequestIdentityHints = {
  sandbox_id?: string;
  agent_id?: string;
  plugin_id?: string;
  [key: string]: string | undefined;
};

export type AccessRequestProposal = {
  resource?: string;
  preset?: string;
  host?: string;
  access?: string;
  duration?: string;
  task_id?: string;
  user_intent?: string;
  reason?: string;
  identity?: AccessRequestIdentityHints;
  sandbox_id?: string;
  agent_id?: string;
  plugin_id?: string;
};

export type CanonicalAccessRequest = {
  resource_type: AccessRequestResourceType;
  preset: AccessRequestPreset;
  access: AccessRequestAccess;
  duration: AccessRequestDuration;
  task_id: string;
  user_intent: string;
  reason: string;
  identity_hints: AccessRequestIdentityHints;
};

export type AccessRequestRecord = CanonicalAccessRequest & {
  id: string;
  version: 1;
  sandbox_id: string;
  status: AccessRequestStatus;
  request_hash: string;
  created_at: string;
  updated_at: string;
  ceiling_reason?: string;
  status_reason?: string;
};

export type AccessRequestState = {
  version: 1;
  sandbox_id: string;
  requests: AccessRequestRecord[];
  audit_head_hash: string | null;
};

export type AccessRequestAuditRecord = {
  version: 1;
  sandbox_id: string;
  request_id: string;
  event: "created" | "deduped" | "transitioned";
  status: AccessRequestStatus;
  at: string;
  prev_record_hash: string | null;
  record_hash: string;
  request_hash: string;
  reason?: string;
};

export type AccessRequestDeps = {
  now?: () => Date;
  id?: () => string;
  hash?: (input: string) => string;
  homeDir?: string;
};

export type AccessRequestCeiling = {
  allowedPresets?: readonly AccessRequestPreset[];
  maxRequestsPerHourPerSandbox?: number;
  maxOpenGrantsPerSandbox?: number;
  dedupeWindowMs?: number;
};

export type CreateAccessRequestResult = {
  request: AccessRequestRecord;
  created: boolean;
  deduped: boolean;
};

export class AccessRequestValidationError extends Error {
  code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "AccessRequestValidationError";
    this.code = code;
  }
}

function defaultHash(input: string): string {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function depsOrDefault(deps: AccessRequestDeps): Required<AccessRequestDeps> {
  return {
    now: deps.now ?? (() => new Date()),
    id: deps.id ?? (() => crypto.randomUUID()),
    hash: deps.hash ?? defaultHash,
    homeDir: deps.homeDir ?? process.env.HOME ?? os.homedir(),
  };
}

export function sanitizeDisplayText(value: unknown, maxLength: number): string {
  const text = typeof value === "string" ? value : "";
  const withoutUnsafe = text.replace(
    /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/gu,
    "",
  );
  return Array.from(withoutUnsafe).slice(0, maxLength).join("");
}

function sanitizeHint(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  return sanitizeDisplayText(value, 200);
}

function collectIdentityHints(proposal: AccessRequestProposal): AccessRequestIdentityHints {
  const hints: AccessRequestIdentityHints = {};
  for (const [key, value] of Object.entries(proposal.identity ?? {})) {
    const clean = sanitizeHint(value);
    if (clean !== undefined) {
      hints[key] = clean;
    }
  }
  for (const key of ["sandbox_id", "agent_id", "plugin_id"] as const) {
    const clean = sanitizeHint(proposal[key]);
    if (clean !== undefined) {
      hints[key] = clean;
    }
  }
  return hints;
}

function normalizePreset(proposal: AccessRequestProposal): AccessRequestPreset {
  const candidate = String(proposal.preset ?? proposal.resource ?? "")
    .trim()
    .toLowerCase();
  const host = String(proposal.host ?? "")
    .trim()
    .toLowerCase();

  if (
    candidate === "github" &&
    (host === "" || host === "github.com" || host === "api.github.com")
  ) {
    return "github";
  }
  if (candidate === "" && (host === "github.com" || host === "api.github.com")) {
    return "github";
  }

  throw new AccessRequestValidationError(
    "UNKNOWN_PRESET",
    "Only known access presets are accepted in v1; custom hosts are not supported.",
  );
}

function normalizeAccess(value: unknown): AccessRequestAccess {
  if (value === undefined || value === null || value === "") {
    return "read";
  }
  if (value === "read" || value === "read_write") {
    return value;
  }
  throw new AccessRequestValidationError("INVALID_ACCESS", "Access must be read or read_write.");
}

function normalizeDuration(value: unknown): AccessRequestDuration {
  if (value === undefined || value === null || value === "" || value === "session") {
    return "session";
  }
  if (value === "persistent") {
    throw new AccessRequestValidationError(
      "PERSISTENT_DISABLED",
      "Persistent access grants are disabled in v1.",
    );
  }
  throw new AccessRequestValidationError("INVALID_DURATION", "Duration must be session.");
}

function canonicalPayload(canonical: CanonicalAccessRequest): string {
  return JSON.stringify({
    access: canonical.access,
    duration: canonical.duration,
    identity_hints: canonical.identity_hints,
    preset: canonical.preset,
    reason: canonical.reason,
    resource_type: canonical.resource_type,
    task_id: canonical.task_id,
    user_intent: canonical.user_intent,
  });
}

export function canonicalizeAccessRequest(
  proposal: AccessRequestProposal,
  deps: AccessRequestDeps = {},
): CanonicalAccessRequest & { request_hash: string } {
  const resolved = depsOrDefault(deps);
  const canonical: CanonicalAccessRequest = {
    resource_type: "network",
    preset: normalizePreset(proposal),
    access: normalizeAccess(proposal.access),
    duration: normalizeDuration(proposal.duration),
    task_id: sanitizeDisplayText(proposal.task_id, 200),
    user_intent: sanitizeDisplayText(proposal.user_intent, 500),
    reason: sanitizeDisplayText(proposal.reason, 280),
    identity_hints: collectIdentityHints(proposal),
  };
  return {
    ...canonical,
    request_hash: resolved.hash(canonicalPayload(canonical)),
  };
}

function sandboxFileStem(sandboxId: string): string {
  const encoded = encodeURIComponent(sandboxId);
  if (encoded.length === 0) {
    throw new AccessRequestValidationError("INVALID_SANDBOX", "Sandbox id is required.");
  }
  return encoded;
}

export function accessRequestStateDir(deps: AccessRequestDeps = {}): string {
  const resolved = depsOrDefault(deps);
  return path.join(resolved.homeDir, ".nemoclaw", "state", "access-requests");
}

export function accessRequestStatePath(sandboxId: string, deps: AccessRequestDeps = {}): string {
  return path.join(accessRequestStateDir(deps), `${sandboxFileStem(sandboxId)}.json`);
}

export function accessRequestAuditPath(sandboxId: string, deps: AccessRequestDeps = {}): string {
  return path.join(accessRequestStateDir(deps), `${sandboxFileStem(sandboxId)}.audit.jsonl`);
}

function emptyState(sandboxId: string): AccessRequestState {
  return {
    version: ACCESS_REQUESTS_STATE_VERSION,
    sandbox_id: sandboxId,
    requests: [],
    audit_head_hash: null,
  };
}

export function readAccessRequestState(
  sandboxId: string,
  deps: AccessRequestDeps = {},
): AccessRequestState {
  const state = readConfigFile<AccessRequestState>(
    accessRequestStatePath(sandboxId, deps),
    emptyState(sandboxId),
  );
  return {
    ...emptyState(sandboxId),
    ...state,
    sandbox_id: sandboxId,
    requests: Array.isArray(state.requests) ? state.requests : [],
    audit_head_hash: state.audit_head_hash ?? null,
  };
}

function writeAccessRequestState(state: AccessRequestState, deps: AccessRequestDeps): void {
  writeConfigFile(accessRequestStatePath(state.sandbox_id, deps), state);
}

function auditPayload(record: Omit<AccessRequestAuditRecord, "record_hash">): string {
  return JSON.stringify(record);
}

function appendAuditRecord(
  state: AccessRequestState,
  request: AccessRequestRecord,
  event: AccessRequestAuditRecord["event"],
  deps: Required<AccessRequestDeps>,
  reason?: string,
): void {
  const withoutHash: Omit<AccessRequestAuditRecord, "record_hash"> = {
    version: ACCESS_REQUESTS_STATE_VERSION,
    sandbox_id: state.sandbox_id,
    request_id: request.id,
    event,
    status: request.status,
    at: request.updated_at,
    prev_record_hash: state.audit_head_hash,
    request_hash: request.request_hash,
    ...(reason ? { reason } : {}),
  };
  const record: AccessRequestAuditRecord = {
    ...withoutHash,
    record_hash: deps.hash(auditPayload(withoutHash)),
  };

  ensureConfigDir(accessRequestStateDir(deps));
  fs.appendFileSync(accessRequestAuditPath(state.sandbox_id, deps), `${JSON.stringify(record)}\n`, {
    mode: 0o600,
  });
  state.audit_head_hash = record.record_hash;
}

function mergeCeiling(ceiling: AccessRequestCeiling): Required<AccessRequestCeiling> {
  return {
    allowedPresets: ceiling.allowedPresets ?? DEFAULT_ACCESS_REQUEST_CEILING.allowedPresets,
    maxRequestsPerHourPerSandbox:
      ceiling.maxRequestsPerHourPerSandbox ??
      DEFAULT_ACCESS_REQUEST_CEILING.maxRequestsPerHourPerSandbox,
    maxOpenGrantsPerSandbox:
      ceiling.maxOpenGrantsPerSandbox ?? DEFAULT_ACCESS_REQUEST_CEILING.maxOpenGrantsPerSandbox,
    dedupeWindowMs: ceiling.dedupeWindowMs ?? DEFAULT_ACCESS_REQUEST_CEILING.dedupeWindowMs,
  };
}

function isOpenStatus(status: AccessRequestStatus): boolean {
  return status === "pending" || status === "pending_activation" || status === "applied";
}

function findDedupe(
  state: AccessRequestState,
  canonical: CanonicalAccessRequest,
  nowMs: number,
  dedupeWindowMs: number,
): AccessRequestRecord | undefined {
  return state.requests.find((request) => {
    if (!isOpenStatus(request.status)) {
      return false;
    }
    const ageMs = nowMs - Date.parse(request.created_at);
    return (
      ageMs >= 0 &&
      ageMs <= dedupeWindowMs &&
      request.preset === canonical.preset &&
      request.access === canonical.access &&
      request.task_id === canonical.task_id
    );
  });
}

function ceilingRejectionReason(
  state: AccessRequestState,
  canonical: CanonicalAccessRequest,
  nowMs: number,
  ceiling: Required<AccessRequestCeiling>,
): string | null {
  if (!ceiling.allowedPresets.includes(canonical.preset)) {
    return `Preset ${canonical.preset} is not allowed by the v1 ceiling.`;
  }

  const hourAgo = nowMs - 60 * 60 * 1000;
  const requestsInHour = state.requests.filter(
    (request) => Date.parse(request.created_at) >= hourAgo,
  );
  if (requestsInHour.length >= ceiling.maxRequestsPerHourPerSandbox) {
    return "Per-sandbox access request rate limit exceeded.";
  }

  const openGrants = state.requests.filter((request) => isOpenStatus(request.status));
  if (openGrants.length >= ceiling.maxOpenGrantsPerSandbox) {
    return "Per-sandbox open access grant limit exceeded.";
  }

  return null;
}

export function createAccessRequest(
  sandboxId: string,
  proposal: AccessRequestProposal,
  options: { deps?: AccessRequestDeps; ceiling?: AccessRequestCeiling } = {},
): CreateAccessRequestResult {
  const deps = depsOrDefault(options.deps ?? {});
  const ceiling = mergeCeiling(options.ceiling ?? {});
  const now = deps.now();
  const nowIso = now.toISOString();
  const nowMs = now.getTime();
  const canonical = canonicalizeAccessRequest(proposal, deps);
  const state = readAccessRequestState(sandboxId, deps);

  const duplicate = findDedupe(state, canonical, nowMs, ceiling.dedupeWindowMs);
  if (duplicate) {
    duplicate.updated_at = nowIso;
    appendAuditRecord(
      state,
      duplicate,
      "deduped",
      deps,
      "Duplicate request returned within dedupe window.",
    );
    writeAccessRequestState(state, deps);
    return { request: duplicate, created: false, deduped: true };
  }

  const ceilingReason = ceilingRejectionReason(state, canonical, nowMs, ceiling);
  const request: AccessRequestRecord = {
    ...canonical,
    id: deps.id(),
    version: ACCESS_REQUESTS_STATE_VERSION,
    sandbox_id: sandboxId,
    status: ceilingReason ? "denied_by_ceiling" : "pending",
    request_hash: canonical.request_hash,
    created_at: nowIso,
    updated_at: nowIso,
    ...(ceilingReason ? { ceiling_reason: ceilingReason } : {}),
  };

  state.requests.push(request);
  appendAuditRecord(state, request, "created", deps, ceilingReason ?? undefined);
  writeAccessRequestState(state, deps);
  return { request, created: true, deduped: false };
}

export function transitionAccessRequest(
  sandboxId: string,
  requestId: string,
  status: AccessRequestStatus,
  options: { deps?: AccessRequestDeps; reason?: string } = {},
): AccessRequestRecord {
  const deps = depsOrDefault(options.deps ?? {});
  const state = readAccessRequestState(sandboxId, deps);
  const request = state.requests.find((candidate) => candidate.id === requestId);
  if (!request) {
    throw new AccessRequestValidationError(
      "REQUEST_NOT_FOUND",
      `Access request not found: ${requestId}`,
    );
  }

  request.status = status;
  request.updated_at = deps.now().toISOString();
  const reason = sanitizeDisplayText(options.reason, 280);
  if (reason) {
    request.status_reason = reason;
  }

  appendAuditRecord(state, request, "transitioned", deps, reason || undefined);
  writeAccessRequestState(state, deps);
  return request;
}

export function readAccessRequestAudit(
  sandboxId: string,
  deps: AccessRequestDeps = {},
): AccessRequestAuditRecord[] {
  const filePath = accessRequestAuditPath(sandboxId, deps);
  if (!fs.existsSync(filePath)) {
    return [];
  }
  return fs
    .readFileSync(filePath, "utf-8")
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as AccessRequestAuditRecord);
}
