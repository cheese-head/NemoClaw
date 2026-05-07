// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";

import type { AccessTuiRecord, AuditResult } from "./model";

const accessRequests = require("../access-requests");
const policies = require("../policies");
const registry = require("../registry");

export function readAllAccessRequests(): AccessTuiRecord[] {
  const items: AccessTuiRecord[] = [];
  const known = new Set<string>();
  for (const sandbox of registry.listSandboxes().sandboxes ?? []) {
    if (typeof sandbox.name === "string") known.add(sandbox.name);
  }

  const stateDir = accessRequests.accessRequestStateDir();
  if (fs.existsSync(stateDir)) {
    for (const entry of fs.readdirSync(stateDir)) {
      if (!entry.endsWith(".json") || entry.endsWith(".audit.json")) continue;
      known.add(decodeURIComponent(entry.slice(0, -".json".length)));
    }
  }

  for (const sandboxName of [...known].sort()) {
    const state = accessRequests.readAccessRequestState(sandboxName);
    for (const request of state.requests ?? []) {
      items.push({
        ...(request as AccessTuiRecord),
        sandbox_id: request.sandbox_id || sandboxName,
      });
    }
  }
  return items;
}

export function approveAccessRequest(record: AccessTuiRecord): string {
  if (record.status !== "pending") {
    throw new Error(`Request is not pending (status: ${record.status}).`);
  }
  if (record.duration !== "session") {
    throw new Error("Persistent grants are not supported in v1.");
  }

  accessRequests.transitionAccessRequest(record.sandbox_id, record.id, "pending_activation", {
    reason: "Operator approved; applying policy preset.",
  });
  const applied = policies.applyPresetWithResult(record.sandbox_id, record.preset);
  if (!applied.ok) {
    accessRequests.transitionAccessRequest(record.sandbox_id, record.id, "failed", {
      reason: applied.message,
    });
    throw new Error(`Failed to apply preset '${record.preset}': ${applied.message}`);
  }
  accessRequests.transitionAccessRequest(record.sandbox_id, record.id, "applied", {
    reason: applied.message,
  });
  return `Applied access request: ${record.id}`;
}

export function denyAccessRequest(record: AccessTuiRecord, reason: string): string {
  if (record.status !== "pending" && record.status !== "pending_activation") {
    throw new Error(`Request is not pending (status: ${record.status}).`);
  }
  accessRequests.transitionAccessRequest(record.sandbox_id, record.id, "denied", { reason });
  return `Denied access request: ${record.id}`;
}

export function revokeAccessRequest(record: AccessTuiRecord): string {
  if (!["pending", "pending_activation", "applied"].includes(record.status)) {
    throw new Error(`Request is not revocable (status: ${record.status}).`);
  }
  if (record.status === "applied" && !policies.removePreset(record.sandbox_id, record.preset)) {
    throw new Error(`Failed to remove preset '${record.preset}'.`);
  }
  accessRequests.transitionAccessRequest(record.sandbox_id, record.id, "revoked", {
    reason: "Operator revoked access request.",
  });
  return `Revoked access request: ${record.id}`;
}

export function verifyAccessAudit(sandboxName: string): AuditResult {
  return accessRequests.verifyAccessRequestAudit(sandboxName);
}
