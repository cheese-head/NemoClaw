// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import type { JsonObject } from "./json-types";

export type OpenShellPolicyStatus = "pending" | "loaded" | "failed" | "superseded" | "unspecified";

export interface OpenShellPolicyMergeOperation {
  readonly [key: string]: JsonObject | JsonObject[] | string | number | boolean | null | undefined;
}

export interface OpenShellUpdateConfigRequest {
  readonly name: string;
  readonly policy?: JsonObject;
  readonly merge_operations?: readonly OpenShellPolicyMergeOperation[];
  readonly global?: boolean;
}

export interface OpenShellUpdateConfigResponse {
  readonly version: number;
  readonly policy_hash: string;
}

export interface OpenShellPolicyRevision {
  readonly version: number;
  readonly policy_hash: string;
  readonly status: OpenShellPolicyStatus | string | number;
  readonly load_error?: string;
}

export interface OpenShellGetSandboxPolicyStatusRequest {
  readonly name: string;
  readonly version: number;
  readonly global?: boolean;
}

export interface OpenShellGetSandboxPolicyStatusResponse {
  readonly revision?: OpenShellPolicyRevision | null;
  readonly active_version: number;
}

export interface OpenShellGrpcClient {
  updateConfig(request: OpenShellUpdateConfigRequest): Promise<OpenShellUpdateConfigResponse>;
  getSandboxPolicyStatus(
    request: OpenShellGetSandboxPolicyStatusRequest,
  ): Promise<OpenShellGetSandboxPolicyStatusResponse>;
}

export interface Clock {
  now(): number;
}

export interface SubmitApprovedPolicyUpdateOptions {
  readonly client: OpenShellGrpcClient;
  readonly request: OpenShellUpdateConfigRequest;
  readonly timeoutMs?: number;
  readonly pollIntervalMs?: number;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly clock?: Clock;
}

export interface SubmittedPolicyUpdate {
  readonly status: "pending_activation";
  readonly sandbox: string;
  readonly version: number;
  readonly policy_hash: string;
}

export interface AppliedPolicyUpdate {
  readonly status: "applied";
  readonly sandbox: string;
  readonly version: number;
  readonly policy_hash: string;
  readonly active_version: number;
}

export interface FailedPolicyUpdate {
  readonly status: "failed";
  readonly reason: "failed" | "superseded" | "timeout" | "missing_revision";
  readonly sandbox: string;
  readonly version: number;
  readonly policy_hash: string;
  readonly active_version?: number;
  readonly load_error?: string;
}

export type ApprovedPolicyUpdateResult = AppliedPolicyUpdate | FailedPolicyUpdate;

export interface SubmitApprovedPolicyUpdateAndWaitResult {
  readonly submitted: SubmittedPolicyUpdate;
  readonly result: ApprovedPolicyUpdateResult;
}

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_POLL_INTERVAL_MS = 1_000;

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizeStatus(status: OpenShellPolicyRevision["status"]): OpenShellPolicyStatus {
  if (typeof status === "number") {
    switch (status) {
      case 1:
        return "pending";
      case 2:
        return "loaded";
      case 3:
        return "failed";
      case 4:
        return "superseded";
      default:
        return "unspecified";
    }
  }

  const value = status.trim().toLowerCase();
  if (value === "loaded") return "loaded";
  if (value === "failed") return "failed";
  if (value === "superseded") return "superseded";
  if (value === "pending") return "pending";
  return "unspecified";
}

function makeFailedResult(
  reason: FailedPolicyUpdate["reason"],
  sandbox: string,
  submitted: OpenShellUpdateConfigResponse,
  status?: OpenShellGetSandboxPolicyStatusResponse,
): FailedPolicyUpdate {
  return {
    status: "failed",
    reason,
    sandbox,
    version: submitted.version,
    policy_hash: submitted.policy_hash,
    active_version: status?.active_version,
    load_error: status?.revision?.load_error,
  };
}

function validateRequest(request: OpenShellUpdateConfigRequest): void {
  if (!request.global && request.name.trim() === "") {
    throw new Error("OpenShell UpdateConfig request requires a sandbox name");
  }
  if (!request.policy && (!request.merge_operations || request.merge_operations.length === 0)) {
    throw new Error("OpenShell UpdateConfig request requires policy or merge_operations");
  }
}

export async function submitApprovedPolicyUpdateAndWait(
  options: SubmitApprovedPolicyUpdateOptions,
): Promise<SubmitApprovedPolicyUpdateAndWaitResult> {
  validateRequest(options.request);

  const clock = options.clock ?? { now: () => Date.now() };
  const sleep = options.sleep ?? defaultSleep;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const pollIntervalMs = options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  const sandbox = options.request.name;
  const deadline = clock.now() + timeoutMs;

  const submittedResponse = await options.client.updateConfig(options.request);
  const submitted: SubmittedPolicyUpdate = {
    status: "pending_activation",
    sandbox,
    version: submittedResponse.version,
    policy_hash: submittedResponse.policy_hash,
  };

  while (clock.now() <= deadline) {
    const status = await options.client.getSandboxPolicyStatus({
      name: sandbox,
      version: submittedResponse.version,
      global: options.request.global,
    });
    const revision = status.revision;

    if (!revision) {
      return {
        submitted,
        result: makeFailedResult("missing_revision", sandbox, submittedResponse, status),
      };
    }

    const revisionStatus = normalizeStatus(revision.status);
    if (
      revisionStatus === "loaded" &&
      revision.version === submittedResponse.version &&
      revision.policy_hash === submittedResponse.policy_hash &&
      status.active_version === submittedResponse.version
    ) {
      return {
        submitted,
        result: {
          status: "applied",
          sandbox,
          version: submittedResponse.version,
          policy_hash: submittedResponse.policy_hash,
          active_version: status.active_version,
        },
      };
    }

    if (revisionStatus === "failed") {
      return {
        submitted,
        result: makeFailedResult("failed", sandbox, submittedResponse, status),
      };
    }

    if (revisionStatus === "superseded") {
      return {
        submitted,
        result: makeFailedResult("superseded", sandbox, submittedResponse, status),
      };
    }

    if (clock.now() >= deadline) {
      return {
        submitted,
        result: makeFailedResult("timeout", sandbox, submittedResponse, status),
      };
    }

    await sleep(Math.min(pollIntervalMs, Math.max(0, deadline - clock.now())));
  }

  return {
    submitted,
    result: makeFailedResult("timeout", sandbox, submittedResponse),
  };
}
