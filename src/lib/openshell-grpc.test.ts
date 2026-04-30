// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import {
  submitApprovedPolicyUpdateAndWait,
  type OpenShellGetSandboxPolicyStatusRequest,
  type OpenShellGetSandboxPolicyStatusResponse,
  type OpenShellGrpcClient,
  type OpenShellUpdateConfigRequest,
  type OpenShellUpdateConfigResponse,
} from "./openshell-grpc";

class FakeClock {
  private current = 0;

  now(): number {
    return this.current;
  }

  advance(ms: number): void {
    this.current += ms;
  }
}

class FakeOpenShellClient implements OpenShellGrpcClient {
  readonly updateRequests: OpenShellUpdateConfigRequest[] = [];
  readonly statusRequests: OpenShellGetSandboxPolicyStatusRequest[] = [];

  constructor(
    private readonly updateResponse: OpenShellUpdateConfigResponse,
    private readonly statuses: OpenShellGetSandboxPolicyStatusResponse[],
  ) {}

  async updateConfig(
    request: OpenShellUpdateConfigRequest,
  ): Promise<OpenShellUpdateConfigResponse> {
    this.updateRequests.push(request);
    return this.updateResponse;
  }

  async getSandboxPolicyStatus(
    request: OpenShellGetSandboxPolicyStatusRequest,
  ): Promise<OpenShellGetSandboxPolicyStatusResponse> {
    this.statusRequests.push(request);
    return this.statuses[Math.min(this.statusRequests.length - 1, this.statuses.length - 1)];
  }
}

const updateRequest: OpenShellUpdateConfigRequest = {
  name: "sandbox-a",
  merge_operations: [{ add_rule: { rule_name: "github", rule: {} } }],
};

const updateResponse: OpenShellUpdateConfigResponse = {
  version: 7,
  policy_hash: "sha256:abc",
};

function revision(status: string): OpenShellGetSandboxPolicyStatusResponse {
  return {
    active_version: status === "loaded" ? 7 : 6,
    revision: {
      version: 7,
      policy_hash: "sha256:abc",
      status,
      load_error: status === "failed" ? "OPA reload failed" : "",
    },
  };
}

describe("openshell gRPC adapter", () => {
  it("waits for loaded status before returning applied", async () => {
    const clock = new FakeClock();
    const sleeps: number[] = [];
    const client = new FakeOpenShellClient(updateResponse, [
      revision("pending"),
      revision("loaded"),
    ]);

    const result = await submitApprovedPolicyUpdateAndWait({
      client,
      request: updateRequest,
      timeoutMs: 1_000,
      pollIntervalMs: 100,
      clock,
      sleep: async (ms) => {
        sleeps.push(ms);
        clock.advance(ms);
      },
    });

    expect(result.submitted).toEqual({
      status: "pending_activation",
      sandbox: "sandbox-a",
      version: 7,
      policy_hash: "sha256:abc",
    });
    expect(result.result).toEqual({
      status: "applied",
      sandbox: "sandbox-a",
      version: 7,
      policy_hash: "sha256:abc",
      active_version: 7,
    });
    expect(client.updateRequests).toEqual([updateRequest]);
    expect(client.statusRequests).toEqual([
      { name: "sandbox-a", version: 7, global: undefined },
      { name: "sandbox-a", version: 7, global: undefined },
    ]);
    expect(sleeps).toEqual([100]);
  });

  it("returns failed when OpenShell reports failed", async () => {
    const clock = new FakeClock();
    const client = new FakeOpenShellClient(updateResponse, [revision("failed")]);

    const result = await submitApprovedPolicyUpdateAndWait({
      client,
      request: updateRequest,
      clock,
      sleep: async (ms) => clock.advance(ms),
    });

    expect(result.result).toEqual({
      status: "failed",
      reason: "failed",
      sandbox: "sandbox-a",
      version: 7,
      policy_hash: "sha256:abc",
      active_version: 6,
      load_error: "OPA reload failed",
    });
  });

  it("returns failed with superseded reason when OpenShell reports superseded", async () => {
    const clock = new FakeClock();
    const client = new FakeOpenShellClient(updateResponse, [revision("superseded")]);

    const result = await submitApprovedPolicyUpdateAndWait({
      client,
      request: updateRequest,
      clock,
      sleep: async (ms) => clock.advance(ms),
    });

    expect(result.result).toEqual({
      status: "failed",
      reason: "superseded",
      sandbox: "sandbox-a",
      version: 7,
      policy_hash: "sha256:abc",
      active_version: 6,
      load_error: "",
    });
  });

  it("returns timeout when policy status never reaches a terminal state", async () => {
    const clock = new FakeClock();
    const client = new FakeOpenShellClient(updateResponse, [revision("pending")]);

    const result = await submitApprovedPolicyUpdateAndWait({
      client,
      request: updateRequest,
      timeoutMs: 250,
      pollIntervalMs: 100,
      clock,
      sleep: async (ms) => clock.advance(ms),
    });

    expect(result.result).toEqual({
      status: "failed",
      reason: "timeout",
      sandbox: "sandbox-a",
      version: 7,
      policy_hash: "sha256:abc",
      active_version: 6,
      load_error: "",
    });
    expect(client.statusRequests).toHaveLength(4);
  });
});
