// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  AccessRequestValidationError,
  accessRequestAuditPath,
  accessRequestStatePath,
  canonicalizeAccessRequest,
  createAccessRequest,
  readAccessRequestAudit,
  readAccessRequestState,
  transitionAccessRequest,
  type AccessRequestDeps,
} from "../../dist/lib/access-requests";

const tmpDirs: string[] = [];

function makeTempHome(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-access-requests-"));
  tmpDirs.push(dir);
  return dir;
}

function makeDeps(homeDir = makeTempHome()): Required<AccessRequestDeps> & {
  advance: (ms: number) => void;
} {
  let nowMs = Date.parse("2026-04-30T00:00:00.000Z");
  let nextId = 1;
  return {
    homeDir,
    now: () => new Date(nowMs),
    id: () => `req-${nextId++}`,
    hash: (input: string) => crypto.createHash("sha256").update(input).digest("hex"),
    advance: (ms: number) => {
      nowMs += ms;
    },
  };
}

afterEach(() => {
  for (const dir of tmpDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe("access requests", () => {
  it("canonicalizes github proposals and treats identity fields as hints", () => {
    const canonical = canonicalizeAccessRequest(
      {
        resource: "GitHub",
        host: "github.com",
        access: "read_write",
        duration: "session",
        task_id: "task-1",
        user_intent: "Use GitHub",
        reason: "Fetch issue metadata",
        sandbox_id: "body-sandbox",
        agent_id: "agent-a",
      },
      makeDeps(),
    );

    expect(canonical).toMatchObject({
      resource_type: "network",
      preset: "github",
      access: "read_write",
      duration: "session",
      task_id: "task-1",
      user_intent: "Use GitHub",
      reason: "Fetch issue metadata",
      identity_hints: {
        sandbox_id: "body-sandbox",
        agent_id: "agent-a",
      },
    });
    expect(canonical.request_hash).toMatch(/^[a-f0-9]{64}$/);
  });

  it("rejects unknown presets, custom hosts, and persistent duration", () => {
    expect(() => canonicalizeAccessRequest({ resource: "npm" }, makeDeps())).toThrow(
      AccessRequestValidationError,
    );
    expect(() => canonicalizeAccessRequest({ host: "example.com" }, makeDeps())).toThrow(
      /custom hosts/,
    );
    expect(() =>
      canonicalizeAccessRequest({ resource: "github", duration: "persistent" }, makeDeps()),
    ).toThrow(/Persistent access grants are disabled/);
  });

  it("sanitizes display-untrusted text and applies field caps", () => {
    const canonical = canonicalizeAccessRequest(
      {
        resource: "github",
        reason: `a\u0000b\u001fc\u007fd\u200be${"x".repeat(400)}`,
        user_intent: `u\u202ev${"y".repeat(600)}`,
      },
      makeDeps(),
    );

    expect(canonical.reason).toHaveLength(280);
    expect(canonical.reason.startsWith("abcdex")).toBe(true);
    expect(canonical.reason).not.toMatch(/[\u0000-\u001f\u007f\u200b]/u);
    expect(canonical.user_intent).toHaveLength(500);
    expect(canonical.user_intent.startsWith("uvy")).toBe(true);
    expect(canonical.user_intent).not.toContain("\u202e");
  });

  it("stores state under the access request directory and rejects by ceiling before pending", () => {
    const deps = makeDeps();

    const result = createAccessRequest(
      "sandbox-a",
      { resource: "github", task_id: "task-1" },
      { deps, ceiling: { allowedPresets: [] } },
    );

    expect(result.request.status).toBe("denied_by_ceiling");
    expect(result.request.ceiling_reason).toMatch(/not allowed/);
    expect(result.request.sandbox_id).toBe("sandbox-a");
    expect(result.request.identity_hints).toEqual({});
    expect(fs.existsSync(accessRequestStatePath("sandbox-a", deps))).toBe(true);
    expect(fs.existsSync(accessRequestAuditPath("sandbox-a", deps))).toBe(true);
    expect(readAccessRequestState("sandbox-a", deps).requests).toHaveLength(1);
  });

  it("dedupes matching open requests within the configured window", () => {
    const deps = makeDeps();
    const first = createAccessRequest(
      "sandbox-a",
      {
        resource: "github",
        access: "read",
        task_id: "task-1",
      },
      { deps },
    );

    deps.advance(60_000);
    const duplicate = createAccessRequest(
      "sandbox-a",
      {
        resource: "github",
        access: "read",
        task_id: "task-1",
        reason: "different untrusted text",
      },
      { deps },
    );

    deps.advance(6 * 60_000);
    const fresh = createAccessRequest(
      "sandbox-a",
      {
        resource: "github",
        access: "read",
        task_id: "task-1",
      },
      { deps },
    );

    expect(first.request.id).toBe("req-1");
    expect(duplicate.request.id).toBe("req-1");
    expect(duplicate.created).toBe(false);
    expect(duplicate.deduped).toBe(true);
    expect(fresh.request.id).toBe("req-2");
    expect(readAccessRequestState("sandbox-a", deps).requests).toHaveLength(2);
    expect(readAccessRequestAudit("sandbox-a", deps).map((record) => record.event)).toEqual([
      "created",
      "deduped",
      "created",
    ]);
  });

  it("enforces request rate limit per rolling hour", () => {
    const deps = makeDeps();

    for (let index = 0; index < 20; index++) {
      const result = createAccessRequest(
        "sandbox-a",
        {
          resource: "github",
          task_id: `task-${index}`,
        },
        { deps, ceiling: { maxOpenGrantsPerSandbox: 100 } },
      );
      expect(result.request.status).toBe("pending");
    }

    const limited = createAccessRequest(
      "sandbox-a",
      {
        resource: "github",
        task_id: "task-limited",
      },
      { deps, ceiling: { maxOpenGrantsPerSandbox: 100 } },
    );

    expect(limited.request.status).toBe("denied_by_ceiling");
    expect(limited.request.ceiling_reason).toMatch(/rate limit/);
  });

  it("enforces open grant limit per sandbox", () => {
    const deps = makeDeps();

    for (let index = 0; index < 5; index++) {
      const result = createAccessRequest(
        "sandbox-a",
        {
          resource: "github",
          task_id: `task-${index}`,
        },
        { deps },
      );
      expect(result.request.status).toBe("pending");
    }

    const limited = createAccessRequest(
      "sandbox-a",
      {
        resource: "github",
        task_id: "task-5",
      },
      { deps },
    );

    expect(limited.request.status).toBe("denied_by_ceiling");
    expect(limited.request.ceiling_reason).toMatch(/open access grant limit/);
  });

  it("chains audit records across transitions", () => {
    const deps = makeDeps();
    const created = createAccessRequest(
      "sandbox-a",
      {
        resource: "github",
        task_id: "task-1",
      },
      { deps },
    );

    deps.advance(1_000);
    transitionAccessRequest("sandbox-a", created.request.id, "denied", {
      deps,
      reason: "No longer needed",
    });

    const audit = readAccessRequestAudit("sandbox-a", deps);
    expect(audit).toHaveLength(2);
    expect(audit[0].prev_record_hash).toBeNull();
    expect(audit[1].prev_record_hash).toBe(audit[0].record_hash);
    expect(readAccessRequestState("sandbox-a", deps).audit_head_hash).toBe(audit[1].record_hash);
    expect(audit[1]).toMatchObject({
      event: "transitioned",
      status: "denied",
      reason: "No longer needed",
    });
  });
});
