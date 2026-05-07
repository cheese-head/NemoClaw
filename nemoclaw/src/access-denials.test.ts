// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  findRecentAccessDenial,
  readRecentAccessDenials,
  writeAccessDenialForTest,
  type NemoClawAccessDenial,
} from "./access-denials";

function fixture(id: string): NemoClawAccessDenial {
  return {
    version: "nemoclaw.denial.v1",
    id,
    kind: "network_policy_denial",
    observed_at: "2026-05-06T14:00:00.000Z",
    observed: {
      method: "GET",
      url: "https://api.github.com/repos/nvidia/nemoclaw",
      host: "api.github.com",
      port: 443,
      protocol: "https",
    },
    openshell: {
      policy: "github",
      rule: "GET /repos/nvidia/nemoclaw",
      detail: "request denied by policy",
    },
    suggested_access: {
      resource: "github",
      access: "read",
      duration: "session",
    },
    user_message: "GitHub access is blocked by the current sandbox policy.",
  };
}

describe("access denial log helpers", () => {
  it("reads recent structured denials newest first", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-denials-"));
    const file = path.join(dir, "access-denials.jsonl");
    writeAccessDenialForTest(fixture("old"), file);
    writeAccessDenialForTest(fixture("new"), file);

    expect(readRecentAccessDenials({ filePath: file, limit: 2 }).map((item) => item.id)).toEqual([
      "new",
      "old",
    ]);
  });

  it("finds a denial by id", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-denials-"));
    const file = path.join(dir, "access-denials.jsonl");
    writeAccessDenialForTest(fixture("denial-1"), file);

    expect(findRecentAccessDenial("denial-1", { filePath: file })?.suggested_access).toEqual({
      resource: "github",
      access: "read",
      duration: "session",
    });
  });
});
