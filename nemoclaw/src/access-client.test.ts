// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { createAccessRequest } from "./access-client.js";

describe("access client", () => {
  it("rejects non-HTTPS control URLs", async () => {
    expect(() =>
      createAccessRequest(
        {
          version: "nemoclaw.access.v1",
          user_intent: "Need GitHub",
          llm_proposal: {
            resource_type: "network",
            preset: "github",
            access: "read",
            duration: "session",
            reason: "Inspect a repository.",
          },
        },
        { controlUrl: "http://nemoclaw-control.local" },
      ),
    ).toThrow(/must use HTTPS with mTLS/);
  });
});
