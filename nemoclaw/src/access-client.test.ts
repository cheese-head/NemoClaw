// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { createAccessRequest, listAccessPresets } from "./access-client.js";

describe("access client", () => {
  it("rejects non-HTTP policy.local URLs", () => {
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
        { policyLocalUrl: "https://policy.local" },
      ),
    ).toThrow(/must use HTTP inside the sandbox/);
  });

  it("lists OpenShell-backed provider presets", async () => {
    await expect(listAccessPresets()).resolves.toMatchObject({
      presets: expect.arrayContaining([
        expect.objectContaining({ name: "github", provider_profile: "github" }),
        expect.objectContaining({ name: "outlook", provider_profile: "outlook" }),
      ]),
    });
  });
});
